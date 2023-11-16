// Copyright 2023 The Casgate Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"fmt"
	"errors"
	"encoding/json"
	"strconv"
	"io"
	"net/http"
	"net/url"
	 "time"

	"golang.org/x/oauth2"
)

type VkAccessToken struct {
	AccessToken   string `json:"access_token"`
	UserId        int    `json:"user_id"`
	ExpiresIn     int    `json:"expires_in"`
	Email         string `json:"email"`
}

type VkIdProvider struct {
	Client *http.Client
	Config *oauth2.Config
}

type VkUserInfoResponse struct {
	Users []VkUserInfo `json:"response"`
}

type VkUserInfo struct {
	ID              int    `json:"id"`
	FirstName       string `json:"first_name"`
	LastName        string `json:"last_name"`
	Avatar			string `json:"photo_50"`	
}

func NewVkIdProvider(clientId string, clientSecret string, redirectUrl string) *VkIdProvider {
	idp := &VkIdProvider{}

	config := idp.getConfig()
	config.ClientID = clientId
	config.ClientSecret = clientSecret
	config.RedirectURL = redirectUrl
	idp.Config = config

	return idp
}

func (idp *VkIdProvider) getConfig() *oauth2.Config {
	endpoint := oauth2.Endpoint{
		TokenURL: "https://oauth.vk.com/access_token",
	}

	config := &oauth2.Config{
		Scopes:   []string{"get_user_info"},
		Endpoint: endpoint,
	}

	return config
}

func (idp *VkIdProvider) SetHttpClient(client *http.Client) {
	idp.Client = client
}

func (idp *VkIdProvider) GetToken(code string) (*oauth2.Token, error) {
	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("client_id", idp.Config.ClientID)
	params.Add("client_secret", idp.Config.ClientSecret)
	params.Add("code", code)
	params.Add("redirect_uri", idp.Config.RedirectURL)

	accessTokenUrl := fmt.Sprintf("https://oauth.vk.com/access_token?%s", params.Encode())
	resp, err := idp.Client.Get(accessTokenUrl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	tokenContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Unquote the string to remove escaping
	unescapedContent, err := strconv.Unquote(fmt.Sprintf("`%s`",string(tokenContent)))
	if err != nil {
		return nil, err
	}

	tokenResp := VkAccessToken{}
	if err = json.Unmarshal([]byte(unescapedContent), &tokenResp); err != nil {
		return nil, err
	}

	token := &oauth2.Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   "Bearer",
		Expiry:      time.Unix(time.Now().Unix()+int64(7200), 0),
	}
	token = token.WithExtra(map[string]interface{}{
		"UserId": tokenResp.UserId,
		"Email": tokenResp.Email,
	})
	return token, nil
}

func (idp *VkIdProvider) GetUserInfo(token *oauth2.Token) (*UserInfo, error) {
	userId, ok := token.Extra("UserId").(int)
	if !ok {
		return nil, errors.New("invalid userId")
	}

	params := url.Values{}
	params.Add("user_ids", strconv.Itoa(userId))
	params.Add("access_token", token.AccessToken)
	params.Add("fields", "photo_50")
	params.Add("v", "5.154")

	accessTokenUrl := fmt.Sprintf("https://api.vk.com/method/users.get?%s", params.Encode())
	resp, err := idp.Client.Get(accessTokenUrl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var vkUserInfo VkUserInfoResponse
	err = json.Unmarshal(body, &vkUserInfo)
	if err != nil {
		return nil, err
	}

	email, _ := token.Extra("Email").(string)

	if (len(vkUserInfo.Users) == 0) {
		return nil, errors.ErrUnsupported
	}

	userInfo := UserInfo{
		Id:  strconv.Itoa(userId),
		Email: 	 email,
		Username:    email,
		DisplayName: vkUserInfo.Users[0].LastName + " " + vkUserInfo.Users[0].FirstName,
		AvatarUrl: vkUserInfo.Users[0].Avatar, 

	}
	return &userInfo, nil
}