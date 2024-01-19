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
	"context"
	"encoding/json"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

const (
	authEndpoint    string = "https://oauth.yandex.ru/authorize"
	tokenEndpoint   string = "https://oauth.yandex.com/token"
	profileEndpoint string = "https://login.yandex.ru/info"
	avatarURL       string = "https://avatars.yandex.net/get-yapic"
	avatarSize      string = "islands-200"
)

type YandexAccessToken struct {
	AccessToken string `json:"access_token"`
	UserId      int    `json:"user_id"`
	ExpiresIn   int    `json:"expires_in"`
	Email       string `json:"email"`
}

type YandexIdProvider struct {
	BaseProvider
	Client *http.Client
	Config *oauth2.Config
}

type YandexUserInfoPhone struct {
	Id int `json:"id"`
	Number string `json:"number"`
}



type YandexUserInfo struct {
	UserID        string `json:"id"`
	Email         string `json:"default_email"`
	Login         string `json:"login"`
	Name          string `json:"real_name"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	AvatarID      string `json:"default_avatar_id"`
	IsAvatarEmpty bool   `json:"is_avatar_empty"`
	DefaultPhone  YandexUserInfoPhone `json:"default_phone"`
}

func NewYandexIdProvider(clientId string, clientSecret string, redirectUrl string) *YandexIdProvider {
	idp := &YandexIdProvider{}

	config := idp.getConfig()
	config.ClientID = clientId
	config.ClientSecret = clientSecret
	config.RedirectURL = redirectUrl
	idp.Config = config

	return idp
}

func (idp *YandexIdProvider) getConfig() *oauth2.Config {
	endpoint := oauth2.Endpoint{
		AuthURL: authEndpoint, 
		TokenURL: tokenEndpoint,
	}

	config := &oauth2.Config{
		Scopes:   []string{"login:email","login:default_phone", "login:default_phone", "login:info", "login:avatar"},
		//Scopes:   []string{},
		Endpoint: endpoint,
	}

	return config
}

func (idp *YandexIdProvider) SetHttpClient(client *http.Client) {
	idp.Client = client
}

func (idp *YandexIdProvider) GetToken(code string) (*oauth2.Token, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, idp.Client)
	return idp.Config.Exchange(ctx, code)
}

func (idp *YandexIdProvider) GetUserInfo(token *oauth2.Token) (*UserInfo, error) {

	req, err := http.NewRequest("GET", profileEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "OAuth " + token.AccessToken)



	resp, err := idp.Client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var yandexUserInfo YandexUserInfo
	err = json.Unmarshal(body, &yandexUserInfo)
	if err != nil {
		return nil, err
	}

	userInfo := UserInfo{
		Id:  yandexUserInfo.UserID,
		Email:       yandexUserInfo.Email,
		Username:    yandexUserInfo.Login,
		DisplayName: yandexUserInfo.FirstName + " " + yandexUserInfo.LastName,
		AvatarUrl:   yandexUserInfo.AvatarID,
	}
	return &userInfo, nil
}
