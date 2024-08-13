// Copyright 2024 The Casgate Authors. All Rights Reserved.
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/casdoor/casdoor/util"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
)

type OpenIdProvider struct {
	BaseProvider
	Client *http.Client
	Config *oauth2.Config

	ConfURL     string
	UserInfoURL string
	TokenURL    string
	AuthURL     string
	UserMapping map[string][]string
	Scopes      []string
}

type oidcConf struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

func NewOpenIdProvider(idpInfo *ProviderInfo, redirectUrl string) *OpenIdProvider {
	idp := &OpenIdProvider{}

	idp.Config = &oauth2.Config{
		ClientID:     idpInfo.ClientId,
		ClientSecret: idpInfo.ClientSecret,
		RedirectURL:  redirectUrl,
	}
	idp.ConfURL = idpInfo.ConfURL
	idp.UserMapping = idpInfo.UserMapping

	return idp
}

func (idp *OpenIdProvider) isURLsValid() bool {
	return !util.IsStringsEmpty(idp.AuthURL, idp.TokenURL, idp.UserInfoURL)
}

func (idp *OpenIdProvider) EnrichOauthURLsIfNotValid() error {
	if !idp.isURLsValid() {
		err := idp.EnrichOauthURLs()
		if err != nil {
			return err
		}
	}
	return nil
}

func (idp *OpenIdProvider) EnrichOauthURLs() error {
	requestURL := idp.ConfURL
	if !strings.Contains(requestURL, ".well-known/openid-configuration") {
		requestURL = fmt.Sprintf("%s/%s", idp.ConfURL, ".well-known/openid-configuration")
	}

	request, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return err
	}

	resp, err := idp.Client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var oidcResp oidcConf

	err = json.Unmarshal(data, &oidcResp)
	if err != nil {
		return err
	}
	idp.AuthURL = oidcResp.AuthorizationEndpoint
	idp.UserInfoURL = oidcResp.UserinfoEndpoint
	idp.TokenURL = oidcResp.TokenEndpoint
	idp.Config.Endpoint = oauth2.Endpoint{
		AuthURL:  idp.AuthURL,
		TokenURL: idp.TokenURL,
	}
	return nil
}

func (idp *OpenIdProvider) SetHttpClient(client *http.Client) {
	idp.Client = client
}

func (idp *OpenIdProvider) GetToken(code string) (*oauth2.Token, error) {
	err := idp.EnrichOauthURLsIfNotValid()
	if err != nil {
		return nil, err
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, idp.Client)
	return idp.Config.Exchange(ctx, code)
}

func (idp *OpenIdProvider) TestConnection() error {
	if util.IsStringsEmpty(idp.Config.ClientID, idp.Config.ClientSecret) {
		return NewMissingParameterError("Missing parameter")
	}

	data := url.Values{}
	data.Add("grant_type", "client_credentials")
	data.Add("client_id", idp.Config.ClientID)
	data.Add("client_secret", idp.Config.ClientSecret)

	err := idp.EnrichOauthURLs()
	if err != nil {
		return err
	}

	tokenResponse, err := idp.Client.Post(idp.TokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil || tokenResponse.StatusCode != 200 {
		return NewStatusError(tokenResponse.StatusCode)
	}

	return nil
}

type OidcUserInfo struct {
	Id          string `mapstructure:"id"`
	Username    string `mapstructure:"username"`
	DisplayName string `mapstructure:"displayName"`
	Email       string `mapstructure:"email"`
	AvatarUrl   string `mapstructure:"avatarUrl"`
}

func (idp *OpenIdProvider) GetUserInfo(token *oauth2.Token) (*UserInfo, error) {
	err := idp.EnrichOauthURLsIfNotValid()
	if err != nil {
		return nil, err
	}

	accessToken := token.AccessToken
	request, err := http.NewRequest("GET", idp.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}

	// add accessToken to request header
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := idp.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var (
		dataMap    map[string]interface{}
		attributes map[string]interface{}
	)
	err = json.Unmarshal(data, &dataMap)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(data, &attributes)

	// map user info
	var displayName string
	for k, attrArr := range idp.UserMapping {
		for _, attr := range attrArr {
			value := dataMap[attr]
			if value != nil {
				switch k {
				case "displayName":
					strValue, ok := value.(string)
					if !ok {
						return nil, fmt.Errorf("value of attribute %s for displayName is not string", k)
					}

					// few values are concatenated by space for displayName
					displayName = strings.Trim(strings.Join([]string{displayName, strValue}, " "), " ")
				default:
					dataMap[k] = value
					// the first non-empty attribute is taken for default case
					break
				}
			}
		}
	}

	if displayName != "" {
		dataMap["displayName"] = displayName
	}

	// try to parse id to string
	id, err := util.ParseIdToString(dataMap["id"])
	if err != nil {
		return nil, err
	}
	dataMap["id"] = id

	oidcUserinfo := &OidcUserInfo{}
	err = mapstructure.Decode(dataMap, oidcUserinfo)
	if err != nil {
		return nil, err
	}

	userInfo := &UserInfo{
		Id:             oidcUserinfo.Id,
		Username:       oidcUserinfo.Username,
		DisplayName:    oidcUserinfo.DisplayName,
		Email:          oidcUserinfo.Email,
		AvatarUrl:      oidcUserinfo.AvatarUrl,
		AdditionalInfo: attributes,
	}
	return userInfo, nil
}
