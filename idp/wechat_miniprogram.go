// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

type WeChatMiniProgramIdProvider struct {
	BaseProvider
	Client *http.Client
	Config *oauth2.Config
}

func NewWeChatMiniProgramIdProvider(clientId string, clientSecret string) *WeChatMiniProgramIdProvider {
	idp := &WeChatMiniProgramIdProvider{}

	config := idp.getConfig(clientId, clientSecret)
	idp.Config = config
	idp.Client = &http.Client{}
	return idp
}

func (idp *WeChatMiniProgramIdProvider) SetHttpClient(client *http.Client) {
	idp.Client = client
}

func (idp *WeChatMiniProgramIdProvider) getConfig(clientId string, clientSecret string) *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
	}

	return config
}

type WeChatMiniProgramSessionResponse struct {
	Openid     string `json:"openid"`
	SessionKey string `json:"session_key"`
	Unionid    string `json:"unionid"`
	Errcode    int    `json:"errcode"`
	Errmsg     string `json:"errmsg"`
}

func (idp *WeChatMiniProgramIdProvider) GetSessionByCode(code string) (*WeChatMiniProgramSessionResponse, error) {
	sessionUri := fmt.Sprintf("https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code", idp.Config.ClientID, idp.Config.ClientSecret, code)
	sessionResponse, err := idp.Client.Get(sessionUri)
	if err != nil {
		return nil, err
	}
	defer sessionResponse.Body.Close()
	data, err := io.ReadAll(sessionResponse.Body)
	if err != nil {
		return nil, err
	}
	var session WeChatMiniProgramSessionResponse
	err = json.Unmarshal(data, &session)
	if err != nil {
		return nil, err
	}
	if session.Errcode != 0 {
		return nil, fmt.Errorf("err: %s", session.Errmsg)
	}
	return &session, nil
}
