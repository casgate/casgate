// Copyright 2024 The Casdoor Authors. All Rights Reserved.
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

package controllers

import (
	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/object"
)

// AddApiToken
// @Title AddApiToken
// @Tag Api Token API
// @Description add api token
// @Param owner query string true "The owner of token"
// @Success 200 {object} object.UserApiToken The Response object
// @Failure 403 Unauthorized operation
// @Failure 500 Internal Server Error
// @router /add-api-token [post]
func (c *ApiController) AddApiToken() {
	ctx := c.getRequestCtx()
	owner := c.Input().Get("owner")
	if !c.IsGlobalAdmin() && owner == "" {
		c.ResponseForbidden(c.T("auth:Unauthorized operation"))
		return
	}

	user, err := object.GetUser(owner)
	if err != nil {
		logs.Error("get user: %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}

	tokenUser := object.MakeUserForToken(user)

	affected, err := object.AddUser(ctx, tokenUser)
	if err != nil {
		logs.Error("token creation: %s", err.Error())

		c.ResponseInternalServerError("Token creation error")
		return
	}
	if !affected {
		logs.Error("token creation: record not affected")

		c.ResponseInternalServerError("Token creation error")
		return
	}

	c.ResponseOk(object.MakeUserApiToken(tokenUser))
}

// DeleteApiToken
// @Title DeleteApiToken
// @Tag Api Token API
// @Description delete api token
// @Param owner query string true "The owner of token"
// @Param api_token string true "The user api token"
// @Success 200 Ok
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /delete-api-token [post]
func (c *ApiController) DeleteApiToken() {
	owner := c.Input().Get("owner")
	if !c.IsGlobalAdmin() && owner == "" {
		c.ResponseForbidden(c.T("auth:Unauthorized operation"))
		return
	}

	token := c.Input().Get("api_token")
	if token == "" {
		c.ResponseUnprocessableEntity("token not provided")
		return
	}

	user, err := object.GetUser(owner)
	if err != nil {
		logs.Error("get user: %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}

	affected, err := object.DeleteApiToken(user, token)
	if err != nil {
		logs.Error("delete api token: %s", err.Error())

		c.ResponseInternalServerError("delete token error")
		return
	}
	if !affected {
		logs.Error("delete api token: does not affected")

		c.ResponseInternalServerError("token does not deleted")
		return
	}

	c.ResponseOk()
}

// RecreateApiToken
// @Title RecreateApiToken
// @Tag Api Token API
// @Description recreate api token
// @Param owner query string true "The owner of token"
// @Param api_token string true "The user api token"
// @Success 200 {object} object.UserApiToken The Response object
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /recreate-api-token [post]
func (c *ApiController) RecreateApiToken() {
	owner := c.Input().Get("owner")
	if !c.IsGlobalAdmin() && owner == "" {
		c.ResponseForbidden(c.T("auth:Unauthorized operation"))
		return
	}

	token := c.Input().Get("api_token")
	if token == "" {
		c.ResponseUnprocessableEntity("token not provided")
		return
	}

	apiTokenUser, err := object.GetApiKeyUser(token)
	if err != nil {
		logs.Error("get api token: %s", err.Error())

		c.ResponseInternalServerError("token not provided")
		return
	}
	if apiTokenUser == nil {
		logs.Info("api token user not found")

		c.ResponseInternalServerError("api token not found")
		return
	}

	tokenOwner, err := object.GetUser(owner)
	if err != nil {
		logs.Error("get user: %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}

	if apiTokenUser.Tag != object.MakeTokenUserTag(tokenOwner) {
		logs.Error("token owner mismatch")

		c.ResponseUnprocessableEntity("owner mismatch")
		return
	}

	err = object.RecreateApiToken(tokenOwner, apiTokenUser)
	if err != nil {
		logs.Error("recreate api token: %s", err.Error())

		c.ResponseInternalServerError("Token not affected")
		return
	}

	c.ResponseOk(object.MakeUserApiToken(apiTokenUser))
}

// GetUserByApiToken
// @Title GetUserByApiToken
// @Tag Api Token API
// @Description get user by API token
// @Param api_token string true "The user api token"
// @Success 200 {object} object.User The Response object
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /get-user-by-api-token [post]
func (c *ApiController) GetUserByApiToken() {
	token := c.Input().Get("api_token")
	if token == "" {
		c.ResponseUnprocessableEntity("token not provided")
		return
	}

	owner, err := object.GetApiKeyOwner(token)
	if err != nil {
		logs.Error("get api key owner : %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}

	c.ResponseOk(owner)
}
