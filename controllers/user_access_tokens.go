// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"github.com/casdoor/casdoor/util"
)

// AddAccessToken
// @Title AddAccessToken
// @Tag Access Token API
// @Description add access token
// @Param owner query string true "The owner of token"
// @Success 200 {object} object.UserAccessToken The Response object
// @Failure 403 Unauthorized operation
// @Failure 500 Internal Server Error
// @router /add-access-token [post]
func (c *ApiController) AddAccessToken() {
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

	affected, err := object.AddUser(tokenUser)
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

	c.ResponseOk(object.MakeUserAccessToken(tokenUser))
}

// DeleteAccessToken
// @Title DeleteAccessToken
// @Tag Access Token API
// @Description delete access token
// @Param owner query string true "The owner of token"
// @Param user_access_token string true "The user access token"
// @Success 200 Ok
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /delete-access-token [post]
func (c *ApiController) DeleteAccessToken() {
	owner := c.Input().Get("owner")
	if !c.IsGlobalAdmin() && owner == "" {
		c.ResponseForbidden(c.T("auth:Unauthorized operation"))
		return
	}

	token := c.Input().Get("user_access_token")
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

	affected, err := object.DeleteAccessToken(user, token)
	if err != nil {
		logs.Error("delete access token: %s", err.Error())

	 	c.ResponseInternalServerError("delete token error")
		return
	}
	if !affected {
		logs.Error("delete access token: does not affected")

	 	c.ResponseInternalServerError("token does not deleted")
		return
	}

	c.ResponseOk()
}

// RecreateAccessToken
// @Title RecreateAccessToken
// @Tag Access Token API
// @Description recreate access token
// @Param owner query string true "The owner of token"
// @Param user_access_token string true "The user access token"
// @Success 200 {object} object.UserAccessToken The Response object
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /recreate-access-token [post]
func (c *ApiController) RecreateAccessToken() {
	owner := c.Input().Get("owner")
	if !c.IsGlobalAdmin() && owner == "" {
		c.ResponseForbidden(c.T("auth:Unauthorized operation"))
		return
	}

	token := c.Input().Get("user_access_token")
	if token == "" {
		c.ResponseUnprocessableEntity("token not provided")
		return
	}

	accTokenUser, err := object.GetAccessTokenUser(token)
	if err != nil {
		logs.Error("get access token: %s", err.Error())

	 	c.ResponseInternalServerError("token not provided")
		return
	}

	tokenOwner, err := object.GetUser(owner)
	if err != nil {
		logs.Error("get user: %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}

	accessKey := util.GenerateId()
	username := object.MakeTokenUserName(tokenOwner, accessKey)
	accTokenUser.AccessKey = accessKey
	accTokenUser.AccessSecret = util.GenerateId()
	accTokenUser.Name = username

	err = object.RecreateAccessToken(accTokenUser)
	if err != nil {
		c.ResponseInternalServerError("Token not affected")
		return
	}

	c.ResponseOk(object.MakeUserAccessToken(accTokenUser))
}

// GetUserByAccessToken
// @Title GetUserByAccessToken
// @Tag Access Token API
// @Description get user by access token
// @Param owner query string true "The owner of token"
// @Param user_access_token string true "The user access token"
// @Success 200 {object} object.User The Response object
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /get-user-by-access-token [post]
func (c *ApiController) GetUserByAccessToken() {
	owner := c.Input().Get("owner")
	if !c.IsGlobalAdmin() && owner == "" {
		c.ResponseForbidden(c.T("auth:Unauthorized operation"))
		return
	}

	token := c.Input().Get("user_access_token")
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

	c.ResponseOk(user)
}
