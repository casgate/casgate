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
	"github.com/casdoor/casdoor/util/logger"
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
	if owner == "" {
		c.ResponseBadRequest(c.T("general:Missing parameter") + ": owner")
		return
	}

	if owner == "" {
		c.ResponseUnprocessableEntity("owner not provided")
		return
	}

	isValid := object.ValidateUserID(owner)
	if !isValid {
		c.ResponseUnprocessableEntity("owner is invalid")
		return
	}

	user, err := object.GetUser(owner)
	if err != nil {
		logs.Error("get user: %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}
	c.ValidateOrganization(user.Owner)

	currentUser := c.getCurrentUser()
	isSelfOrAdmin := currentUser.Id == user.Id || currentUser.IsAdmin
	if !isSelfOrAdmin {
		logs.Error("add api token for user: %s. Only self or admin can release token", user.Name)
		c.ResponseForbidden(c.T("auth:Forbidden operation"))
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

	token := tokenUser.AccessKey + tokenUser.AccessSecret
	isRootUser := currentUser.Owner == "built-in" && currentUser.Name == "admin"

	logger.Info(ctx, "user api token created", "token", token, "is_root_user", isRootUser)

	c.ResponseOk(object.MakeUserApiToken(tokenUser))
}

// DeleteApiToken
// @Title DeleteApiToken
// @Tag Api Token API
// @Description delete api token
// @Param owner query string true "The owner of token"
// @Param api_token query string true "The user api token"
// @Success 200 Ok
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /delete-api-token [post]
func (c *ApiController) DeleteApiToken() {
	owner := c.Input().Get("owner")
	if owner == "" {
		c.ResponseBadRequest(c.T("general:Missing parameter") + ": owner")
		return
	}

	if owner == "" {
		c.ResponseUnprocessableEntity("owner not provided")
		return
	}

	isValid := object.ValidateUserID(owner)
	if !isValid {
		c.ResponseUnprocessableEntity("owner is invalid")
		return
	}

	token := c.Input().Get("api_token")
	if token == "" {
		c.ResponseUnprocessableEntity("token not provided")
		return
	}

	isValid = object.ValidateToken(token)
	if !isValid {
		c.ResponseUnprocessableEntity("token is invalid")
		return
	}

	user, err := object.GetUser(owner)
	if err != nil {
		logs.Error("get user: %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}
	c.ValidateOrganization(user.Owner)
	currentUser := c.getCurrentUser()
	isSelfOrAdmin := currentUser.Id == user.Id || currentUser.IsAdmin
	if !isSelfOrAdmin {
		logs.Error("delete api token for user: %s. Only self or admin can delete token", user.Name)
		c.ResponseForbidden(c.T("auth:Forbidden operation"))
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

	isRootUser := currentUser.Owner == "built-in" && currentUser.Name == "admin"

	logger.Info(c.getRequestCtx(), "user api token deleted", "token", token, "is_root_user", isRootUser)

	c.ResponseOk()
}

// RecreateApiToken
// @Title RecreateApiToken
// @Tag Api Token API
// @Description recreate api token
// @Param owner query string true "The owner of token"
// @Param api_token query string true "The user api token"
// @Success 200 {object} object.UserApiToken The Response object
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /recreate-api-token [post]
func (c *ApiController) RecreateApiToken() {
	owner := c.Input().Get("owner")
	if owner == "" {
		c.ResponseBadRequest(c.T("general:Missing parameter") + ": owner")
		return
	}
	c.ValidateOrganization(owner)

	if owner == "" {
		c.ResponseUnprocessableEntity("owner not provided")
		return
	}

	isValid := object.ValidateUserID(owner)
	if !isValid {
		c.ResponseUnprocessableEntity("owner is invalid")
		return
	}

	token := c.Input().Get("api_token")
	if token == "" {
		c.ResponseUnprocessableEntity("token not provided")
		return
	}

	isValid = object.ValidateToken(token)
	if !isValid {
		c.ResponseUnprocessableEntity("token is invalid")
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

	c.ValidateOrganization(tokenOwner.Owner)

	currentUser := c.getCurrentUser()
	isSelfOrAdmin := currentUser.Id == tokenOwner.Id || currentUser.IsAdmin
	if !isSelfOrAdmin {
		logs.Error("recreate api token for user: %s. Only self or admin can recreate token", tokenOwner.Name)
		c.ResponseForbidden(c.T("auth:Forbidden operation"))
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
// @Param api_token query string true "The user api token"
// @Success 200 {object} object.User The Response object
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /get-user-by-api-token [get]
func (c *ApiController) GetUserByApiToken() {
	token := c.Input().Get("api_token")
	if token == "" {
		c.ResponseUnprocessableEntity("token not provided")
		return
	}

	isValid := object.ValidateToken(token)
	if !isValid {
		c.ResponseUnprocessableEntity("token is invalid")
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

// GetUserTokens
// @Title GetUserTokens
// @Tag Api Token API
// @Description get user tokens
// @Param owner query string true "The owner of token"
// @Success 200 {array} object.User The Response object
// @Failure 403 Unauthorized operation
// @Failure 422 Unprocessable entity
// @Failure 500 Internal Server Error
// @router /get-user-tokens [get]
func (c *ApiController) GetUserTokens() {
	owner := c.Input().Get("owner")
	if owner == "" {
		c.ResponseBadRequest(c.T("general:Missing parameter") + ": owner")
		return
	}

	if owner == "" {
		c.ResponseUnprocessableEntity("owner not provided")
		return
	}

	isValid := object.ValidateUserID(owner)
	if !isValid {
		c.ResponseUnprocessableEntity("owner is invalid")
		return
	}

	tokenOwner, err := object.GetUser(owner)
	if err != nil {
		logs.Error("get user: %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}

	c.ValidateOrganization(tokenOwner.Owner)

	currentUser := c.getCurrentUser()
	isSelfOrAdmin := currentUser.Id == tokenOwner.Id || currentUser.IsAdmin
	if !isSelfOrAdmin {
		logs.Error("add api token for user: %s. Only self or admin can get token", tokenOwner.Name)
		c.ResponseForbidden(c.T("auth:Forbidden operation"))
	}

	tokens, err := object.GetUserTokens(tokenOwner)
	if err != nil {
		logs.Error("get user tokens: %s", err.Error())

		c.ResponseInternalServerError("Internal server error")
		return
	}

	c.ResponseOk(tokens)
}
