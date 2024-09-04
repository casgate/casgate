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
	"encoding/json"

	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util/logger"
)

// GetRoles
// @Title GetRoles
// @Tag Role API
// @Description get roles
// @Param   owner     query    string  true        "The owner of roles"
// @Success 200 {array} object.Role The Response object
// @Failure 500 Internal server error
// @router /get-roles [get]
func (c *ApiController) GetRoles() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	count, err := object.GetRoleCount(request.Owner, request.Field, request.Value)
	if err != nil {
		c.ResponseDBError(err)
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, request.Limit, count)
	roles, err := object.GetPaginationRoles(request.Owner, paginator.Offset(), request.Limit, request.Field, request.Value, request.SortField, request.SortOrder)
	if err != nil {
		c.ResponseDBError(err)
		return
	}

	c.ResponseOk(roles, paginator.Nums())
}

// GetRole
// @Title GetRole
// @Tag Role API
// @Description get role
// @Param   id     query    string  true        "The id ( owner/name ) of the role"
// @Success 200 {object} object.Role The Response object
// @Failure 500 Internal server error
// @router /get-role [get]
func (c *ApiController) GetRole() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var err error
	var role *object.Role

	if request.Field == displayNameField {
		role, err = object.GetRoleByDisplayName(request.Owner, request.Value)
	} else {
		role, err = object.GetRole(request.Id)
	}

	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}
	
	if role == nil {
		c.ResponseOk()
		return
	}
	c.ValidateOrganization(role.Owner)

	c.ResponseOk(role)
}

// UpdateRole
// @Title UpdateRole
// @Tag Role API
// @Description update role
// @Param   id     query    string  true        "The id ( owner/name ) of the role"
// @Param   body    body   object.Role  true        "The details of the role"
// @Success 200 {object} controllers.Response The Response object
// @Failure 400 Bad request
// @router /update-role [post]
func (c *ApiController) UpdateRole() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	ctx := c.getRequestCtx()

	logger.SetItem(ctx, "obj-type", logger.ObjectTypeRole)
	logger.SetItem(ctx, "usr", c.GetSessionUsername())

	var role object.Role
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &role)
	if err != nil {
		logger.LogWithInfo(
			ctx,
			logger.LogMsgDetailed{
				"error": err.Error(),
			},
			logger.OperationNameRoleUpdate,
			logger.OperationResultFailure,
		)
		c.ResponseBadRequest(err.Error())
		return
	}

	logger.SetItem(ctx, "obj", role.GetId())

	roleFromDb, _ := object.GetRole(request.Id)
	if roleFromDb == nil {
		logger.LogWithInfo(
			ctx,
			logger.LogMsgDetailed{
				"error": "role not found",
			},
			logger.OperationNameRoleUpdate,
			logger.OperationResultFailure,
		)
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(roleFromDb.Owner)

	affected, err := object.UpdateRole(request.Id, &role)

	if err != nil {
		logger.LogWithInfo(
			ctx,
			logger.LogMsgDetailed{
				"error": err.Error(),
			},
			logger.OperationNameRoleUpdate,
			logger.OperationResultFailure,
		)
	} else if !affected {
		logger.LogWithInfo(
			ctx,
			logger.LogMsgDetailed{
				"error": "not affected",
			},
			logger.OperationNameRoleUpdate,
			logger.OperationResultFailure,
		)
	} else {
		logger.LogWithInfo(
			ctx,
			"",
			logger.OperationNameRoleUpdate,
			logger.OperationResultSuccess,
		)

		oldUsers := make(map[string]struct{})
		newUsers := make(map[string]struct{})

		for _, userID := range roleFromDb.Users {
			oldUsers[userID] = struct{}{}
		}

		for _, userID := range role.Users {
			newUsers[userID] = struct{}{}
		}

		for userID := range oldUsers {
			if _, found := newUsers[userID]; !found {
				logger.LogWithInfo(
					ctx,
					logger.LogMsgDetailed{
						"info":   "role removed from user",
						"userID": userID,
					},
					logger.OperationNameRoleUpdate,
					logger.OperationResultSuccess,
				)
			}
		}

		for userID := range newUsers {
			if _, found := oldUsers[userID]; !found {
				logger.LogWithInfo(
					ctx,
					logger.LogMsgDetailed{
						"info":   "role added to user",
						"userID": userID,
					},
					logger.OperationNameRoleUpdate,
					logger.OperationResultSuccess,
				)
			}
		}
	}

	c.Data["json"] = wrapActionResponse(affected, err)
	c.ServeJSON()
}

// AddRole
// @Title AddRole
// @Tag Role API
// @Description add role
// @Param   body    body   object.Role  true        "The details of the role"
// @Success 200 {object} controllers.Response The Response object
// @Failure 400 Bad request
// @router /add-role [post]
func (c *ApiController) AddRole() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var role object.Role
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &role)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}
	c.ValidateOrganization(role.Owner)

	c.Data["json"] = wrapActionResponse(object.AddRole(&role))
	c.ServeJSON()
}

// DeleteRole
// @Title DeleteRole
// @Tag Role API
// @Description delete role
// @Param   body    body   object.Role  true        "The details of the role"
// @Success 200 {object} controllers.Response The Response object
// @Failure 400 Bad request
// @router /delete-role [post]
func (c *ApiController) DeleteRole() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var role object.Role
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &role)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}

	roleFromDb, _ := object.GetRole(role.GetId())
	if roleFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(roleFromDb.Owner)

	c.Data["json"] = wrapActionResponse(object.DeleteRole(&role))
	c.ServeJSON()
}
