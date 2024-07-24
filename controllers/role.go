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

	role, err := object.GetRole(request.Id)
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

	var role object.Role
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &role)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}
	roleFromDb, _ := object.GetRole(request.Id)
	if roleFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(roleFromDb.Owner)

	affected, err := object.UpdateRole(request.Id, &role)

	ctx := c.getRequestCtx()

	if err != nil {
		logger.Error(ctx, "UpdateRole: failed to update role",
			"old_role", roleFromDb,
			"new_role", role,
			"error", err.Error())
	} else if !affected {
		logger.Error(ctx, "UpdateRole: failed to update role: not affected",
			"old_role", roleFromDb,
			"new_role", role)
	} else {
		logger.Info(ctx, "UpdateRole: role updated successfully",
			"role_id", role.GetId())

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
				logger.Info(ctx, "UpdateRole: role removed from user",
					"role_id", role.GetId(),
					"user_id", userID,
					"by_user", c.getCurrentUser().GetId())
			}
		}

		for userID := range newUsers {
			if _, found := oldUsers[userID]; !found {
				logger.Info(ctx, "UpdateRole: role added to user",
					"role_id", role.GetId(),
					"user_id", userID,
					"by_user", c.getCurrentUser().GetId())
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
