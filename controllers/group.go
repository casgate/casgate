// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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

package controllers

import (
	"encoding/json"

	"github.com/casdoor/casdoor/object"
)

// GetGroups
// @Title GetGroups
// @Tag Group API
// @Description get groups
// @Param   owner     query    string  true        "The owner of groups"
// @Success 200 {array} object.Group The Response object
// @router /get-groups [get]
func (c *ApiController) GetGroups() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	withTree := c.Input().Get("withTree")

	paginator, err := object.GetPaginator(c.Ctx, request.Owner, request.Field, request.Value, request.Limit, object.Group{})
	if err != nil {
		c.ResponseDBError(err)
		return
	}

	groups, err := object.GetPaginationGroups(request.Owner, paginator.Offset(), request.Limit,
		request.Field, request.Value, request.SortField, request.SortOrder)
	if err != nil {
		c.ResponseDBError(err)
		return
	}

	if withTree == "true" {
		groups = object.ConvertToTreeData(groups, request.Owner)
	}

	c.ResponseOk(groups, paginator.Nums())
}

// GetGroup
// @Title GetGroup
// @Tag Group API
// @Description get group
// @Param   id     query    string  true        "The id ( owner/name ) of the group"
// @Success 200 {object} object.Group The Response object
// @router /get-group [get]
func (c *ApiController) GetGroup() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	group, err := object.GetGroup(request.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if group == nil {
		c.ResponseOk()
		return
	}
	c.ValidateOrganization(group.Owner)

	c.ResponseOk(group)
}

// UpdateGroup
// @Title UpdateGroup
// @Tag Group API
// @Description update group
// @Param   id     query    string  true        "The id ( owner/name ) of the group"
// @Param   body    body   object.Group  true        "The details of the group"
// @Success 200 {object} controllers.Response The Response object
// @router /update-group [post]
func (c *ApiController) UpdateGroup() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var group object.Group
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &group)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	groupFromDb, _ := object.GetGroup(request.Id)
	if groupFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(groupFromDb.Owner)

	c.Data["json"] = wrapActionResponse(object.UpdateGroup(request.Id, &group))
	c.ServeJSON()
}

// AddGroup
// @Title AddGroup
// @Tag Group API
// @Description add group
// @Param   body    body   object.Group  true      "The details of the group"
// @Success 200 {object} controllers.Response The Response object
// @router /add-group [post]
func (c *ApiController) AddGroup() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var group object.Group
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &group)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ValidateOrganization(group.Owner)

	c.Data["json"] = wrapActionResponse(object.AddGroup(&group))
	c.ServeJSON()
}

// DeleteGroup
// @Title DeleteGroup
// @Tag Group API
// @Description delete group
// @Param   body    body   object.Group  true        "The details of the group"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-group [post]
func (c *ApiController) DeleteGroup() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var group object.Group
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &group)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	groupFromDb, _ := object.GetGroup(group.GetId())
	if groupFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(groupFromDb.Owner)

	c.Data["json"] = wrapActionResponse(object.DeleteGroup(&group))
	c.ServeJSON()
}
