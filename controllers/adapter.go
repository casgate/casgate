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

package controllers

import (
	"encoding/json"

	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/object"
)

// GetAdapters
// @Title GetAdapters
// @Tag Adapter API
// @Description get adapters
// @Param   owner     query    string  true        "The owner of adapters"
// @Success 200 {array} object.Adapter The Response object
// @router /get-adapters [get]
func (c *ApiController) GetAdapters() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	count, err := object.GetAdapterCount(request.Owner, request.Field, request.Value)
	if err != nil {
		c.ResponseDBError(err)
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, request.Limit, count)
	adapters, err := object.GetPaginationAdapters(request.Owner, paginator.Offset(), request.Limit, request.Field, request.Value, request.SortField, request.SortOrder)
	if err != nil {
		c.ResponseDBError(err)
		return
	}

	c.ResponseOk(adapters, paginator.Nums())
}

// GetAdapter
// @Title GetAdapter
// @Tag Adapter API
// @Description get adapter
// @Param   id     query    string  true        "The id ( owner/name ) of the adapter"
// @Success 200 {object} object.Adapter The Response object
// @router /get-adapter [get]
func (c *ApiController) GetAdapter() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	adapter, err := object.GetAdapter(request.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if adapter == nil {
		c.ResponseOk()
		return
	}
	c.ValidateOrganization(adapter.Owner)

	c.ResponseOk(adapter)
}

// UpdateAdapter
// @Title UpdateAdapter
// @Tag Adapter API
// @Description update adapter
// @Param   id     query    string  true        "The id ( owner/name ) of the adapter"
// @Param   body    body   object.Adapter  true        "The details of the adapter"
// @Success 200 {object} controllers.Response The Response object
// @router /update-adapter [post]
func (c *ApiController) UpdateAdapter() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var adapter object.Adapter
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &adapter)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	adapterFromDb, _ := object.GetDomain(request.Id)
	if adapterFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(adapterFromDb.Owner)

	c.Data["json"] = wrapActionResponse(object.UpdateAdapter(request.Id, &adapter))
	c.ServeJSON()
}

// AddAdapter
// @Title AddAdapter
// @Tag Adapter API
// @Description add adapter
// @Param   body    body   object.Adapter  true        "The details of the adapter"
// @Success 200 {object} controllers.Response The Response object
// @router /add-adapter [post]
func (c *ApiController) AddAdapter() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var adapter object.Adapter
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &adapter)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ValidateOrganization(adapter.Owner)

	c.Data["json"] = wrapActionResponse(object.AddAdapter(&adapter))
	c.ServeJSON()
}

// DeleteAdapter
// @Title DeleteAdapter
// @Tag Adapter API
// @Description delete adapter
// @Param   body    body   object.Adapter  true        "The details of the adapter"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-adapter [post]
func (c *ApiController) DeleteAdapter() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var adapter object.Adapter
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &adapter)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	adapterFromDb, _ := object.GetDomain(adapter.GetId())
	if adapterFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(adapterFromDb.Owner)

	c.Data["json"] = wrapActionResponse(object.DeleteAdapter(&adapter))
	c.ServeJSON()
}
