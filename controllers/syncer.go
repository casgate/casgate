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
	"github.com/casdoor/casdoor/util"
)

// GetSyncers
// @Title GetSyncers
// @Tag Syncer API
// @Description get syncers
// @Param   owner     query    string  true        "The owner of syncers"
// @Success 200 {array} object.Syncer The Response object
// @router /get-syncers [get]
func (c *ApiController) GetSyncers() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")

	if limit == "" || page == "" {
		organizationSyncers, err := object.GetOrganizationSyncers(request.Owner, request.Organization)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(organizationSyncers)
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetSyncerCount(request.Owner, request.Organization, request.Field, request.Value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		syncers, err := object.GetPaginationSyncers(request.Owner, request.Organization, paginator.Offset(), limit, request.Field, request.Value, request.SortField, request.SortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(syncers, paginator.Nums())
	}
}

// GetSyncer
// @Title GetSyncer
// @Tag Syncer API
// @Description get syncer
// @Param   id     query    string  true        "The id ( owner/name ) of the syncer"
// @Success 200 {object} object.Syncer The Response object
// @router /get-syncer [get]
func (c *ApiController) GetSyncer() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	syncer, err := object.GetSyncer(request.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if syncer == nil {
		c.ResponseOk()
		return
	}

	c.ValidateOrganization(syncer.Organization)

	c.ResponseOk(syncer)
}

// UpdateSyncer
// @Title UpdateSyncer
// @Tag Syncer API
// @Description update syncer
// @Param   id     query    string  true        "The id ( owner/name ) of the syncer"
// @Param   body    body   object.Syncer  true        "The details of the syncer"
// @Success 200 {object} controllers.Response The Response object
// @router /update-syncer [post]
func (c *ApiController) UpdateSyncer() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var syncer object.Syncer
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &syncer)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	syncerFromDb, _ := object.GetSyncer(request.Id)
	if syncerFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(syncerFromDb.Organization)

	c.Data["json"] = wrapActionResponse(object.UpdateSyncer(request.Id, &syncer))
	c.ServeJSON()
}

// AddSyncer
// @Title AddSyncer
// @Tag Syncer API
// @Description add syncer
// @Param   body    body   object.Syncer  true        "The details of the syncer"
// @Success 200 {object} controllers.Response The Response object
// @router /add-syncer [post]
func (c *ApiController) AddSyncer() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var syncer object.Syncer
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &syncer)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ValidateOrganization(syncer.Organization)

	c.Data["json"] = wrapActionResponse(object.AddSyncer(&syncer))
	c.ServeJSON()
}

// DeleteSyncer
// @Title DeleteSyncer
// @Tag Syncer API
// @Description delete syncer
// @Param   body    body   object.Syncer  true        "The details of the syncer"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-syncer [post]
func (c *ApiController) DeleteSyncer() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var syncer object.Syncer
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &syncer)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	syncerFromDb, _ := object.GetSyncer(syncer.GetId())
	if syncerFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(syncerFromDb.Organization)

	c.Data["json"] = wrapActionResponse(object.DeleteSyncer(&syncer))
	c.ServeJSON()
}

// RunSyncer
// @Title RunSyncer
// @Tag Syncer API
// @Description run syncer
// @Param   body    body   object.Syncer  true        "The details of the syncer"
// @Success 200 {object} controllers.Response The Response object
// @router /run-syncer [get]
func (c *ApiController) RunSyncer() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	syncer, err := object.GetSyncer(request.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ValidateOrganization(syncer.Organization)

	err = object.RunSyncer(syncer)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk()
}
