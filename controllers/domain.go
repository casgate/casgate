// Copyright 2023 The Casgate Authors. All Rights Reserved.
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

// GetDomains
// @Title GetDomains
// @Tag Domain API
// @Description get domains
// @Param   owner     query    string  true        "The owner of domains"
// @Success 200 {array} object.Domain The Response object
// @router /get-domains [get]
func (c *ApiController) GetDomains() {
	owner := c.Input().Get("owner")
	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")

	if !c.IsGlobalAdmin() && owner == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	if limit == "" || page == "" {
		domains, err := object.GetDomains(c.Ctx.Request.Context(), owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(domains)
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetDomainCount(owner, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		domains, err := object.GetPaginationDomains(owner, paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(domains, paginator.Nums())
	}
}

// GetDomain
// @Title GetDomain
// @Tag Domain API
// @Description get domain
// @Param   id     query    string  true        "The id ( owner/name ) of the domains"
// @Success 200 {object} object.Domain The Response object
// @router /get-domain [get]
func (c *ApiController) GetDomain() {
	id := c.Input().Get("id")

	domain, err := object.GetDomain(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(domain)
}

// UpdateDomain
// @Title UpdateDomain
// @Tag Domain API
// @Description update domain
// @Param   id     query    string  true        "The id ( owner/name ) of the domain"
// @Param   body    body   object.Domain  true        "The details of the domain"
// @Success 200 {object} controllers.Response The Response object
// @router /update-domain [post]
func (c *ApiController) UpdateDomain() {
	id := c.Input().Get("id")

	var domain object.Domain
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &domain)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateDomain(id, &domain))
	c.ServeJSON()
}

// AddDomain
// @Title AddDomain
// @Tag Domain API
// @Description add domain
// @Param   body    body   object.Domain  true        "The details of the domain"
// @Success 200 {object} controllers.Response The Response object
// @router /add-domain [post]
func (c *ApiController) AddDomain() {
	var domain object.Domain
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &domain)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddDomain(&domain))
	c.ServeJSON()
}

// DeleteDomain
// @Title DeleteDomain
// @Tag Domain API
// @Description delete domain
// @Param   body    body   object.Domain  true        "The details of the domain"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-domain [post]
func (c *ApiController) DeleteDomain() {
	var domain object.Domain
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &domain)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteDomain(&domain))
	c.ServeJSON()
}
