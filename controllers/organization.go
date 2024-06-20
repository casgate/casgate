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

// GetOrganizations ...
// @Title GetOrganizations
// @Tag Organization API
// @Description get organizations
// @Param   owner     query    string  true        "owner"
// @Success 200 {array} object.Organization The Response object
// @Failure 500 Internal server error
// @router /get-organizations [get]
func (c *ApiController) GetOrganizations() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	owner := c.Input().Get("owner")
	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")
	organizationName := c.Input().Get("organizationName")

	isGlobalAdmin := c.IsGlobalAdmin()
	if limit == "" || page == "" {
		var maskedOrganizations []*object.Organization
		var err error

		if isGlobalAdmin {
			maskedOrganizations, err = object.GetMaskedOrganizations(object.GetOrganizations(owner))
		} else {
			maskedOrganizations, err = object.GetMaskedOrganizations(object.GetOrganizations(owner, c.getCurrentUser().Owner))
		}

		if err != nil {
			c.ResponseInternalServerError(err.Error())
			return
		}

		c.ResponseOk(maskedOrganizations)
	} else {
		if !isGlobalAdmin {
			maskedOrganizations, err := object.GetMaskedOrganizations(object.GetOrganizations(owner, c.getCurrentUser().Owner))
			if err != nil {
				c.ResponseInternalServerError(err.Error())
				return
			}
			c.ResponseOk(maskedOrganizations)
		} else {
			limit := util.ParseInt(limit)
			count, err := object.GetOrganizationCount(owner, field, value)
			if err != nil {
				c.ResponseInternalServerError(err.Error())
				return
			}

			paginator := pagination.SetPaginator(c.Ctx, limit, count)
			organizations, err := object.GetMaskedOrganizations(object.GetPaginationOrganizations(owner, organizationName, paginator.Offset(), limit, field, value, sortField, sortOrder))
			if err != nil {
				c.ResponseInternalServerError(err.Error())
				return
			}

			c.ResponseOk(organizations, paginator.Nums())
		}
	}
}

// GetOrganization ...
// @Title GetOrganization
// @Tag Organization API
// @Description get organization
// @Param   id     query    string  true        "organization id"
// @Success 200 {object} object.Organization The Response object
// @Failure 500 Internal server error
// @router /get-organization [get]
func (c *ApiController) GetOrganization() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	maskedOrganization, err := object.GetMaskedOrganization(object.GetOrganization(request.Id))
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	c.ResponseOk(maskedOrganization)
}

// UpdateOrganization ...
// @Title UpdateOrganization
// @Tag Organization API
// @Description update organization
// @Param   id     query    string  true        "The id ( owner/name ) of the organization"
// @Param   body    body   object.Organization  true        "The details of the organization"
// @Success 200 {object} controllers.Response The Response object
// @Failure 400 Bad request
// @router /update-organization [post]
func (c *ApiController) UpdateOrganization() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	
	var organization object.Organization
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &organization)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}

	currentUser := c.getCurrentUser()
	if !currentUser.IsGlobalAdmin() && currentUser.Owner != organization.Name {
		c.ResponseForbidden(c.T("auth:Forbidden operation"))
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateOrganization(c.Ctx.Request.Context(), request.Id, &organization, c.GetAcceptLanguage()))
	c.ServeJSON()
}

// AddOrganization ...
// @Title AddOrganization
// @Tag Organization API
// @Description add organization
// @Param   body    body   object.Organization  true        "The details of the organization"
// @Success 200 {object} controllers.Response The Response object
// @Failure 400 Bad request
// @Failure 422 Unprocessable entity
// @Failure 500 Internal server error
// @router /add-organization [post]
func (c *ApiController) AddOrganization() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	currentUser := c.getCurrentUser()
	if !currentUser.IsGlobalAdmin() {
		c.ResponseForbidden(c.T("auth:Forbidden operation"))
		return
	}

	var organization object.Organization
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &organization)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}

	count, err := object.GetOrganizationCount("", "", "")
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	if err = checkQuotaForOrganization(int(count)); err != nil {
		c.ResponseUnprocessableEntity(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddOrganization(&organization))
	c.ServeJSON()
}

// DeleteOrganization ...
// @Title DeleteOrganization
// @Tag Organization API
// @Description delete organization
// @Param   body    body   object.Organization  true        "The details of the organization"
// @Success 200 {object} controllers.Response The Response object
// @Failure 400 Bad request
// @router /delete-organization [post]
func (c *ApiController) DeleteOrganization() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	currentUser := c.getCurrentUser()
	if !currentUser.IsGlobalAdmin() {
		c.ResponseForbidden(c.T("auth:Forbidden operation"))
		return
	}

	var organization object.Organization
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &organization)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteOrganization(&organization))
	c.ServeJSON()
}

// GetDefaultApplication ...
// @Title GetDefaultApplication
// @Tag Organization API
// @Description get default application
// @Param   id     query    string  true        "organization id"
// @Success 200 {object}  Response The Response object
// @Failure 500 Internal server error
// @router /get-default-application [get]
func (c *ApiController) GetDefaultApplication() {
	ctx := c.getRequestCtx()
	userId := c.GetSessionUsername()
	id := c.Input().Get("id")

	application, err := object.GetDefaultApplication(ctx, id)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	maskedApplication := object.GetMaskedApplication(application, userId)
	c.ResponseOk(maskedApplication)
}

// GetOrganizationNames ...
// @Title GetOrganizationNames
// @Tag Organization API
// @Param   owner     query    string    true   "owner"
// @Description get all organization name and displayName
// @Success 200 {array} object.Organization The Response object
// @Failure 500 Internal server error
// @router /get-organization-names [get]
func (c *ApiController) GetOrganizationNames() {
	owner := c.Input().Get("owner")
	organizationNames, err := object.GetOrganizationsByFields(owner, []string{"name", "display_name"}...)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	c.ResponseOk(organizationNames)
}
