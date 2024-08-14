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
	"fmt"

	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// GetApplications
// @Title GetApplications
// @Tag Application API
// @Description get all applications
// @Param   owner     query    string  true        "The owner of applications."
// @Success 200 {array} object.Application The Response object
// @router /get-applications [get]
func (c *ApiController) GetApplications() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	userId := c.GetSessionUsername()
	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")

	if !c.IsGlobalAdmin() && request.Organization == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	var err error
	if limit == "" || page == "" {
		var applications []*object.Application
		if request.Organization == "" {
			applications, err = object.GetApplications(request.Owner)
		} else {
			applications, err = object.GetOrganizationApplications(request.Owner, request.Organization)
		}
		if err != nil {
			c.ResponseDBError(err)
			return
		}
		c.ResponseOk(object.GetMaskedApplications(applications, userId))
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetOrganizationApplicationCount("admin", request.Organization, request.Field, request.Value)
		if err != nil {
			c.ResponseDBError(err)
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		application, err := object.GetPaginationOrganizationApplications("admin", request.Organization, paginator.Offset(), limit, request.Field, request.Value, request.SortField, request.SortOrder)
		if err != nil {
			c.ResponseDBError(err)
			return
		}

		applications := object.GetMaskedApplications(application, userId)
		c.ResponseOk(applications, paginator.Nums())
	}
}

// GetApplication
// @Title GetApplication
// @Tag Application API
// @Description get the detail of an application
// @Param   id     query    string  true        "The id ( owner/name ) of the application."
// @Success 200 {object} object.Application The Response object
// @router /get-application [get]
func (c *ApiController) GetApplication() {
	userId := c.GetSessionUsername()
	id := c.Input().Get("id")
	goCtx := c.getRequestCtx()

	application, err := object.GetApplication(goCtx, id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if c.Input().Get("withKey") != "" && application != nil && application.Cert != "" {
		cert, err := object.GetCert(util.GetId(application.Owner, application.Cert))
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if cert == nil {
			cert, err = object.GetCert(util.GetId(application.Organization, application.Cert))
			if err != nil {
				c.ResponseError(err.Error())
				return
			}
		}

		if cert != nil {
			application.CertPublicKey = cert.Certificate
		}
	}

	c.ResponseOk(object.GetMaskedApplication(application, userId))
}

// GetUserApplication
// @Title GetUserApplication
// @Tag Application API
// @Description get the detail of the user's application
// @Param   id     query    string  true        "The id ( owner/name ) of the user"
// @Success 200 {object} object.Application The Response object
// @router /get-user-application [get]
func (c *ApiController) GetUserApplication() {
	userId := c.GetSessionUsername()
	id := c.Input().Get("id")
	goCtx := c.getRequestCtx()

	user, err := object.GetUser(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), id))
		return
	}

	application, err := object.GetApplicationByUser(goCtx, user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(object.GetMaskedApplication(application, userId))
}

// GetOrganizationApplications
// @Title GetOrganizationApplications
// @Tag Application API
// @Description get the detail of the organization's application
// @Param   organization     query    string  true        "The organization name"
// @Success 200 {array} object.Application The Response object
// @router /get-organization-applications [get]
func (c *ApiController) GetOrganizationApplications() {
	userId := c.GetSessionUsername()
	organization := c.Input().Get("organization")
	owner := c.Input().Get("owner")
	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")

	if organization == "" {
		c.ResponseBadRequest(c.T("general:Missing parameter") + ": organization")
		return
	}

	if limit == "" || page == "" {
		applications, err := object.GetOrganizationApplications(owner, organization)
		if err != nil {
			c.ResponseBadRequest(err.Error())
			return
		}

		c.ResponseOk(object.GetMaskedApplications(applications, userId))
	} else {
		limit := util.ParseInt(limit)

		count, err := object.GetOrganizationApplicationCount(owner, organization, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		application, err := object.GetPaginationOrganizationApplications(owner, organization, paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		applications := object.GetMaskedApplications(application, userId)
		c.ResponseOk(applications, paginator.Nums())
	}
}

// UpdateApplication
// @Title UpdateApplication
// @Tag Application API
// @Description update an application
// @Param   id     query    string  true        "The id ( owner/name ) of the application"
// @Param   body    body   object.Application  true        "The details of the application"
// @Success 200 {object} controllers.Response The Response object
// @router /update-application [post]
func (c *ApiController) UpdateApplication() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	id := c.Input().Get("id")
	goCtx := c.getRequestCtx()

	var application object.Application
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &application)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	application.Owner = "admin"
	c.ValidateOrganization(application.Organization)

	c.validateApplicationURLs(application)

	c.Data["json"] = wrapActionResponse(object.UpdateApplication(goCtx, id, &application))
	c.ServeJSON()
}

// AddApplication
// @Title AddApplication
// @Tag Application API
// @Description add an application
// @Param   body    body   object.Application  true        "The details of the application"
// @Success 200 {object} controllers.Response The Response object
// @router /add-application [post]
func (c *ApiController) AddApplication() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	goCtx := c.getRequestCtx()

	var application object.Application
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &application)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	application.Owner = "admin"
	c.ValidateOrganization(application.Organization)

	c.validateApplicationURLs(application)

	count, err := object.GetApplicationCount("", "", "")
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err := checkQuotaForApplication(int(count)); err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddApplication(goCtx, &application))
	c.ServeJSON()
}

// DeleteApplication
// @Title DeleteApplication
// @Tag Application API
// @Description delete an application
// @Param   body    body   object.Application  true        "The details of the application"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-application [post]
func (c *ApiController) DeleteApplication() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var application object.Application
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &application)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	appFromDb, _ := object.GetApplication(c.getRequestCtx(), application.GetId())
	if appFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(appFromDb.Organization)

	c.Data["json"] = wrapActionResponse(object.DeleteApplication(&application))
	c.ServeJSON()
}

func (c *ApiController) validateApplicationURLs(application object.Application) {
	fieldErrMap := map[string]string{
		application.Logo:              fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("application:Logo")),
		application.HomepageUrl:       fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("application:HomepageUrl")),
		application.SamlReplyUrl:      fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("application:SamlReplyUrl")),
		application.SignupUrl:         fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("application:SignupUrl")),
		application.SigninUrl:         fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("application:SigninUrl")),
		application.ForgetUrl:         fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("application:ForgetUrl")),
		application.AffiliationUrl:    fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("application:AffiliationUrl")),
		application.FormBackgroundUrl: fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("application:FormBackgroundUrl")),
	}

	for field, err := range fieldErrMap {
		if field != "" && !util.IsURLValid(field) {
			c.ResponseError(err)
			return
		}
	}
}
