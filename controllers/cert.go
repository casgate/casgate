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
	"strings"

	"github.com/beego/beego/logs"
	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// GetCerts
// @Title GetCerts
// @Tag Cert API
// @Description get certs
// @Param   owner     query    string  true        "The owner of certs"
// @Success 200 {array} object.Cert The Response object
// @router /get-certs [get]
func (c *ApiController) GetCerts() {
	owner := c.Input().Get("owner")
	limitParam := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")

	var limit int
	if limitParam == "" || page == "" {
		limit = -1
	} else {
		limit = util.ParseInt(limitParam)
	}

	count, err := object.GetCertCount(owner, field, value)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, limit, count)
	certs, err := object.GetMaskedCerts(object.GetPaginationCerts(owner, paginator.Offset(), limit, field, value, sortField, sortOrder))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(certs, paginator.Nums())
}

// GetGlobleCerts
// @Title GetGlobleCerts
// @Tag Cert API
// @Description get globle certs
// @Success 200 {array} object.Cert The Response object
// @router /get-globle-certs [get]
func (c *ApiController) GetGlobleCerts() {
	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")

	if limit == "" || page == "" {
		maskedCerts, err := object.GetMaskedCerts(object.GetGlobleCerts())
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(maskedCerts)
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetGlobalCertsCount(field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		certs, err := object.GetMaskedCerts(object.GetPaginationGlobalCerts(paginator.Offset(), limit, field, value, sortField, sortOrder))
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(certs, paginator.Nums())
	}
}

// GetCert
// @Title GetCert
// @Tag Cert API
// @Description get cert
// @Param   id     query    string  true        "The id ( owner/name ) of the cert"
// @Success 200 {object} object.Cert The Response object
// @router /get-cert [get]
func (c *ApiController) GetCert() {
	id := c.Input().Get("id")
	cert, err := object.GetCert(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(object.GetMaskedCert(cert))
}

// UpdateCert
// @Title UpdateCert
// @Tag Cert API
// @Description update cert
// @Param   id     query    string  true        "The id ( owner/name ) of the cert"
// @Param   body    body   object.Cert  true        "The details of the cert"
// @Success 200 {object} controllers.Response The Response object
// @router /update-cert [post]
func (c *ApiController) UpdateCert() {
	id := c.Input().Get("id")

	var cert object.Cert
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &cert)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateCert(id, &cert))
	c.ServeJSON()
}

// AddCert
// @Title AddCert
// @Tag Cert API
// @Description add cert
// @Param   body    body   object.Cert  true        "The details of the cert"
// @Success 200 {object} controllers.Response The Response object
// @router /add-cert [post]
func (c *ApiController) AddCert() {
	var cert object.Cert
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &cert)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddCert(&cert))
	c.ServeJSON()
}

// DeleteCert
// @Title DeleteCert
// @Tag Cert API
// @Description delete cert
// @Param   body    body   object.Cert  true        "The details of the cert"
// @Success 200 {object} controllers.Response The Response object
// @Failure 400 Bad Request
// @Failure 409 Conflict
// @Failure 500 Internal Server Error
// @router /delete-cert [post]
func (c *ApiController) DeleteCert() {
	var cert object.Cert
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &cert)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}

	providers, err := object.GetProvidersByCertName(cert.Name)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	if len(providers) > 0 {
		errMess := makeDeleteCertErrMessage(providers)
		c.ResponseConflict(errMess)

		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteCert(&cert))
	c.ServeJSON()
}

func makeDeleteCertErrMessage(providers []*object.Provider) string {
	providerIDs := make([]string, 0, len(providers))

	for _, provider := range providers {
		providerIDs = append(providerIDs, provider.Name)
	}

	return fmt.Sprintf("Can't delete certificate due to using in providers: %s", strings.Join(providerIDs, ", "))
}
