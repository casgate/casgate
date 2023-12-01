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
	"net/http"
	"net/url"
	"strings"
)

// GetProviders
// @Title GetProviders
// @Tag Provider API
// @Description get providers
// @Param   owner     query    string  true        "The owner of providers"
// @Success 200 {array} object.Provider The Response object
// @router /get-providers [get]
func (c *ApiController) GetProviders() {
	owner := c.Input().Get("owner")
	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")

	ok, isMaskEnabled := c.IsMaskedEnabled()
	if !ok {
		return
	}

	if limit == "" || page == "" {
		providers, err := object.GetProviders(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(object.GetMaskedProviders(providers, isMaskEnabled))
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetProviderCount(owner, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		paginationProviders, err := object.GetPaginationProviders(owner, paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		providers := object.GetMaskedProviders(paginationProviders, isMaskEnabled)
		c.ResponseOk(providers, paginator.Nums())
	}
}

// GetGlobalProviders
// @Title GetGlobalProviders
// @Tag Provider API
// @Description get Global providers
// @Success 200 {array} object.Provider The Response object
// @router /get-global-providers [get]
func (c *ApiController) GetGlobalProviders() {
	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")

	ok, isMaskEnabled := c.IsMaskedEnabled()
	if !ok {
		return
	}

	if limit == "" || page == "" {
		globalProviders, err := object.GetGlobalProviders()
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(object.GetMaskedProviders(globalProviders, isMaskEnabled))
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetGlobalProviderCount(field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		paginationGlobalProviders, err := object.GetPaginationGlobalProviders(paginator.Offset(), limit, field, value, sortField, sortOrder)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		providers := object.GetMaskedProviders(paginationGlobalProviders, isMaskEnabled)
		c.ResponseOk(providers, paginator.Nums())
	}
}

// GetProvider
// @Title GetProvider
// @Tag Provider API
// @Description get provider
// @Param   id     query    string  true        "The id ( owner/name ) of the provider"
// @Success 200 {object} object.Provider The Response object
// @router /get-provider [get]
func (c *ApiController) GetProvider() {
	id := c.Input().Get("id")

	ok, isMaskEnabled := c.IsMaskedEnabled()
	if !ok {
		return
	}
	provider, err := object.GetProvider(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(object.GetMaskedProvider(provider, isMaskEnabled))
}

// UpdateProvider
// @Title UpdateProvider
// @Tag Provider API
// @Description update provider
// @Param   id     query    string  true        "The id ( owner/name ) of the provider"
// @Param   body    body   object.Provider  true        "The details of the provider"
// @Success 200 {object} controllers.Response The Response object
// @router /update-provider [post]
func (c *ApiController) UpdateProvider() {
	id := c.Input().Get("id")

	var provider object.Provider
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &provider)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	for _, roleMappingItem := range provider.RoleMappingItems {
		if util.IsStringsEmpty(roleMappingItem.Attribute, roleMappingItem.Role) || len(roleMappingItem.Values) == 0 {
			c.ResponseError(c.T("general:Missing parameter"))
			return
		}
	}

	c.Data["json"] = wrapActionResponse(object.UpdateProvider(id, &provider))
	c.ServeJSON()
}

// AddProvider
// @Title AddProvider
// @Tag Provider API
// @Description add provider
// @Param   body    body   object.Provider  true        "The details of the provider"
// @Success 200 {object} controllers.Response The Response object
// @router /add-provider [post]
func (c *ApiController) AddProvider() {
	var provider object.Provider
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &provider)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	count, err := object.GetProviderCount("", "", "")
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err := checkQuotaForProvider(int(count)); err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddProvider(&provider))
	c.ServeJSON()
}

// DeleteProvider
// @Title DeleteProvider
// @Tag Provider API
// @Description delete provider
// @Param   body    body   object.Provider  true        "The details of the provider"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-provider [post]
func (c *ApiController) DeleteProvider() {
	var provider object.Provider
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &provider)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteProvider(&provider))
	c.ServeJSON()
}

// TestOpenIdConnection
// @Title TestOpenIdConnection
// @Tag Provider API
// @Description test OpenId connection
// @Param   body    body   object.Provider  true        "The details of the OpenId provider"
// @Success 200 {object} controllers.Response The Response object
// @router /test-openid [post]
func (c *ApiController) TestOpenIdConnection() {
	var provider object.Provider
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &provider)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if provider.Category != "OAuth" {
		c.ResponseError(fmt.Sprintf("saml_sp:provider %s's category is not OAuth", provider.Name))
		return
	}

	if provider.ClientId == "" || provider.ClientSecret == "" || provider.CustomAuthUrl == "" {
		c.ResponseError("empty clientId, clientSecret or authUrl")
		return
	}

	httpClient := new(http.Client)
	realmPath, _ := strings.CutSuffix(provider.CustomAuthUrl, "/protocol/openid-connect/auth")
	openidConfigurationPath := realmPath + "/.well-known/openid-configuration"

	resp, err := httpClient.Get(openidConfigurationPath)
	if err != nil || resp.StatusCode != 200 {
		c.ResponseError(err.Error())
		return
	}

	data := url.Values{}
	data.Add("grant_type", "client_credentials")
	data.Add("client_id", provider.ClientId)
	data.Add("client_secret", provider.ClientSecret)

	tokenResponse, err := httpClient.Post(provider.CustomTokenUrl, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil || tokenResponse.StatusCode != 200 {
		data.Add("scope", provider.Scopes)
		tokenResponse, err = httpClient.Post(provider.CustomTokenUrl, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
		if err != nil || tokenResponse.StatusCode != 200 {
			c.ResponseError(fmt.Sprintf("%d", tokenResponse.StatusCode))
			return
		}
	}

	c.ResponseOk()
}
