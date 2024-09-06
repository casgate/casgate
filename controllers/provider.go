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
	"errors"
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/casdoor/casdoor/util/logger"
	"github.com/xorm-io/builder"
)

// GetProviders
// @Title GetProviders
// @Tag Provider API
// @Description get providers
// @Param   owner     query    string  true        "The owner of providers"
// @Success 200 {array} object.Provider The Response object
// @router /get-providers [get]
func (c *ApiController) GetProviders() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	if !c.IsGlobalAdmin() && request.Owner == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	ok, isMaskEnabled := c.IsMaskedEnabled()
	if !ok {
		return
	}

	paginator, err := object.GetPaginator(c.Ctx, "", request.Field, request.Value, request.Limit,
		object.Provider{}, builder.Eq{"owner": []string{"admin", request.Owner}})
	if err != nil {
		c.ResponseDBError(err)
		return
	}

	paginationProviders, err := object.GetPaginationProviders(request.Owner, paginator.Offset(), request.Limit,
		request.Field, request.Value, request.SortField, request.SortOrder)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	providers := object.GetMaskedProviders(paginationProviders, isMaskEnabled)
	c.ResponseOk(providers, paginator.Nums())
}

// GetGlobalProviders
// @Title GetGlobalProviders
// @Tag Provider API
// @Description get Global providers
// @Success 200 {array} object.Provider The Response object
// @router /get-global-providers [get]
func (c *ApiController) GetGlobalProviders() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	ok, isMaskEnabled := c.IsMaskedEnabled()
	if !ok {
		return
	}

	paginator, err := object.GetPaginator(c.Ctx, "", request.Field, request.Value, request.Limit, object.Provider{})
	if err != nil {
		c.ResponseDBError(err)
		return
	}

	paginationGlobalProviders, err := object.GetPaginationGlobalProviders(paginator.Offset(), request.Limit, request.Field, request.Value, request.SortField, request.SortOrder)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	providers := object.GetMaskedProviders(paginationGlobalProviders, isMaskEnabled)
	c.ResponseOk(providers, paginator.Nums())
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
	if provider == nil {
		c.ResponseOk()
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

	goCtx := c.getRequestCtx()
	record := object.GetRecordBuilderFromContext(goCtx)

	logger.SetItem(goCtx, "obj-type", logger.ObjectTypeProvider)
	logger.SetItem(goCtx, "usr", c.GetSessionUsername())

	var provider object.Provider
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &provider)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	logger.SetItem(goCtx, "obj", provider.GetId())

	c.ValidateOrganization(provider.Owner)

	c.validateProviderURLs(provider)

	for _, roleMappingItem := range provider.RoleMappingItems {
		if util.IsStringsEmpty(roleMappingItem.Attribute, roleMappingItem.Role) || len(roleMappingItem.Values) == 0 {
			logger.LogWithInfo(
				goCtx,
				logger.LogMsgDetailed{
					"error": "missing parameter",
				},
				logger.OperationNameProviderUpdate,
				logger.OperationResultFailure,
			)
			c.ResponseError(c.T("general:Missing parameter"))
			return
		}
	}

	affected, err := object.UpdateProvider(c.getRequestCtx(), id, &provider)
	if err != nil {
		logger.LogWithInfo(
			goCtx,
			logger.LogMsgDetailed{
				"error": "missing parameter",
			},
			logger.OperationNameProviderUpdate,
			logger.OperationResultFailure,
		)
		detail := fmt.Sprintf("Update provider error: Owner: %s, Name: %s, Type: %s", provider.Owner, provider.Name, provider.Type)
		record.AddReason(detail)
	} else {
		logger.LogWithInfo(
			goCtx,
			"",
			logger.OperationNameProviderUpdate,
			logger.OperationResultSuccess,
		)
		record.AddReason("Update provider success")
	}

	c.Data["json"] = wrapActionResponse(affected, err)
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

	ctx := c.getRequestCtx()

	logger.SetItem(ctx, "obj-type", logger.ObjectTypeProvider)
	logger.SetItem(ctx, "usr", c.GetSessionUsername())

	err := json.Unmarshal(c.Ctx.Input.RequestBody, &provider)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	logger.SetItem(ctx, "obj", provider.GetId())

	c.ValidateOrganization(provider.Owner)

	c.validateProviderURLs(provider)

	count, err := object.GetProviderCount("", "", "")
	if err != nil {
		logger.LogWithInfo(
			ctx,
			logger.LogMsgDetailed{
				"error": err.Error(),
			},
			logger.OperatoinNameAddProvider,
			logger.OperationResultFailure,
		)

		c.ResponseError(err.Error())
		return
	}

	if err := checkQuotaForProvider(int(count)); err != nil {
		logger.LogWithInfo(
			ctx,
			logger.LogMsgDetailed{
				"error": err.Error(),
			},
			logger.OperatoinNameAddProvider,
			logger.OperationResultFailure,
		)

		c.ResponseError(err.Error())
		return
	}

	affected, err := object.AddProvider(c.getRequestCtx(), &provider)
	if err != nil {
		logger.LogWithInfo(
			ctx,
			logger.LogMsgDetailed{
				"error": err.Error(),
			},
			logger.OperatoinNameAddProvider,
			logger.OperationResultFailure,
		)
	} else if !affected {
		logger.LogWithInfo(
			ctx,
			logger.LogMsgDetailed{
				"error": "not affected",
			},
			logger.OperatoinNameAddProvider,
			logger.OperationResultFailure,
		)
	} else {
		logger.LogWithInfo(
			ctx,
			"successfuly added provider",
			logger.OperatoinNameAddProvider,
			logger.OperationResultSuccess,
		)
	}

	c.Data["json"] = wrapActionResponse(affected, err)
	c.ServeJSON()
}

// DeleteProvider
// @Title DeleteProvider
// @Tag Provider API
// @Description delete provider
// @Param   body    body   object.Provider  true        "The details of the provider"
// @Success 200 {object} controllers.Response The Response object
// @Failure 400 Bad request
// @Failure 409 Conflict
// @Failure 500 Internal server error
// @router /delete-provider [post]
func (c *ApiController) DeleteProvider() {
	goCtx := c.getRequestCtx()

	var provider object.Provider
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &provider)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}
	c.ValidateOrganization(provider.Owner)

	applications, err := object.CountApplicatoinsByProvider(provider.Name)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	if len(applications) > 0 {
		if !provider.RemoveFromApps {
			msg := c.makeDeleteProviderErrorMessage(applications, c.GetAcceptLanguage())
			c.ResponseConflict(msg)
			return
		}
		for _, app := range applications {
			providers := make([]*object.ProviderItem, 0, len(app.Providers))
			for _, providerItem := range app.Providers {
				if providerItem.Name != provider.Name {
					providers = append(providers, providerItem)
				}
			}
			app.Providers = providers

			_, err = object.UpdateApplication(goCtx, app.GetId(), app)
			if err != nil {
				c.ResponseInternalServerError(err.Error())
				return
			}
		}
	}

	c.Data["json"] = wrapActionResponse(object.DeleteProvider(&provider))
	c.ServeJSON()
}

func (c *ApiController) makeDeleteProviderErrorMessage(applications []*object.Application, lang string) string {
	appNames := make([]string, 0, len(applications))

	for _, app := range applications {
		appNames = append(appNames, app.Name)
	}

	apps := strings.Join(appNames, ", ")

	return fmt.Sprintf(i18n.Translate(lang, "provider:Can't delete provider due to using in applications: [%s]"), apps)
}

// TestProviderConnection
// @Title TestProviderConnection
// @Tag Provider API
// @Description test provider connection
// @Param   body    body   object.Provider  true        "The details of the provider"
// @Success 200 {object} controllers.Response The Response object
// @router /test-provider [post]
func (c *ApiController) TestProviderConnection() {
	var provider object.Provider
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &provider)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ValidateOrganization(provider.Owner)
	idpInfo := object.FromProviderToIdpInfo(nil, &provider)
	idProvider := idp.GetIdProvider(idpInfo, idpInfo.RedirectUrl)
	if provider.Type == "OpenID" {
		object.SetHttpClientToOIDCProvider(idpInfo, idProvider)
	}

	err = idProvider.TestConnection()
	if err != nil {
		var missingParameterError *idp.MissingParameterError
		var statusError *idp.StatusError
		var notImplementedError *idp.NotImplementedError
		switch {
		case errors.As(err, &missingParameterError):
			c.ResponseError(c.T("general:Missing parameter"))
		case errors.As(err, &statusError):
			c.ResponseError(fmt.Sprintf(c.T("general:Unexpected status code %s"), err.Error()))
		case errors.As(err, &notImplementedError):
			c.ResponseError(c.T("general:Not implemented"))
		default:
			c.ResponseError(c.T(err.Error()))
		}
		return
	}
	c.ResponseOk()
}

func (c *ApiController) validateProviderURLs(provider object.Provider) {
	fieldErrMap := map[string]string{
		provider.Domain:                 fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:Domain")),
		provider.CustomConfUrl:          fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:CustomConfUrl")),
		provider.CustomAuthUrl:          fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:CustomAuthUrl")),
		provider.CustomTokenUrl:         fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:CustomTokenUrl")),
		provider.CustomUserInfoUrl:      fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:CustomUserInfoUrl")),
		provider.CustomLogo:             fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:CustomLogo")),
		provider.IssuerUrl:              fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:IssuerUrl")),
		provider.BaseHostUrl:            fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:BaseHostUrl")),
		provider.ProviderUrl:            fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:ProviderUrl")),
		provider.SingleLogoutServiceUrl: fmt.Sprintf(c.T("general:%s field is not valid URL"), c.T("provider:SingleLogoutServiceUrl")),
	}

	for field, err := range fieldErrMap {
		if field != "" && !util.IsURLValid(field) {
			c.ResponseError(err)
			return
		}
	}
}
