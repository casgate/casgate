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
	"errors"
	"fmt"
	"strings"

	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/object"
)

func (c *ApiController) GetSamlMeta() {
	ctx := c.getRequestCtx()
	host := c.Ctx.Request.Host
	paramApp := c.Input().Get("application")
	application, err := object.GetApplication(ctx, paramApp)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if application == nil {
		c.ResponseError(fmt.Sprintf(c.T("saml:Application %s not found"), paramApp))
		return
	}
	metadata, _ := object.GetSamlMeta(application, host)
	c.Data["xml"] = metadata
	c.ServeXML()
}

// GetProviderSamlMetadata
// @Title GetProviderSamlMetadata
// @Tag Provider API
// @Description get provider SAML methadata
// @Param   id     query    string  true        "The id ( owner/name ) of the provider"
// @Success 200 {object} object.Provider The Response object
// @Failure 500 Internal server error
// @router /get-provider-saml-metadata [get]
func (c *ApiController) GetProviderSamlMetadata() {
	id := c.Input().Get("id")

	provider, err := object.GetProvider(id)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	sp, err := object.BuildSp(c.getRequestCtx(), provider, "", c.Ctx.Request.Host)
	if err != nil {
		c.ResponseInternalServerError("Build SP error")
		return
	}

	entityDescriptor, err := sp.MetadataWithSLO(-1)
	if err != nil {
		c.ResponseInternalServerError("Build SP metadata error")
		return
	}

	if nameIDFormat, err := MapSamlNameIDFormat(provider.NameIdFormat); err == nil {
		entityDescriptor.SPSSODescriptor.NameIDFormats = []string{nameIDFormat}
	} else {
		logs.Error("mapping methadata: %s", err.Error())
	}

	c.Data["xml"] = entityDescriptor
	c.ServeXML()
}

var ErrMapShortToLongFormat = errors.New("Error short to long format")

var samlShortToLongNameIDFormatMapping = map[string]string{
	"persistent":                 "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
	"transient":                  "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
	"emailAddress":               "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
	"unspecified":                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
	"X509SubjectName":            "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
	"WindowsDomainQualifiedName": "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
	"kerberos":                   "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
	"entity":                     "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
}

func MapSamlNameIDFormat(shortFormat string) (string, error) {
	fixedShortFormat := strings.ToLower(shortFormat)

	if longFormat, ok := samlShortToLongNameIDFormatMapping[fixedShortFormat]; ok {
		return longFormat, nil
	}

	return "", ErrMapShortToLongFormat
}
