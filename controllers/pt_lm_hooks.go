//Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing, software
//distributed under the License is distributed on an "AS IS" BASIS,
//WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//See the License for the specific language governing permissions and
//limitations under the License.

package controllers

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic"
	af_client "github.com/casdoor/casdoor/pt_af_sdk"
	"github.com/casdoor/casdoor/util"
)

const afHost = "https://m1-26.af.rd.ptsecurity.ru/api/ptaf/v4/"

// UpdateSubscriptionPostBack ...
// @Title Blueprint
// @Tag PTLMHOOKS API
// @Description PTLMHOOKS
// @Param   body    body   object.Record  true        "The details of the event"
// @Success 200 {object} controllers.Response The Response object
// @router /update-subscription-postback [post]
func (c *ApiController) UpdateSubscriptionPostBack() {

	var record object.Record
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if record.Action != "update-subscription" {
		return
	}

	u, err := url.Parse(record.RequestUri)
	if err != nil {
		panic(err)
	}
	id := u.Query().Get("id")

	subscription := object.GetSubscription(id)
	if subscription == nil {
		util.LogWarning(c.Ctx, "No subscription found")
		c.ServeJSON() // to avoid crash
		return
	}

	switch strings.ToLower(subscription.State) {
	case "pending":
		c.email(subscription)
	case "started":
		{
			//c.email(subscription)
			c.createTenant(subscription)
		}
	}

	c.ServeJSON()
}

func (c *ApiController) email(subscription *object.Subscription) {
	err := pt_af_logic.Email(subscription)
	if err != nil {
		util.LogError(c.Ctx, err.Error())
	}
}

func (c *ApiController) createTenant(subscription *object.Subscription) {
	af := af_client.NewPtAF(afHost)

	allRoles := af.GetRoles()
	if allRoles == nil {
		panic("no roles found")
	}

	customer := object.GetUser(subscription.User)
	allCustomerCompanyUsers := object.GetUsers(customer.Owner)

	var customerCompanyAdmin *object.User
	for _, user := range allCustomerCompanyUsers {
		if user.IsAdmin {
			customerCompanyAdmin = user
			break
		}
	}

	if customerCompanyAdmin == nil {
		// log
		return
	}

	loginRequest := af_client.LoginRequest{
		Username:    "admin",
		Password:    "P@ssw0rd",
		Fingerprint: "qwe",
	}

	var logr, _ = af.Login(loginRequest)
	af.Token = logr.AccessToken

	request := af_client.TenantRequest{
		Name:        "tenant_" + customer.Name,
		Description: "Tenant's description",
		IsActive:    true,
		TrafficProcessing: af_client.TrafficProcessingRequest{
			TrafficProcessingType: "agent",
		},
		Administrator: af_client.AdministratorRequest{
			Email:                  customerCompanyAdmin.Email,
			Username:               customerCompanyAdmin.Name,
			Password:               "P@ssw0rd",
			PasswordChangeRequired: false,
		},
	}

	//admin should be - admin of pt client protal

	tenant, err := af.CreateTenant(request)

	if err != nil {
		util.LogError(c.Ctx, err.Error())
		return
	}

	if tenant != nil {

		if customer.Properties == nil {
			customer.Properties = make(map[string]string)
		}

		customer.Properties[af_client.PtPropPref+"ServiceAccountLogin"] = customerCompanyAdmin.Name
		customer.Properties[af_client.PtPropPref+"ServiceAccountPwd"] = "P@ssw0rd"

		affected := object.UpdateUser(customer.GetId(), customer, []string{"properties"}, false)
		print(affected)

		loginRequest := af_client.LoginRequest{
			Username:    customerCompanyAdmin.Name,
			Password:    "P@ssw0rd",
			Fingerprint: "qwe",
		}

		token, _ := af.Login(loginRequest)
		af.Token = token.AccessToken

		// create proper roles

		var serviceRole *af_client.Role
		var userRole *af_client.Role

		for _, role := range allRoles {
			if strings.EqualFold(role.Name, "service") {
				serviceRole = &role
			}

			if strings.EqualFold(role.Name, "user") {
				userRole = &role
			}
		}

		if serviceRole == nil {
			panic("no service role found")
		}

		if userRole == nil {
			panic("no user role found")
		}

		//	serviceRoleId, _ := af_client.CreateRole(token.AccessToken, serviceRole)
		userRoleId, _ := af.CreateRole(token.AccessToken, *userRole)

		createUserRequest := af_client.CreateUserRequest{
			Username:               customer.Email,
			Password:               "P@ssw0rd",
			Email:                  customer.Email,
			Role:                   userRoleId,
			PasswordChangeRequired: true,
			IsActive:               true,
		}

		af.CreateUser(createUserRequest)

		// create one more user with service role

		customer.Properties[af_client.PtPropPref+"ClientAccountLogin"] = "f6_client@mail.ru"
		customer.Properties[af_client.PtPropPref+"ClientAccountPwd"] = "P@ssw0rd"

		customer.Properties[af_client.PtPropPref+"Tenant ID"] = tenant.ID

		object.UpdateUser(customer.GetId(), customer, []string{"properties"}, false)

		// put to customer Properties info about logon and pwd
		// put to organization prop info about admin
		// enable subscription
	}
}
