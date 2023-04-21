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
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_sdk"
	"net/url"
	"strings"
)

const af_host = "https://m1-26.af.rd.ptsecurity.ru/api/ptaf/v4/"

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
		return
	}

	if subscription.State == "Approved" {

		af := af_client.NewPtAF(af_host)

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

		af.Login(loginRequest)

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

		tenant, err := af.CreateTenant(request)

		if err != nil {
			//log
			return
		}

		if tenant != nil {

			if customer.Properties == nil {
				customer.Properties = make(map[string]string)
			}

			customer.Properties["tenantId"] = tenant.ID
			customer.Properties["tenantAdmin"] = customerCompanyAdmin.Email
			customer.Properties["pwd"] = "P@ssw0rd"

			affected := object.UpdateUser(customer.GetId(), customer, []string{"properties"}, false)
			print(affected)

			loginRequest := af_client.LoginRequest{
				Username:    customerCompanyAdmin.Name,
				Password:    "P@ssw0rd",
				Fingerprint: "qwe",
			}

			token, _ := af.Login(loginRequest)

			// create proper roles

			var serviceRole *af_client.Role
			var userRole *af_client.Role

			for _, role := range allRoles {
				if strings.ToLower(role.Name) == "service" {
					serviceRole = &role
				}

				if strings.ToLower(role.Name) == "user" {
					userRole = &role
				}
			}

			if serviceRole == nil {
				panic("no service role found")
			}

			if userRole == nil {
				panic("no service role found")
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

			// put to customer Properties info about logon and pwd
			// enable subscription
		}
	}

	c.ServeJSON()
}
