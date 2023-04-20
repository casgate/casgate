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
	"github.com/casdoor/casdoor/extension"
	"github.com/casdoor/casdoor/object"
	"net/url"
)

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

		customer := object.GetUser(subscription.User)

		// find admin in customer org
		// use admin cred for af_client.AdministratorRequest

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

		request := af_client.TenantRequest{
			Name:        "tenant_" + customer.Name,
			Description: "Tenant's description",
			IsActive:    true,
			TrafficProcessing: af_client.TrafficProcessingRequest{
				TrafficProcessingType: "agent",
			},
			Administrator: af_client.AdministratorRequest{
				Email:    customerCompanyAdmin.Email,
				Username: customerCompanyAdmin.Name,
				Password: "P@ssw0rd",
			},
		}

		tenant, err := af_client.CreateTenant(request)

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

			//get new access token via admin cred

			// create roles roles

			// create customer with role

			// put to customer Properties info about logon and pwd
			// enable subscription

		}
	}

	c.ServeJSON()
}
