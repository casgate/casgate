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
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// ApplyBlueprint ...
// @Title Blueprint
// @Tag Blueprint API
// @Description blueprint
// @Param   body    body   object.Record  true        "The details of the event"
// @Success 200 {object} controllers.Response The Response object
// @router /apply-blueprint [post]
func (c *ApiController) ApplyBlueprint() {

	var record object.Record
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if record.Action == "update-organization" {
		var org object.Organization
		if err := json.Unmarshal([]byte(record.Object), &org); err != nil {
			c.ResponseError(err.Error())
			return
		}

		url, _ := url.Parse(record.RequestUri)
		id := url.Query().Get("id")

		currentOrganization, _ := object.GetOrganization(id)
		// prevent double blueprint creation
		if currentOrganization.BlueprintsApplied {
			c.ResponseOk("Blueprints already applied")
			return
		}

		masterRoles, _ := object.GetRoles("built-in")
		masterModel, _ := object.GetModel("built-in/rbac_built-in") // "rbac_built-in")
		masterPermissions, _ := object.GetPermissions("built-in")
		applications, _ := object.GetOrganizationApplications("admin", "built-in")
		plans, _ := object.GetPlans("built-in")
		pricings, _ := object.GetPricings("built-in")
		//subscriptions := object.GetSubscriptions("built-in")

		date := time.Now().Format(time.RFC3339)

		//copy model
		if masterModel != nil {
			newModel := masterModel
			newModel.Owner = org.Name
			newModel.CreatedTime = date
			object.AddModel(newModel)
		}

		// create and bind new certificate
		keyPem, certPem, err := util.GenerateRSACertificate(
			org.Name,
			org.Name,
			time.Now().Add(20*24*365*time.Hour),
		)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		cert := &object.Cert{
			Owner:           org.Name,
			Name:            org.Name,
			CreatedTime:     date,
			DisplayName:     org.Name,
			Scope:           "JWT",
			Type:            "x509",
			CryptoAlgorithm: "RS256",
			BitSize:         4096,
			ExpireInYears:   20,
			Certificate:     string(certPem),
			PrivateKey:      string(keyPem),
		}
		object.AddCert(cert)

		//copy application
		for _, app := range applications {
			if app.Name != "" {
				newApp := app
				newApp.Cert = cert.Name
				newApp.Name = org.Name
				newApp.Organization = org.Name
				newApp.CreatedTime = date
				newApp.Providers = app.Providers
				newApp.ClientId = util.GenerateClientId()
				newApp.ClientSecret = util.GenerateClientSecret()
				newApp.SigninUrl = fmt.Sprintf("/login/%s", org.Name)
				object.AddApplication(newApp)
			}
		}

		//copy roles
		for _, role := range masterRoles {
			newRole := role
			newRole.Owner = org.Name
			newRole.CreatedTime = date
			object.AddRole(newRole)
		}

		//copy permissions
		for _, permission := range masterPermissions {
			newPermission := permission
			newPermission.Users = []string{}

			oldRoles := newPermission.Roles

			newPermission.Roles = []string{}

			for _, role := range oldRoles {
				newPermission.Roles = append(newPermission.Roles, org.Name+"/"+strings.Split(role, "/")[1])
			}

			//newPermission.Resources = []string{application.Name}
			newPermission.Owner = org.Name
			newPermission.CreatedTime = date
			object.AddPermission(newPermission)
		}

		// copy plans
		for _, plan := range plans {
			plan.Owner = org.Name
			plan.CreatedTime = date
			object.AddPlan(plan)
		}

		// copy pricing
		for _, pricing := range pricings {
			newPricing := pricing
			newPricing.Owner = org.Name
			newPricing.CreatedTime = date
			newPricing.Application = org.Name
			for i := range pricing.Plans {
				pricing.Plans[i] = strings.Replace(pricing.Plans[i], "built-in", org.Name, -1)
			}
			object.AddPricing(newPricing)
		}

		*currentOrganization = org
		currentOrganization.BlueprintsApplied = true
		_, err = object.UpdateOrganization(util.GetId(org.Owner, org.Name), currentOrganization)
		if err != nil {
			c.ResponseError(fmt.Sprintf("object.UpdateOrganization: %v", err))
			return
		}

	} else if record.Action == "delete-organization" {
		var org object.Organization
		if err := json.Unmarshal([]byte(record.Object), &org); err != nil {
			c.ResponseError(err.Error())
			return
		}

		users, _ := object.GetUsers(org.Name)
		roles, _ := object.GetRoles(org.Name)
		model, _ := object.GetModel(org.Name + "/rbac_built-in")
		permissions, _ := object.GetPermissions(org.Name)
		applications, _ := object.GetOrganizationApplications("admin", org.Name)
		plans, _ := object.GetPlans(org.Name)
		pricings, _ := object.GetPricings(org.Name)
		cert, _ := object.GetCert(org.Name + "/" + org.Name)

		for _, pricing := range pricings {
			object.DeletePricing(pricing)
		}

		for _, plan := range plans {
			object.DeletePlan(plan)
		}

		for _, app := range applications {
			if app.Organization == org.Name {
				object.DeleteApplication(app)
			}
		}

		object.DeleteModel(model)

		for _, permission := range permissions {
			object.DeletePermission(permission)
		}

		for _, role := range roles {
			object.DeleteRole(role)
		}

		for _, user := range users {
			object.DeleteUser(user)
		}

		object.DeleteCert(cert)
	}

	c.ServeJSON()
}
