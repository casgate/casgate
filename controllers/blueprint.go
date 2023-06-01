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
	"github.com/casdoor/casdoor/util"
	"strings"
	"time"
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

	//fmt.Printf("%+v", record)

	if record.Action == "update-organization" {
		var org object.Organization
		if err := json.Unmarshal([]byte(record.Object), &org); err != nil {
			c.ResponseError(err.Error())
			return
		}
		orgName := "admin/" + org.Name

		currentOrganization := object.GetOrganization(orgName)
		// prevent double blueprint creation
		if currentOrganization.BlueprintsApplied {
			c.ResponseOk("Blueprints already applied")
			return
		}

		//key, cert, err := util.GenerateRSACertificate(
		//	currentOrganization.Name,
		//	currentOrganization.Name,
		//	time.Now().Add(10*24*365*time.Hour),
		//)

		masterRoles := object.GetRoles("built-in")
		masterModel := object.GetModel("built-in/rbac_built-in") // "rbac_built-in")
		masterPermissions := object.GetPermissions("built-in")
		applications := object.GetOrganizationApplications("admin", "built-in")
		plans := object.GetPlans("built-in")
		pricings := object.GetPricings("built-in")
		//subscriptions := object.GetSubscriptions("built-in")

		date := time.Now().Format(time.RFC3339)

		//copy model
		if masterModel != nil {
			newModel := masterModel
			newModel.Owner = currentOrganization.Name
			newModel.CreatedTime = date
			object.AddModel(newModel)
		}

		//copy application
		for _, app := range applications {
			if app.Name != "app-built-in" {
				newApp := app
				newApp.Name = app.Name + "_" + currentOrganization.Name
				newApp.Organization = currentOrganization.Name
				newApp.CreatedTime = date
				newApp.ClientId = util.GenerateClientId()
				newApp.ClientSecret = util.GenerateClientSecret()
				object.AddApplication(newApp)
			}
		}

		//copy roles
		for _, role := range masterRoles {
			newRole := role
			newRole.Owner = currentOrganization.Name
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
				newPermission.Roles = append(newPermission.Roles, currentOrganization.Name+"/"+strings.Split(role, "/")[1])
			}

			//newPermission.Resources = []string{application.Name}
			newPermission.Owner = currentOrganization.Name
			newPermission.CreatedTime = date
			object.AddPermission(newPermission)
		}

		// copy plans
		for _, plan := range plans {
			plan.Owner = currentOrganization.Name
			plan.CreatedTime = date
			object.AddPlan(plan)
		}

		// copy pricing
		for _, pricing := range pricings {
			newPricing := pricing
			newPricing.Owner = currentOrganization.Name
			newPricing.CreatedTime = date
			for i := range pricing.Plans {
				pricing.Plans[i] = strings.Replace(pricing.Plans[i], "built-in", currentOrganization.Name, -1)
			}
			object.AddPricing(newPricing)
		}

		// copy subscriptions
		//for _, sub := range subscriptions {
		//	newSub := sub
		//	newSub.Owner = currentOrganization.Name
		//	newSub.State = "Pending"
		//	object.AddSubscription(newSub)
		//}

		// create and apply certificate
		//object.AddCert()

		currentOrganization.BlueprintsApplied = true
		object.UpdateOrganization(orgName, currentOrganization)

	} else if record.Action == "delete-organization" {
		var org object.Organization
		if err := json.Unmarshal([]byte(record.Object), &org); err != nil {
			c.ResponseError(err.Error())
			return
		}

		users := object.GetUsers(org.Name)
		roles := object.GetRoles(org.Name)
		model := object.GetModel(org.Name + "/rbac_built-in")
		permissions := object.GetPermissions(org.Name)
		applications := object.GetApplications(org.Name)
		plans := object.GetPlans(org.Name)
		pricings := object.GetPricings(org.Name)
		//subscriptions := object.GetSubscriptions(org.Name)
		//cert := object.GetCert(currentOrganization.Name)

		//for _, sub := range subscriptions {
		//	object.DeleteSubscription(sub)
		//}

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

		//object.DeleteCert(cert)
	}

	c.ServeJSON()
}
