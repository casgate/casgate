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

	if record.Action == "update-organization" {

		lastOrganization := object.GetPaginationOrganizations(record.User, 0, 1, "", "", "createdTime", "")
		organizationName := lastOrganization[0].Name

		isActive := lastOrganization[0].InitScore > 0
		alreadyHasRole := len(object.GetRoles(organizationName)) > 0

		if !isActive || alreadyHasRole {
			return
		}

		masterRoles := object.GetRoles("built-in")
		masterModel := object.GetModel("built-in/rbac_built-in") // "rbac_built-in")
		masterPermissions := object.GetPermissions("built-in")
		//application := object.GetApplication("admin/app-built-in")

		date := time.Now().Format(time.RFC3339)

		//copy model
		newModel := masterModel
		newModel.Owner = organizationName
		newModel.CreatedTime = date
		object.AddModel(newModel)

		//copy application
		//newApplication := application
		//newApplication.Owner = organizationName
		//object.AddApplication(newApplication)

		//copy roles
		for _, role := range masterRoles {
			newRole := role
			newRole.Owner = organizationName
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
				newPermission.Roles = append(newPermission.Roles, organizationName+"/"+strings.Split(role, "/")[1])
			}

			//newPermission.Resources = []string{application.Name}
			newPermission.Owner = organizationName
			newPermission.CreatedTime = date
			object.AddPermission(newPermission)
		}

	}

	c.ServeJSON()
}
