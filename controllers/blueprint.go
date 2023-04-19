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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/casdoor/casdoor/object"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const token = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJ1c2VyIjp7ImlkIjoiOGUzMWNhOGQtOWM2Yy00OWYyLTg3ZTItZjE2NjgyYmE1MTJiIiwidXNlcm5hbWUiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AcHRzZWN1cml0eS5jb20iLCJwZXJtaXNzaW9ucyI6WyJhdXRoLmFjY291bnQudmlldyIsImF1dGguYWNjb3VudC51cGRhdGUiLCJhdXRoLnRlbmFudHMuY3JlYXRlIiwiYXV0aC50ZW5hbnRzLmRlbGV0ZSIsImF1dGgudGVuYW50cy51cGRhdGUiLCJtb25pdG9yaW5nLmRhdGFiYXNlcy5saXN0IiwibW9uaXRvcmluZy5zeXN0ZW0ubGlzdCIsImxpY2Vuc2UubGljZW5zZS5jcmVhdGUiLCJsaWNlbnNlLmxpY2Vuc2UudXBkYXRlIiwiYmFja3Vwcy5iYWNrdXBzLmxpc3QiLCJiYWNrdXBzLmJhY2t1cHMuY3JlYXRlIiwiYmFja3Vwcy5iYWNrdXBzLnZpZXciLCJiYWNrdXBzLmJhY2t1cHMudXBkYXRlIiwiYmFja3Vwcy5iYWNrdXBzLmRlbGV0ZSIsImJhY2t1cHMucmVzdG9yaW5ncy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLnJ1bGVfc2V0X3VwZGF0ZXMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5hY3Rpb25zLmxpc3QiLCJjb25maWd1cmF0aW9uLmFjdGlvbnMudmlldyIsImNvbmZpZ3VyYXRpb24uYXBwbGljYXRpb25zLmxpc3QiLCJjb25maWd1cmF0aW9uLmFwcGxpY2F0aW9ucy52aWV3IiwiY29uZmlndXJhdGlvbi5hcHBsaWNhdGlvbnMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5hcHBsaWNhdGlvbnMuZGVsZXRlIiwiY29uZmlndXJhdGlvbi5hcHBsaWNhdGlvbnMudXBkYXRlIiwiY29uZmlndXJhdGlvbi5wb2xpY2llcy5saXN0IiwiY29uZmlndXJhdGlvbi5wb2xpY2llcy52aWV3IiwiY29uZmlndXJhdGlvbi5wb2xpY2llcy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLnBvbGljaWVzLmRlbGV0ZSIsImNvbmZpZ3VyYXRpb24ucG9saWNpZXMudXBkYXRlIiwiYXV0aC51c2Vycy5saXN0IiwiYXV0aC51c2Vycy52aWV3IiwiYXV0aC51c2Vycy5jcmVhdGUiLCJhdXRoLnVzZXJzLmRlbGV0ZSIsImF1dGgudXNlcnMudXBkYXRlIiwiYXV0aC5wZXJtaXNzaW9ucy5saXN0IiwicmVwb3J0cy5yZXBvcnRzLmxpc3QiLCJyZXBvcnRzLnJlcG9ydHMudmlldyIsInJlcG9ydHMucmVwb3J0cy5jcmVhdGUiLCJyZXBvcnRzLnJlcG9ydHMuZGVsZXRlIiwidGFza3Muc2NoZWR1bGVzLmxpc3QiLCJ0YXNrcy5zY2hlZHVsZXMudmlldyIsInRhc2tzLnNjaGVkdWxlcy5jcmVhdGUiLCJ0YXNrcy5zY2hlZHVsZXMuZGVsZXRlIiwidGFza3Muc2NoZWR1bGVzLnVwZGF0ZSIsInRhc2tzLnRhc2tzLmxpc3QiLCJ0YXNrcy50YXNrcy52aWV3IiwidGFza3MudGFza3MuY3JlYXRlIiwidGFza3MudGFza3MudXBkYXRlIiwidGhyZWF0cy50aHJlYXRzLmxpc3QiLCJsaWNlbnNlLmxpY2Vuc2UubGlzdCIsImF1dGguY3VycmVudF90ZW5hbnQudmlldyIsImF1dGgudGVuYW50cy5saXN0IiwiYXV0aC50ZW5hbnRzLnZpZXciLCJjb25maWd1cmF0aW9uLnBvbGljeV90ZW1wbGF0ZXMubGlzdCIsImNvbmZpZ3VyYXRpb24ucG9saWN5X3RlbXBsYXRlcy52aWV3IiwiY29uZmlndXJhdGlvbi5wb2xpY3lfdGVtcGxhdGVzLmNyZWF0ZSIsImNvbmZpZ3VyYXRpb24ucG9saWN5X3RlbXBsYXRlcy5kZWxldGUiLCJjb25maWd1cmF0aW9uLnBvbGljeV90ZW1wbGF0ZXMudXBkYXRlIiwiY29uZmlndXJhdGlvbi5iYWNrZW5kcy5saXN0IiwiY29uZmlndXJhdGlvbi5iYWNrZW5kcy52aWV3IiwiY29uZmlndXJhdGlvbi5iYWNrZW5kcy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLmJhY2tlbmRzLmRlbGV0ZSIsImNvbmZpZ3VyYXRpb24uYmFja2VuZHMudXBkYXRlIiwiY29uZmlndXJhdGlvbi50cmFmZmljX3Byb2ZpbGVzLmxpc3QiLCJjb25maWd1cmF0aW9uLnRyYWZmaWNfcHJvZmlsZXMudmlldyIsImNvbmZpZ3VyYXRpb24udHJhZmZpY19wcm9maWxlcy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLnRyYWZmaWNfcHJvZmlsZXMuZGVsZXRlIiwiY29uZmlndXJhdGlvbi50cmFmZmljX3Byb2ZpbGVzLnVwZGF0ZSIsImNvbmZpZ3VyYXRpb24uc3NsLmxpc3QiLCJjb25maWd1cmF0aW9uLnNzbC52aWV3IiwiY29uZmlndXJhdGlvbi5zc2wuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5zc2wuZGVsZXRlIiwiY29uZmlndXJhdGlvbi5zc2wudXBkYXRlIiwiY29uZmlndXJhdGlvbi52aXBzLmxpc3QiLCJjb25maWd1cmF0aW9uLnZpcHMudmlldyIsImNvbmZpZ3VyYXRpb24udmlwcy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLnZpcHMuZGVsZXRlIiwiY29uZmlndXJhdGlvbi52aXBzLnVwZGF0ZSIsImF1dGgucm9sZXMuY3JlYXRlIiwiYXV0aC5yb2xlcy5kZWxldGUiLCJhdXRoLnJvbGVzLmxpc3QiLCJhdXRoLnJvbGVzLnVwZGF0ZSIsImF1dGgucm9sZXMudmlldyIsImFib3V0LnN5c3RlbS52aWV3IiwiY29uZmlndXJhdGlvbi5ydWxlX3NldF91cGRhdGVzLnZpZXciLCJjb25maWd1cmF0aW9uLmFjdGlvbnMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5hY3Rpb25zLmRlbGV0ZSIsImNvbmZpZ3VyYXRpb24uYWN0aW9ucy51cGRhdGUiLCJhdWRpdC5ldmVudHMubGlzdCIsImF1ZGl0LmV2ZW50cy52aWV3IiwibW9uaXRvcmluZy5jb25maWd1cmF0aW9uLnZpZXciLCJjb25maWd1cmF0aW9uLnVzZXJfcnVsZXMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi51c2VyX3J1bGVzLmRlbGV0ZSIsImNvbmZpZ3VyYXRpb24udXNlcl9ydWxlcy51cGRhdGUiLCJjb25maWd1cmF0aW9uLnVzZXJfcnVsZXMudmlldyIsImNvbmZpZ3VyYXRpb24udXNlcl9ydWxlcy5saXN0IiwiY29uZmlndXJhdGlvbi5nbG9iYWxfbGlzdHMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5nbG9iYWxfbGlzdHMuZGVsZXRlIiwiY29uZmlndXJhdGlvbi5nbG9iYWxfbGlzdHMudXBkYXRlIiwiY29uZmlndXJhdGlvbi5nbG9iYWxfbGlzdHMudmlldyIsImNvbmZpZ3VyYXRpb24uZ2xvYmFsX2xpc3RzLmxpc3QiLCJjb25maWd1cmF0aW9uLnJ1bGVfc2V0X3VwZGF0ZXMubGlzdCIsInJlc291cmNlcy5ub2Rlcy5saXN0IiwiYXVkaXQuc3lzdGVtX2V2ZW50cy5saXN0IiwiYXVkaXQuc3lzdGVtX2V2ZW50cy52aWV3IiwiY29uZmlndXJhdGlvbi5pbnRlcm5hbF9iYWxhbmNlci52aWV3IiwiaW5zdGFsbGF0aW9uLm9uX3ByZW1pc2UudmlldyJdLCJ0ZW5hbnRfaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAifSwibGlmZV90aW1lIjo5OTk5OTk5OTksImV4cCI6MjY4MTkyMjU4NywianRpIjoiNjE3Yjk5ZGEtMWMyOS00ZmNlLWJmZDgtMmE2NmFmZmNkMGI3In0.jligSnNJpe0ThBoYB5ljqX5ioPPdPVTd5NMhCvqBX6ZJlBPsz3lQoKMDP84lijHV0DMs1BSkRkQXbGrof1NQXQ"

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

	//make http request

	if record.Action == "add-organization" {

		makeRequest()

		lastOrganization := object.GetPaginationOrganizations(record.User, 0, 1, "", "", "createdTime", "")
		organizationName := lastOrganization[0].Name

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

func makeRequest() error {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	//body := strings.NewReader(util.StructToJson(record))

	req, err := http.NewRequest("GET", "https://m1-26.af.rd.ptsecurity.ru/api/ptaf/v4/about/versions", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", token)

	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("Error sending request:", err)
	}

	defer resp.Body.Close()

	// read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
	}

	result := string(body)

	fmt.Println(result)

	return nil
}
