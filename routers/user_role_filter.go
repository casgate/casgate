// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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

package routers

import (
	"github.com/beego/beego/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

var distributorAllowedUrls = map[string]bool{
	"/api/logout":                        true,
	"/api/get-account":                   true,
	"/api/get-organization-applications": true,
	"/api/get-organizations":             true,
	"/api/get-subscriptions":             true,
	"/api/get-subscription":              true,
	"/api/get-plans":                     true,
	"/api/get-users":                     true,
	"/api/get-user":                      true,
	"/api/update-subscription":           true,
	"/api/get-user-application":          true,
}

func UserRoleFilter(ctx *context.Context) {
	userID := getUsername(ctx)
	if userID == "" {
		return
	}

	user, _ := object.GetUser(userID)
	if user == nil {
		return
	}

	userRole := pt_af_logic.GetUserRole(user)
	if userRole == PTAFLTypes.UserRoleDistributor {
		urlPath := getUrlPath(ctx.Request.URL.Path)

		if !distributorAllowedUrls[urlPath] {
			denyRequest(ctx)
		}

		if urlPath == "/api/get-user" && ctx.Request.Form.Get("id") != userID {
			denyRequest(ctx)
		}
	}
}
