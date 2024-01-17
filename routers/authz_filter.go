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

package routers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/beego/beego/context"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/util"
)

type Object struct {
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	Organization string `json:"organization"`
	AccessKey    string `json:"accessKey"`
	AccessSecret string `json:"accessSecret"`
}

func getUsername(ctx *context.Context) (username string) {
	defer func() {
		if r := recover(); r != nil {
			username = getUsernameByClientIdSecret(ctx)
		}
	}()

	username = ctx.Input.Session("username").(string)

	if username == "" {
		username = getUsernameByClientIdSecret(ctx)
	}

	if username == "" {
		username = getUsernameByKeys(ctx)
	}
	return
}

func getSubject(ctx *context.Context) (string, string) {
	username := getUsername(ctx)
	if username == "" {
		return "anonymous", "anonymous"
	}

	// username == "built-in/admin"
	return util.GetOwnerAndNameFromId(username)
}

func getObject(ctx *context.Context) (string, string) {
	method := ctx.Request.Method
	path := ctx.Request.URL.Path

	if method == http.MethodGet {
		var objOwner, objName string
		// query == "?id=built-in/admin"
		id := ctx.Input.Query("id")
		owner := ctx.Input.Query("owner")

		if id != "" && owner != "" {
			return "", ""
		}

		if id != "" {
			objOwner, objName = util.GetOwnerAndNameFromIdNoCheck(id)
		}

		if owner != "" {
			if objOwner != "" {
				return "", ""
			}
			objOwner = owner
		}

		organization := ctx.Input.Query("organization")
		if organization != "" {
			if objOwner != "admin" {
				return "", ""
			}
			objOwner = organization
		}

		return objOwner, objName
	} else {
		body := ctx.Input.RequestBody

		if len(body) == 0 {
			return ctx.Request.Form.Get("owner"), ctx.Request.Form.Get("name")
		}

		var obj Object
		err := json.Unmarshal(body, &obj)
		if err != nil {
			// panic(err)
			return "", ""
		}

		if obj.Organization != "" {
			if obj.Owner != "admin" {
				return "", ""
			}
			obj.Owner = obj.Organization
		}

		if path == "/api/delete-resource" {
			tokens := strings.Split(obj.Name, "/")
			if len(tokens) >= 5 {
				obj.Name = tokens[4]
			}
		}

		return obj.Owner, obj.Name
	}
}

func getKeys(ctx *context.Context) (string, string) {
	method := ctx.Request.Method

	if method == http.MethodGet {
		accessKey := ctx.Input.Query("accessKey")
		accessSecret := ctx.Input.Query("accessSecret")
		return accessKey, accessSecret
	} else {
		body := ctx.Input.RequestBody

		if len(body) == 0 {
			return ctx.Request.Form.Get("accessKey"), ctx.Request.Form.Get("accessSecret")
		}

		var obj Object
		err := json.Unmarshal(body, &obj)
		if err != nil {
			return "", ""
		}

		return obj.AccessKey, obj.AccessSecret
	}
}

func willLog(subOwner string, subName string, method string, urlPath string, objOwner string, objName string) bool {
	if subOwner == "anonymous" && subName == "anonymous" && method == "GET" && (urlPath == "/api/get-account" || urlPath == "/api/get-app-login") && objOwner == "" && objName == "" {
		return false
	}
	return true
}

func getUrlPath(urlPath string) string {
	if strings.HasPrefix(urlPath, "/cas") && (strings.HasSuffix(urlPath, "/serviceValidate") || strings.HasSuffix(urlPath, "/proxy") || strings.HasSuffix(urlPath, "/proxyValidate") || strings.HasSuffix(urlPath, "/validate") || strings.HasSuffix(urlPath, "/p3/serviceValidate") || strings.HasSuffix(urlPath, "/p3/proxyValidate") || strings.HasSuffix(urlPath, "/samlValidate")) {
		return "/cas"
	}

	if strings.HasPrefix(urlPath, "/api/login/oauth") {
		return "/api/login/oauth"
	}

	if strings.HasPrefix(urlPath, "/api/webauthn") {
		return "/api/webauthn"
	}

	return urlPath
}

func ApiFilter(ctx *context.Context) {
	subOwner, subName := getSubject(ctx)
	method := ctx.Request.Method
	urlPath := getUrlPath(ctx.Request.URL.Path)

	objOwner, objName := "", ""
	if urlPath != "/api/get-app-login" && urlPath != "/api/get-resource" {
		objOwner, objName = getObject(ctx)
	}
	id := ctx.Input.Query("id")

	if strings.HasPrefix(urlPath, "/api/notify-payment") {
		urlPath = "/api/notify-payment"
	}

	isAllowed := authz.IsAllowed(subOwner, subName, method, urlPath, objOwner, objName, id)

	result := "deny"
	if isAllowed {
		result = "allow"
	}

	if willLog(subOwner, subName, method, urlPath, objOwner, objName) {
		logLine := fmt.Sprintf("subOwner = %s, subName = %s, method = %s, urlPath = %s, obj.Owner = %s, obj.Name = %s, result = %s",
			subOwner, subName, method, urlPath, objOwner, objName, result)
		fmt.Println(logLine)
		util.LogInfo(ctx, logLine)
	}

	if !isAllowed {
		denyRequest(ctx)
	}
}
