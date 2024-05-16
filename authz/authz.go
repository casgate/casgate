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

package authz

import (
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

var casbinEnforcer *casbin.SyncedEnforcer

func InitApi(enforcer *casbin.SyncedEnforcer) error {
	casbinEnforcer = enforcer

	err := object.InitCasbinPolicy()
	if err != nil {
		return err
	}

	return nil
}

func IsAllowed(subOwner string, subName string, method string, urlPath string, objOwner string, objName string, id string) bool {
	if conf.IsDemoMode() {
		if !isAllowedInDemoMode(subOwner, subName, method, urlPath, objOwner, objName) {
			return false
		}
	}

	user, err := object.GetUser(util.GetId(subOwner, subName))
	if err != nil {
		panic(err)
	}

	if user != nil {
		if user.IsDeleted {
			return false
		}
	}

	res, err := casbinEnforcer.Enforce(subOwner, subName, method, urlPath, objOwner, objName)
	if err != nil {
		panic(err)
	}

	return res
}

func isAllowedInDemoMode(subOwner string, subName string, method string, urlPath string, objOwner string, objName string) bool {
	if method == "POST" {
		if strings.HasPrefix(urlPath, "/api/login") || urlPath == "/api/logout" || urlPath == "/api/signup" || urlPath == "/api/send-verification-code" || urlPath == "/api/send-email" || urlPath == "/api/verify-captcha" {
			return true
		} else if urlPath == "/api/update-user" {
			// Allow ordinary users to update their own information
			if subOwner == objOwner && subName == objName && !(subOwner == "built-in" && subName == "admin") {
				return true
			}
			return false
		} else {
			return false
		}
	}

	// If method equals GET
	return true
}
