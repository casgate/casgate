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
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	// stringadapter "github.com/qiangmzsx/string-adapter/v2"
)

var Enforcer *casbin.Enforcer
var casbinEnforcer *casbin.Enforcer

func InitApi(enforcer *casbin.Enforcer) error {
	// e, err := object.GetInitializedEnforcer(util.GetId("built-in", "api-enforcer-built-in"))
	// if err != nil {
	// 	panic(err)
	// }

	casbinEnforcer = enforcer

	// casbinEnforcer.ClearPolicy()
	ok, err := casbinEnforcer.AddPoliciesEx([][]string{
		{"*", "*", "POST", "/api/signup", "*", "*"},
		{"*", "*", "GET", "/api/get-email-and-phone", "*", "*"},
		{"*", "*", "POST", "/api/login", "*", "*"},
		{"*", "*", "GET", "/api/get-app-login", "*", "*"},
		{"*", "*", "(GET|POST)", "/api/logout", "*", "*"},
		{"*", "*", "POST", "/api/callback", "*", "*"},
		{"*", "*", "GET", "/api/get-account", "*", "*"},
		{"*", "*", "GET", "/api/userinfo", "*", "*"},
		{"*", "*", "GET", "/api/user", "*", "*"},
		{"*", "*", "GET", "/api/health", "*", "*"},
		{"*", "*", "GET", "/api/get-webhook-event", "*", "*"},
		{"*", "*", "GET", "/api/get-captcha-status", "*", "*"},
		{"*", "*", "(GET|POST)", "/api/login/oauth", "*", "*"},
		{"*", "*", "GET", "/api/get-application", "*", "*"},
		{"*", "*", "GET", "/api/get-organization-applications", "*", "*"},
		{"*", "*", "GET", "/api/get-user-application", "*", "*"},
		{"*", "*", "POST", "/api/unlink", "*", "*"},
		{"*", "*", "POST", "/api/set-password", "*", "*"},
		{"*", "*", "POST", "/api/send-verification-code", "*", "*"},
		{"*", "*", "GET", "/api/get-captcha", "*", "*"},
		{"*", "*", "POST", "/api/verify-captcha", "*", "*"},
		{"*", "*", "POST", "/api/verify-code", "*", "*"},
		{"*", "*", "POST", "/api/reset-email-or-phone", "*", "*"},
		{"*", "*", "GET", "/.well-known/*", "*", "*"},
		{"*", "*", "GET", "/api/get-saml-login", "*", "*"},
		{"*", "*", "POST", "/api/acs", "*", "*"},
		{"*", "*", "GET", "/api/saml/metadata", "*", "*"},
		{"*", "*", "(GET|POST)", "/cas", "*", "*"},
		{"*", "*", "(GET|POST)", "/api/webauthn", "*", "*"},
		{"*", "*", "GET", "/api/get-release", "*", "*"},
		{"*", "*", "GET", "/api/get-default-application", "*", "*"},
		{"*", "*", "GET", "/api/get-prometheus-info", "*", "*"},
		{"*", "*", "(GET|POST)", "/api/metrics", "*", "*"},
		{"*", "*", "GET", "/api/get-pricing", "*", "*"},
		{"*", "*", "GET", "/api/get-plan", "*", "*"},
		{"*", "*", "GET", "/api/get-provider", "*", "*"},
		{"*", "*", "GET", "/api/get-organization-names", "*", "*"},
		{"*", "*", "GET", "/api/get-ldap-server-names", "*", "*"},
	})
	if !ok || err != nil {
		return fmt.Errorf("error adding base policies: %s", err)
	}

	return nil

	// Enforcer = e.Enforcer
	// Enforcer.ClearPolicy()

	// if len(Enforcer.GetPolicy()) == 0 {
	// 	if true {
	// 		ruleText := `
	// p, built-in, *, *, *, *, *
	// p, app, *, *, *, *, *
	// p, *, *, POST, /api/signup, *, *
	// p, *, *, GET, /api/get-email-and-phone, *, *
	// p, *, *, POST, /api/login, *, *
	// p, *, *, GET, /api/get-app-login, *, *
	// p, *, *, POST, /api/logout, *, *
	// p, *, *, GET, /api/logout, *, *
	// p, *, *, POST, /api/callback, *, *
	// p, *, *, GET, /api/get-account, *, *
	// p, *, *, GET, /api/userinfo, *, *
	// p, *, *, GET, /api/user, *, *
	// p, *, *, GET, /api/health, *, *
	// p, *, !anonymous, POST, /api/webhook, *, *
	// p, *, *, GET, /api/get-webhook-event, *, *
	// p, *, *, GET, /api/get-captcha-status, *, *
	// p, *, *, *, /api/login/oauth, *, *
	// p, *, *, GET, /api/get-application, *, *
	// p, *, !anonymous, POST, /api/add-application, *, *
	// p, *, *, GET, /api/get-organization-applications, *, *
	// p, *, !anonymous, GET, /api/get-user, *, *
	// p, *, *, GET, /api/get-user-application, *, *
	// p, *, !anonymous, GET, /api/get-resources, *, *
	// p, *, !anonymous, GET, /api/get-records, *, *
	// p, *, !anonymous, GET, /api/get-product, *, *
	// p, *, !anonymous, POST, /api/buy-product, *, *
	// p, *, !anonymous, GET, /api/get-payment, *, *
	// p, *, !anonymous, POST, /api/update-payment, *, *
	// p, *, !anonymous, POST, /api/invoice-payment, *, *
	// p, *, !anonymous, POST, /api/notify-payment, *, *
	// p, *, *, POST, /api/unlink, *, *
	// p, *, *, POST, /api/set-password, *, *
	// p, *, *, POST, /api/send-verification-code, *, *
	// p, *, *, GET, /api/get-captcha, *, *
	// p, *, *, POST, /api/verify-captcha, *, *
	// p, *, *, POST, /api/verify-code, *, *
	// p, *, *, POST, /api/reset-email-or-phone, *, *
	// p, *, !anonymous, POST, /api/upload-resource, *, *
	// p, *, *, GET, /.well-known/openid-configuration, *, *
	// p, *, *, *, /.well-known/jwks, *, *
	// p, *, *, GET, /api/get-saml-login, *, *
	// p, *, *, POST, /api/acs, *, *
	// p, *, *, GET, /api/saml/metadata, *, *
	// p, *, *, *, /cas, *, *
	// p, *, *, *, /api/webauthn, *, *
	// p, *, *, GET, /api/get-release, *, *
	// p, *, *, GET, /api/get-default-application, *, *
	// p, *, *, GET, /api/get-prometheus-info, *, *
	// p, *, *, *, /api/metrics, *, *
	// p, *, *, GET, /api/get-pricing, *, *
	// p, *, *, GET, /api/get-plan, *, *
	// p, *, !anonymous, GET, /api/get-subscriptions, *, *
	// p, *, !anonymous, GET, /api/get-subscription, *, *
	// p, *, *, GET, /api/get-provider, *, *
	// p, *, *, GET, /api/get-organization-names, *, *
	// p, *, *, GET, /api/get-ldap-server-names, *, *
	// p, *, !anonymous, POST, /api/add-user-id-provider, *, *
	// `
	//
	// 		sa := stringadapter.NewAdapter(ruleText)
	// 		// load all rules from string adapter to enforcer's memory
	// 		err := sa.LoadPolicy(Enforcer.GetModel())
	// 		if err != nil {
	// 			panic(err)
	// 		}
	//
	// 		// save all rules from enforcer's memory to Xorm adapter (DB)
	// 		// same as:
	// 		// a.SavePolicy(Enforcer.GetModel())
	// 		err = Enforcer.SavePolicy()
	// 		if err != nil {
	// 			panic(err)
	// 		}IsAllowed
	// 	}
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

	// if subOwner == "app" {
	// 	return true
	// }

	// if id != "" {
	// objIdOwner, _ := util.GetOwnerAndNameFromIdNoCheck(id)
	// if subOwner != "built-in" && objIdOwner != objOwner {
	// 	return false
	// }
	// }

	if user != nil {
		if user.IsDeleted {
			return false
		}

		// if user.IsAdmin && (subOwner == objOwner || (objOwner == "admin")) {
		// 	return true
		// }
	}
	fmt.Println(casbinEnforcer.GetPolicy())
	fmt.Println(casbinEnforcer.GetNamedGroupingPolicy("g"))
	fmt.Println(casbinEnforcer.GetNamedGroupingPolicy("g2"))
	fmt.Println(subName, subOwner, method, urlPath, objOwner, objName)
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
