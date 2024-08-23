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
	"fmt"
	"net/http"

	"github.com/beego/beego/context"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

func AutoSigninFilter(ctx *context.Context) {
	goCtx := ctx.Request.Context()

	//if getSessionUser(ctx) != "" {
	//	return
	//}

	// GET parameter like "/page?access_token=123" or
	// HTTP Bearer token like "Authorization: Bearer 123"
	accessToken := ctx.Input.Query("accessToken")
	if accessToken == "" {
		accessToken = ctx.Input.Query("access_token")
	}
	if accessToken == "" {
		accessToken = parseBearerToken(ctx)
	}

	if accessToken != "" {
		token, err := object.GetTokenByAccessToken(accessToken)
		if err != nil {
			responseError(ctx, err.Error(), http.StatusForbidden)
			return
		}

		if token == nil {
			responseError(ctx, "Access token doesn't exist", http.StatusForbidden)
			return
		}

		if util.IsTokenExpired(token.CreatedTime, token.ExpiresIn) {
			responseError(ctx, "Access token has expired", http.StatusForbidden)
			return
		}

		userId := util.GetId(token.Organization, token.User)
		application, err := object.GetApplicationByUserId(goCtx, fmt.Sprintf("app/%s", token.Application))
		if err != nil {
			panic(err)
		}

		setSessionUser(ctx, userId)
		setSessionOidc(ctx, token.Scope, application.ClientId)
		return
	}

	// "/page?clientId=123&clientSecret=456"
	userId := getUsernameByClientIdSecret(ctx)
	if userId != "" {
		setSessionUser(ctx, userId)
		return
	}

	// "/page?username=built-in/admin&password=123"
	userId = ctx.Input.Query("username")
	password := ctx.Input.Query("password")
	if userId != "" && password != "" && ctx.Input.Query("grant_type") == "" {
		owner, name, err := util.GetOwnerAndNameFromId(userId)
		if err != nil {
			msg := object.CheckPassErrorToMessage(err, "en")
			responseError(ctx, msg, http.StatusForbidden)
			return
		}
		options := object.CheckUserPasswordOptions{
			Lang: "en",
		}
		_, err = object.CheckUserPassword(goCtx, owner, name, password, options)
		if err != nil {
			msg := object.CheckPassErrorToMessage(err, "en")
			responseError(ctx, msg, http.StatusForbidden)
			return
		}

		setSessionUser(ctx, userId)
		return
	}
}
