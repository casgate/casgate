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

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"

	"github.com/beego/beego/context"
)

func getUser(ctx *context.Context) (username string) {
	defer func() {
		if r := recover(); r != nil {
			username = getUserByClientIdSecret(ctx)
		}
	}()

	username = ctx.Input.Session("username").(string)

	if username == "" {
		username = getUserByClientIdSecret(ctx)
	}

	return
}

func getUserByClientIdSecret(ctx *context.Context) string {
	clientId := ctx.Input.Query("clientId")
	clientSecret := ctx.Input.Query("clientSecret")
	if clientId == "" || clientSecret == "" {
		return ""
	}

	application, err := object.GetApplicationByClientId(clientId)
	if err != nil {
		panic(err)
	}

	if application == nil || application.ClientSecret != clientSecret {
		return ""
	}

	return util.GetId(application.Organization, application.Name)
}

func RecordMessage(ctx *context.Context) {
	rb := object.ExtractRecord(ctx)
	var record *object.Record

	if rb == nil {
		record = defaultRecordLog(ctx)
	} else {
		record = rb.Build()
	}

	if resp, ok := ctx.Input.Data()["json"]; ok {
		if strResp, err := json.Marshal(resp); err == nil {
			record.Response = string(strResp)
		}
	}

	util.SafeGoroutine(func() { object.AddRecord(record) })
}

func defaultRecordLog(ctx *context.Context) *object.Record {
	record := object.NewRecord(ctx)

	userId := getUser(ctx)
	if ctx.Request.URL.Path == "/api/logout" {
		userId, _ = ctx.Input.GetData("user").(string)
	}

	if userId != "" {
		record.Organization, record.User = util.GetOwnerAndNameFromId(userId)
	}

	return record
}
