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
	goCtx "context"
	"encoding/json"
	"reflect"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"

	beeCtx "github.com/beego/beego/context"
)

func getUser(ctx *beeCtx.Context) (username string) {
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

func getUserByClientIdSecret(ctx *beeCtx.Context) string {
	goCtx := ctx.Request.Context()
	clientId := ctx.Input.Query("clientId")
	clientSecret := ctx.Input.Query("clientSecret")
	if clientId == "" || clientSecret == "" {
		return ""
	}

	application, err := object.GetApplicationByClientId(goCtx, clientId)
	if err != nil {
		panic(err)
	}

	if application == nil || application.ClientSecret != clientSecret {
		return ""
	}

	return util.GetId(application.Organization, application.Name)
}

func InitRecordMessage(bCtx *beeCtx.Context) {
	reqCtx := bCtx.Request.Context()
	rb := object.NewRecordBuilderFromCtx(bCtx)
	ctxWithRecord := goCtx.WithValue(reqCtx, object.RecordDataKey, rb)
	bCtx.Request = bCtx.Request.WithContext(ctxWithRecord)
}

func LogRecordMessage(bCtx *beeCtx.Context) {
	rb, err := object.ExtractRecord(bCtx)
	var record *object.Record

	if err != nil {
		record = defaultRecordLog(bCtx)
	} else {
		record = rb.Build()
	}

	if resp, ok := bCtx.Input.Data()["json"]; ok {
		sensitiveResponseFields := []string{"access_token", "id_token", "refresh_token"}
		sanitizeData(resp, sensitiveResponseFields, "***")

		if jsonResp, err := json.Marshal(resp); err == nil {
			record.Response = string(jsonResp)
		}
	}

	util.SafeGoroutine(func() { object.AddRecord(record) })
}

func defaultRecordLog(ctx *beeCtx.Context) *object.Record {
	record := object.NewRecord(ctx)

	userId := getUser(ctx)
	if ctx.Request.URL.Path == "/api/logout" {
		userId, _ = ctx.Input.GetData("user").(string)
	}

	if userId != "" {
		record.Organization, record.User = util.GetOwnerAndNameFromIdWithPanic(userId)
	}

	return record
}

func sanitizeData(data interface{}, sensitiveResponseFields []string, stringToReplace string) {
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Ptr {
		v = v.Elem() // dereference if it is a pointer
	}

	if v.Kind() == reflect.Struct {
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			fieldType := v.Type().Field(i)

			// check if the field is a struct and recursively call sanitizeData
			if field.Kind() == reflect.Struct || (field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct) {
				sanitizeData(field.Addr().Interface(), sensitiveResponseFields, stringToReplace)
			} else {
				// check if the field name or its tag is in the list of sensitive fields
				for _, sensitiveField := range sensitiveResponseFields {
					if (fieldType.Name == sensitiveField || fieldType.Tag.Get("json") == sensitiveField) && field.CanSet() {
						if field.Kind() == reflect.String {
							field.SetString(stringToReplace)
						}
						break
					}
				}
			}
		}
	}
}
