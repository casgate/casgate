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

package object

import (
	"encoding/json"
	"github.com/casdoor/casdoor/orm"
	"strconv"
	"strings"

	"github.com/beego/beego/context"
	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/builder"
)

var logPostOnly bool

var sensitiveDataKeys = []string{"password", "passwordSalt", "clientSecret", "accessSecret", "totpSecret"}

func init() {
	logPostOnly = conf.GetConfigBool("logPostOnly")
}

type Record struct {
	Id int `xorm:"int notnull pk autoincr" json:"id"`

	Owner       string `xorm:"varchar(100) index" json:"owner"`
	Name        string `xorm:"varchar(100) index" json:"name"`
	CreatedTime string `xorm:"varchar(100) index" json:"createdTime"`

	Organization string `xorm:"varchar(100)" json:"organization"`
	ClientIp     string `xorm:"varchar(100)" json:"clientIp"`
	User         string `xorm:"varchar(100)" json:"user"`
	Method       string `xorm:"varchar(100)" json:"method"`
	RequestUri   string `xorm:"varchar(1000)" json:"requestUri"`
	Action       string `xorm:"varchar(1000)" json:"action"`
	StatusCode   string `xorm:"varchar(5)" json:"statusCode"`

	Object       string        `xorm:"text" json:"object"`
	Response     string        `xorm:"text" json:"response"`
	Detail       *RecordDetail `xorm:"text" json:"detail,omitempty"`
	ExtendedUser *User         `xorm:"-" json:"extendedUser"`

	IsTriggered bool `json:"isTriggered"`
}

type RecordDetail struct {
	Reasons   []string    `json:"reasons,omitempty"`
	OldObject interface{} `json:"oldObject,omitempty"`
}

func (rd *RecordDetail) FromDB(bytes []byte) error {
	return json.Unmarshal(bytes, rd)
}

func (rd *RecordDetail) ToDB() ([]byte, error) {
	return json.Marshal(rd)
}

func NewRecord(ctx *context.Context) *Record {
	ip := strings.Replace(util.GetIPFromRequest(ctx.Request), ": ", "", -1)
	action := strings.Replace(ctx.Request.URL.Path, "/api/", "", -1)
	requestUri := util.FilterQuery(ctx.Request.RequestURI, []string{"accessToken"})
	if len(requestUri) > 1000 {
		requestUri = requestUri[0:1000]
	}

	object := ""
	if ctx.Input.RequestBody != nil && len(ctx.Input.RequestBody) != 0 {
		object = maskObjectFields(string(ctx.Input.RequestBody))
	}

	statusCode := ctx.ResponseWriter.Status
	if statusCode == 0 {
		statusCode = 200
	}

	record := Record{
		Name:        util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		ClientIp:    ip,
		User:        "",
		Method:      ctx.Request.Method,
		RequestUri:  requestUri,
		Action:      action,
		Object:      object,
		IsTriggered: false,
		StatusCode:  strconv.Itoa(statusCode),
	}
	return &record
}

func AddRecord(record *Record) bool {
	if logPostOnly {
		if record.Method == "GET" {
			logs.Info("record not saved, reason: GET request")

			return false
		}
	}

	if record.Organization == "app" {
		logs.Info("record not saved, reason: organization == app")

		return false
	}

	record.Owner = record.Organization

	errWebhook := SendWebhooks(record)
	if errWebhook == nil {
		record.IsTriggered = true
	} else {
		logs.Info("webhook: ", errWebhook)
	}

	affected, err := orm.AppOrmer.Engine.Insert(record)
	if err != nil {
		logs.Error("record not saved: %s", err.Error())

		panic(err)
	}

	return affected != 0
}

func GetRecordCount(field, value, fromDate, endDate string, filterRecord *Record) (int64, error) {
	session := orm.GetSession("", -1, -1, field, value, "", "")
	if fromDate != "" {
		session = session.Where(builder.Gt{"created_time": fromDate})
	}
	if endDate != "" {
		session = session.Where(builder.Lt{"created_time": endDate})
	}
	return session.Count(filterRecord)
}

func GetRecords(filterRecord *Record) ([]*Record, error) {
	records := []*Record{}
	err := orm.AppOrmer.Engine.Desc("id").Find(&records, filterRecord)
	if err != nil {
		return records, err
	}

	return records, nil
}

func GetPaginationRecords(offset, limit int, field, value, fromDate, endDate, sortField, sortOrder string, filterRecord *Record) ([]*Record, error) {
	records := []*Record{}
	session := orm.GetSession("", offset, limit, field, value, sortField, sortOrder)
	if fromDate != "" {
		session = session.Where(builder.Gt{"created_time": fromDate})
	}
	if endDate != "" {
		session = session.Where(builder.Lt{"created_time": endDate})
	}
	err := session.Find(&records, filterRecord)
	if err != nil {
		return records, err
	}

	return records, nil
}

func GetRecordsByField(record *Record) ([]*Record, error) {
	records := []*Record{}
	err := orm.AppOrmer.Engine.Find(&records, record)
	if err != nil {
		return records, err
	}

	return records, nil
}

func SendWebhooks(record *Record) error {
	webhooks, err := getWebhooksByOrganization(record.Organization)
	if err != nil {
		return err
	}

	for _, webhook := range webhooks {
		if !webhook.IsEnabled {
			continue
		}

		matched := false
		for _, event := range webhook.Events {
			if record.Action == event {
				matched = true
				break
			}
		}

		if matched {
			if webhook.IsUserExtended {
				user, err := getUser(record.Organization, record.User)
				user, err = GetMaskedUser(user, false, err)
				if err != nil {
					return err
				}

				record.ExtendedUser = user
			}

			err := sendWebhook(webhook, record)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func maskObjectFields(data string) string {
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(data), &jsonData)
	if err != nil {
		return data
	}
	for k := range jsonData {
		if util.InSlice(sensitiveDataKeys, k) {
			jsonData[k] = "***"
		}
	}

	res, err := json.Marshal(jsonData)
	if err != nil {
		return data
	}

	return string(res)
}
