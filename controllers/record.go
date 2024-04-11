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

package controllers

import (
	"encoding/json"
	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// GetRecords
// @Title GetRecords
// @Tag Record API
// @Description get all records
// @Param   pageSize     query    string  true        "The size of each page"
// @Param   p     query    string  true        "The number of the page"
// @Success 200 {object} object.Record The Response object
// @router /get-records [get]
func (c *ApiController) GetRecords() {
	pageSize := c.Input().Get("pageSize")
	pageNumber := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")
	fromDate := c.Input().Get("fromDate")
	endDate := c.Input().Get("endDate")
	organizationName := c.Input().Get("organizationName")

	filterRecord := &object.Record{}

	if c.IsGlobalAdmin() {
		if organizationName != "" {
			filterRecord.Organization = organizationName
		}
	} else {
		user, ok := c.RequireSignedInUser()
		if !ok {
			c.ResponseUnauthorized(c.T("auth:Unauthorized operation"))
			return
		}

		if !user.IsAdmin {
			c.ResponseForbidden(c.T("auth:Forbidden operation"))
			return
		}

		if organizationName != "" && organizationName != user.Owner {
			c.ResponseForbidden(c.T("auth:Unable to get records from other organization without global administrator role"))
			return
		}

		filterRecord.Organization = user.Owner
	}

	var (
		limit, offset int
		paginator     *pagination.Paginator
	)
	if pageSize == "" || pageNumber == "" {
		limit = -1
		offset = -1
	} else {
		limit = util.ParseInt(pageSize)
		count, err := object.GetRecordCount(field, value, fromDate, endDate, filterRecord)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		paginator = pagination.SetPaginator(c.Ctx, limit, count)
		offset = paginator.Offset()
	}

	records, err := object.GetPaginationRecords(offset, limit, field, value, fromDate, endDate, sortField, sortOrder, filterRecord)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if paginator == nil {
		c.ResponseOk(records)
	} else {
		c.ResponseOk(records, paginator.Nums())
	}
}

// GetRecordsByFilter
// @Tag Record API
// @Title GetRecordsByFilter
// @Description get records by filter
// @Success 200 {object} object.Record The Response object
// @router /get-records-filter [post]
func (c *ApiController) GetRecordsByFilter() {
	body := string(c.Ctx.Input.RequestBody)

	record := &object.Record{}
	err := util.JsonToStruct(body, record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	records, err := object.GetRecordsByField(record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(records)
}

// AddRecord
// @Title AddRecord
// @Tag Record API
// @Description add a record
// @Param   body    body   object.Record  true        "The details of the record"
// @Success 200 {object} controllers.Response The Response object
// @router /add-record [post]
func (c *ApiController) AddRecord() {
	var record object.Record
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &record)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddRecord(&record))
	c.ServeJSON()
}
