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
	"fmt"

	"github.com/beego/beego/context"
)

func NewRecordBuilder(ctx *context.Context) *RecordBuilder {
	return &RecordBuilder{
		record: NewRecord(ctx),
	}
}

type RecordBuilder struct {
	record *Record
}

func (rb *RecordBuilder) WithOrganization(organization string) *RecordBuilder {
	rb.record.Organization = organization

	return rb
}

func (rb *RecordBuilder) WithUsername(username string) *RecordBuilder {
	rb.record.User = username

	return rb
}

func (rb *RecordBuilder) WithAction(action string) *RecordBuilder {
	rb.record.Action = action

	return rb
}

func (rb *RecordBuilder) WithResponse(response string) *RecordBuilder {
	rb.record.Response = response

	return rb
}

func (rb *RecordBuilder) WithDetail(detail string) *RecordBuilder {
	rb.record.Detail = detail

	return rb
}

func (rb *RecordBuilder) WithReason(reason string) *RecordBuilder {
	rb.record.Detail += fmt.Sprintln("reason: ", reason)

	return rb
}

func (rb *RecordBuilder) Build() *Record {
	return rb.record
}

type recordDataKey string

const dataKey recordDataKey = "recordsStore"

func SaveOnSuccess(ctx *context.Context, record *Record) {
	records := ExtractRecords(ctx)
	records = append(records, record)

	ctx.Input.SetData(dataKey, records)
}

func ExtractRecords(ctx *context.Context) []*Record {
	values := ctx.Input.GetData(dataKey)
	if values == nil {
		return make([]*Record, 0)
	}

	recordData, ok := values.([]*Record)
	if !ok {
		return make([]*Record, 0)
	}

	return recordData
}
