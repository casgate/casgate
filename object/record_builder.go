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
	"fmt"

	"github.com/beego/beego/context"
)

func NewRecordBuilder(ctx *context.Context) *RecordBuilder {
	rb := &RecordBuilder{
		record: NewRecord(ctx),
	}

	rb.setDefaultFieldValues()

	return rb
}

type RecordBuilder struct {
	record *Record
}

func (rb *RecordBuilder) setDefaultFieldValues() {
	rb.record.Organization = "built-in"
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

func (rb *RecordBuilder) AddDetail(detail string) *RecordBuilder {
	rb.record.Detail += fmt.Sprintln("detail: ", detail)

	return rb
}

func (rb *RecordBuilder) AddOldObject(object interface{}) *RecordBuilder {
	if jsonObj, err := json.Marshal(object); err == nil {
		rb.record.Detail += fmt.Sprintln("old object: ", string(jsonObj))
	}

	return rb
}

func (rb *RecordBuilder) Build() *Record {
	return rb.record
}

type recordDataKey string

const dataKey recordDataKey = "recordsStore"

func ExtractRecord(ctx *context.Context) *RecordBuilder {
	values := ctx.Input.GetData(dataKey)

	if values == nil {
		return nil
	}

	rb, ok := values.(*RecordBuilder)
	if !ok {
		return nil
	}

	return rb
}

func GetRecord(ctx *context.Context) *RecordBuilder {
	rb := ExtractRecord(ctx)
	if rb == nil {
		rb = NewRecordBuilder(ctx)
		ctx.Input.SetData(dataKey, rb)
	}

	return rb
}
