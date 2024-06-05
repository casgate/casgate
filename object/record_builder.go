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
	goCtx "context"
	"errors"

	beeCtx "github.com/beego/beego/context"
	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/util"
)

func NewRecordBuilder() *RecordBuilder {
	record := &Record{
		Name:        util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
	}

	rb := &RecordBuilder{
		record: record,
	}

	rb.setDefaultFieldValues()

	return rb
}

func NewRecordBuilderFromCtx(bCtx *beeCtx.Context) *RecordBuilder {
	rb := &RecordBuilder{
		record: NewRecord(bCtx),
	}

	rb.setDefaultFieldValues()

	return rb
}

type RecordBuilder struct {
	record *Record
}

func (rb *RecordBuilder) setDefaultFieldValues() {
	rb.record.Organization = "built-in"
	rb.record.Detail = &RecordDetail{}
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

func (rb *RecordBuilder) AddReason(detail string) *RecordBuilder {
	if rb.record == nil {
		rb.record = &Record{
			Name:        util.GenerateId(),
			CreatedTime: util.GetCurrentTime(),
		}
	}

	if rb.record.Detail == nil {
		rb.setDefaultFieldValues()
	}

	rb.record.Detail.Reasons = append(rb.record.Detail.Reasons, detail)

	return rb
}

func (rb *RecordBuilder) AddOldObject(object interface{}) *RecordBuilder {
	rb.record.Detail.OldObject = object

	return rb
}

func (rb *RecordBuilder) Build() *Record {
	return rb.record
}

type recordDataKey string

const RecordDataKey recordDataKey = "recordDataStore"

func ExtractRecord(bCtx *beeCtx.Context) (*RecordBuilder, error) {
	reqCtx := bCtx.Request.Context()

	return extractRecordFromCtx(reqCtx)
}

func GetRecord(ctx goCtx.Context) *RecordBuilder {
	rb, err := extractRecordFromCtx(ctx)
	if err == nil {
		return rb
	}

	logs.Error("extract record from context: %s", err.Error())

	return &RecordBuilder{}
}

var (
	ErrExtractRecordFromCtx = errors.New("record is not present")
	ErrCastingToRecord      = errors.New("casting to record")
)

func extractRecordFromCtx(goCtx goCtx.Context) (*RecordBuilder, error) {
	recordVal := goCtx.Value(RecordDataKey)

	if recordVal == nil {
		return nil, ErrExtractRecordFromCtx
	}

	rb, ok := recordVal.(*RecordBuilder)
	if !ok {
		return nil, ErrCastingToRecord
	}

	return rb, nil
}
