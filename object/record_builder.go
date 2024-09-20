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
	"context"
	"errors"

	beeCtx "github.com/beego/beego/context"
	"github.com/beego/beego/logs"

	"github.com/casdoor/casdoor/util"
)

func NewRecordBuilder() *RecordBuilder {
	record := &Record{
		Name:        util.GenerateId(),
		CreatedTime: util.GetCurrentTime(),
		Detail: &RecordDetail{},
		Organization: builtInOrganization,
	}

	rb := &RecordBuilder{
		record: record,
	}

	return rb
}

func NewRecordBuilderWithRequestValues(bCtx *beeCtx.Context) *RecordBuilder {
	rb := &RecordBuilder{
		record: NewRecord(bCtx),
	}
	return rb
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

func (rb *RecordBuilder) AddReason(detail string) {
	if rb.record == nil {
		rb.record = &Record{
			Name:        util.GenerateId(),
			CreatedTime: util.GetCurrentTime(),
		}
	}

	if rb.record.Detail == nil {
		rb.record.Detail = &RecordDetail{}
	}
	rb.record.Detail.Reasons = append(rb.record.Detail.Reasons, detail)
}

func (rb *RecordBuilder) AddOldObject(object interface{}) *RecordBuilder {
	rb.record.Detail.OldObject = object

	return rb
}

func (rb *RecordBuilder) Build() *Record {
	return rb.record
}

type recordDataKey string

const (
	RecordDataKey            recordDataKey = "recordDataStore"
	RoleMappingRecordDataKey recordDataKey = "roleMappingRecordDataStore"
)

func ExtractRecordBuilderFromCtx(ctx context.Context) (*RecordBuilder, error) {
	rbVal := ctx.Value(RecordDataKey)

	if rbVal == nil {
		return nil, ErrExtractRecordFromCtx
	}

	rb, ok := rbVal.(*RecordBuilder)
	if !ok {
		return nil, ErrCastingToRecord
	}

	return rb, nil
}


func GetRecordBuilderFromContext(ctx context.Context) *RecordBuilder {
	rb, err := ExtractRecordBuilderFromCtx(ctx)
	if err == nil {
		return rb
	}

	logs.Error("extract record from context: %s", err.Error())

	return NewRecordBuilder()
}

var (
	ErrExtractRecordFromCtx = errors.New("record is not present")
	ErrCastingToRecord      = errors.New("casting to record")
)