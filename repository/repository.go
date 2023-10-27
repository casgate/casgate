// Copyright 2023 The Casgate Authors. All Rights Reserved.
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

package repository

import (
	"context"

	"github.com/xorm-io/xorm"
)

type TransactionManager interface {
	WithTx(parentCtx context.Context, f func(ctx context.Context) error) error
	GetEngine(ctx context.Context) xorm.Interface
}

type Repo struct {
	trm TransactionManager
}

// NewRepo creates new instance of repository
func NewRepo(trm TransactionManager) *Repo {
	return &Repo{
		trm: trm,
	}
}
