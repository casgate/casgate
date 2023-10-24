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

	"github.com/casdoor/casdoor/object"
)

func (r *Repo) GetModel(ctx context.Context, owner string, name string, forUpdate bool) (*object.Model, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	query := r.trm.GetEngine(ctx).Where("owner = ? and name = ?", owner, name)
	if forUpdate {
		query = query.ForUpdate()
	}

	m := object.Model{}
	existed, err := query.Get(&m)
	if err != nil {
		return &m, err
	}

	if existed {
		return &m, nil
	} else {
		return nil, nil
	}
}
