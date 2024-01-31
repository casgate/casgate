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
	"github.com/xorm-io/core"
)

func (r *Repo) GetUsers(ctx context.Context, owner string) ([]*object.User, error) {
	users := []*object.User{}
	err := r.trm.GetEngine(ctx).Desc("created_time").Find(&users, &object.User{Owner: owner})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (r *Repo) UpdateUserPasswordChangeTime(ctx context.Context, user *object.User) error {
	_, err := r.trm.GetEngine(ctx).ID(core.PK{user.Owner, user.Name}).Cols("password_change_time").Update(user)
	if err != nil {
		return err
	}

	return nil
}

func (r *Repo) GetUsersWithoutRequiredPasswordChange(ctx context.Context, owner string) ([]*object.User, error) {
	var users []*object.User
	err := r.trm.GetEngine(ctx).Table("user").Where("password_change_time >= now() or password_change_time is null and owner = ?", owner).Find(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (r *Repo) ResetUsersPasswordChangeTime(ctx context.Context, owner string) error {
	bean := make(map[string]interface{})
	bean["password_change_time"] = nil
	_, err := r.trm.GetEngine(ctx).Table("user").Where("password_change_time >= now() and owner = ?", owner).Cols("password_change_time").Update(bean)
	if err != nil {
		return err
	}
	return nil
}
