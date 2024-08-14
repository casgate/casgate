// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"github.com/casdoor/casdoor/orm"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
)

type Migrator_1_336_0_PR_1970 struct{}

func (*Migrator_1_336_0_PR_1970) IsMigrationNeeded() bool {
	count, err := orm.AppOrmer.Engine.Where("password_type=? and password_salt=?", "salt", "").Count(&User{})
	if err != nil {
		// table doesn't exist
		return false
	}

	return count > 0
}

func (*Migrator_1_336_0_PR_1970) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20230615MigrateUser--Update salt if necessary",
		Migrate: func(engine *xorm.Engine) error {
			tx := engine.NewSession()

			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}

			userOwners := []string{}
			err = tx.Table(new(User)).Where("password_type=? and password_salt=?", "salt", "").Distinct("owner").Iterate(new(User), func(i int, bean interface{}) error {
				userOwners = append(userOwners, bean.(*User).Owner)
				return nil
			})

			if err != nil {
				return err
			}

			organizations := []*Organization{}
			err = tx.Table(new(Organization)).Where("owner = ?", "admin").In("name", userOwners).Find(&organizations)
			if err != nil {
				return err
			}
			for _, organization := range organizations {
				_, err = tx.Table(new(User)).Where("owner=? and password_salt=?", organization.Name, "").Cols("password_salt").Update(map[string]interface{}{"password_salt": organization.PasswordSalt})
				if err != nil {
					return err
				}
			}

			tx.Commit()

			return nil
		},
	}

	return &migration
}
