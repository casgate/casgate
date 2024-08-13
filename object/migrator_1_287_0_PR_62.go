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

package object

import (
	"github.com/casdoor/casdoor/orm"
	"time"

	"github.com/beego/beego/logs"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
	"github.com/xorm-io/xorm/schemas"
)

type Migrator_1_287_0_PR_62 struct{}

func (*Migrator_1_287_0_PR_62) IsMigrationNeeded() bool {
	metas, err := orm.AppOrmer.Engine.DBMetas()
	if err != nil {
		return false
	}
	for _, meta := range metas {
		if meta.Name == "user" {
			for _, col := range meta.Columns() {
				if col.Name == "password_change_required" {
					return true
				}
			}
			return false
		}
	}
	return false
}

func (*Migrator_1_287_0_PR_62) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20231013UserMappingTransform--Transform password change required field to password_change_time",
		Migrate: func(engine *xorm.Engine) error {
			tx := engine.NewSession()
			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}

			type oldUser struct {
				Id                     string `xorm:"varchar(100) index" json:"id"`
				PasswordChangeRequired bool   `xorm:"varchar(100)" json:"passwordChangeRequired"`
			}

			type curUser struct {
				Id                 string    `xorm:"varchar(100) index" json:"id"`
				PasswordChangeTime time.Time `json:"passwordChangeTime"`
			}

			users := []*oldUser{}
			err = tx.Table("user").Find(&users)
			if err != nil {
				return err
			}

			for _, user := range users {
				if user.PasswordChangeRequired {
					newUser := &curUser{
						Id:                 user.Id,
						PasswordChangeTime: time.Now(),
					}
					_, err = tx.Table("user").Where("id = ?", newUser.Id).Cols("password_change_time").Update(newUser)
					if err != nil {
						return err
					}
				}
			}

			dbType := engine.Dialect().URI().DBType
			if dbType != schemas.POSTGRES && dbType != schemas.MYSQL {
				logs.Warn("You must delete 'password_change_required' field from 'user' table manualy	(migration: 20231013UserMappingTransform)")
				return nil
			}

			dropColumnSql := "ALTER TABLE `user` DROP COLUMN `password_change_required`"
			if _, err = tx.Query(dropColumnSql); err != nil {
				return err
			}

			tx.Commit()

			return nil
		},
	}

	return &migration
}
