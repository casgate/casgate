// Copyright 2024 The Casgate Authors. All Rights Reserved.
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
	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/orm"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
	"github.com/xorm-io/xorm/schemas"
)

type Migrator_202408201846 struct{}

func (*Migrator_202408201846) IsMigrationNeeded() bool {
	exist, _ := orm.AppOrmer.Engine.IsTableExist("role")

	if exist {
		return true
	}
	return false
}

func (*Migrator_202408201846) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20240820IncreaseFieldsLenForRole--Increase fields length for role: display_name(255), description(255)",
		Migrate: func(engine *xorm.Engine) error {
			dbType := engine.Dialect().URI().DBType

			if dbType != schemas.POSTGRES && dbType != schemas.MYSQL {
				logs.Warn("You must make migration: 20240820IncreaseFieldsLenForRole manually")
				return nil
			}

			if dbType == schemas.POSTGRES {
				return migratePG(engine)
			}

			return nil
		},
	}

	return &migration
}

func (*Migrator_202408201846) migratePG(engine *xorm.Engine) error {
	tx := engine.NewSession()
	defer tx.Close()

	err := tx.Begin()
	if err != nil {
		return err
	}

	sql := `
		ALTER TABLE "role" ALTER COLUMN "display_name" TYPE varchar(255);
		ALTER TABLE "role" ALTER COLUMN "description" TYPE varchar(255);
	`

	if _, err = tx.Query(sql); err != nil {
		return err
	}

	return tx.Commit()
}
