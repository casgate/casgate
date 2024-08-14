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
	"github.com/beego/beego"
	"github.com/casdoor/casdoor/orm"
	"github.com/xorm-io/xorm/migrate"
)

type Migrator interface {
	IsMigrationNeeded() bool
	DoMigration() *migrate.Migration
}

func DoMigration() {
	migrators := []Migrator{
		&Migrator_1_101_0_PR_1083{},
		&Migrator_1_235_0_PR_1530{},
		&Migrator_1_240_0_PR_1539{},
		&Migrator_1_314_0_PR_1841{},
		&Migrator_1_336_0_PR_1970{},
		&Migrator_1_376_2_PR_10{},
		&Migrator_1_401_2_PR_67{},
		&Migrator_1_198_0_PR_56{},
		&Migrator_1_287_0_PR_62{},
		&Migrator_1_342_0_PR_94{},
		&Migrator_1_19504_0_PR_105{},
		&Migrator_1_19503_0_PR_106{},
		&Migrator_1_19505_0_PR_191{},
		&Migrator_202407151619{},
		// more migrators add here in chronological order...
	}

	migrations := []*migrate.Migration{}

	for _, migrator := range migrators {
		if migrator.IsMigrationNeeded() {
			migrations = append(migrations, migrator.DoMigration())
		}
	}

	options := &migrate.Options{
		TableName:    "migration",
		IDColumnName: "id",
	}

	m := migrate.New(orm.AppOrmer.Engine, options, migrations)
	err := m.Migrate()
	if err != nil {
		panic(err)
	}
}

// InitTestConfig
// Initialize database fixtures for testing.
func InitTestConfig() {
	err := beego.LoadAppConfig("ini", "../conf/app.conf")
	if err != nil {
		panic(err)
	}

	beego.BConfig.WebConfig.Session.SessionOn = true

	orm.InitAdapter()
	CreateTables()
	DoMigration()
}
