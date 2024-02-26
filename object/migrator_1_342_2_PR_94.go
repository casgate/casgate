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
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
)

type Migrator_1_342_0_PR_94 struct{}

func (*Migrator_1_342_0_PR_94) IsMigrationNeeded() bool {
	return true
}

func (*Migrator_1_342_0_PR_94) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20240226ApllicationPasswordRecovery-- Enable password recovery flag for all existing applications",
		Migrate: func(engine *xorm.Engine) error {
			tx := engine.NewSession()
			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}

			_, err = tx.Cols("enable_password_recovery").Update(&Application{EnablePasswordRecovery: true})
			if err != nil {
				return err
			}

			tx.Commit()

			return nil
		},
	}

	return &migration
}
