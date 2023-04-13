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
	"errors"

	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
)

type Migrator_1_subscription struct{}

func (*Migrator_1_subscription) IsMigrationNeeded() bool {
	exist, _ := adapter.Engine.IsTableExist("subscription")

	return !exist
}

func (*Migrator_1_subscription) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20230322MigrateSubscription--Create a new table `subscription`",
		Migrate: func(engine *xorm.Engine) error {
			if alreadyCreated, _ := engine.IsTableExist("subscription"); alreadyCreated {
				return errors.New("there is already a table called 'subscription', please rename or delete it for casdoor version migration and restart")
			}

			tx := engine.NewSession()

			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}

			err = tx.Table("subscription").CreateTable(&Subscription{})

			if err != nil {
				return err
			}

			err = tx.Table("plan").CreateTable(&Plan{})

			if err != nil {
				return err
			}

			err = tx.Table("pricing").CreateTable(&Pricing{})

			if err != nil {
				return err
			}

			tx.Commit()

			return nil
		},
	}

	return &migration
}
