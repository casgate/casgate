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
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
)

type Migrator_1_401_2_PR_67 struct{}

func (*Migrator_1_401_2_PR_67) IsMigrationNeeded() bool {
	return true
}

func (*Migrator_1_401_2_PR_67) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20231013UserMappingTransform--Transform user_mapping field to map[string][]string",
		Migrate: func(engine *xorm.Engine) error {
			tx := engine.NewSession()
			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}

			type oldProvider struct {
				Owner       string            `xorm:"varchar(100) notnull pk"`
				Name        string            `xorm:"varchar(100) notnull pk unique"`
				UserMapping map[string]string `xorm:"varchar(500)"`
			}

			providers := []*oldProvider{}
			err = tx.Table("provider").Find(&providers)
			if err != nil {
				return err
			}

			for _, provider := range providers {
				newProvider := &Provider{
					Owner: provider.Owner,
					Name:  provider.Name,
				}
				newProvider.UserMapping = make(map[string][]string, len(provider.UserMapping))

				for k, v := range provider.UserMapping {
					newProvider.UserMapping[k] = []string{v}
				}

				_, err = tx.Where("owner = ? and name = ?", newProvider.Owner, newProvider.Name).Cols("user_mapping").Update(newProvider)
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
