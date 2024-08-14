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

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
)

type Migrator_1_376_2_PR_10 struct{}

func (*Migrator_1_376_2_PR_10) IsMigrationNeeded() bool {
	exist, _ := orm.AppOrmer.Engine.IsTableExist("domain")

	return exist
}

func (*Migrator_1_376_2_PR_10) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20230830MigrateDomains--Create a domains from roles and permissions to separate domain table",
		Migrate: func(engine *xorm.Engine) error {
			tx := engine.NewSession()

			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}

			roles := []*Role{}
			err = tx.Table("role").Find(&roles)
			if err != nil {
				return err
			}

			createdDomains := make(map[string]bool, 0)

			for _, role := range roles {
				for _, domainName := range role.Domains {
					domainId := util.GetId(role.Owner, domainName)
					role.Domains = util.ReplaceVal(role.Domains, domainName, domainId)
					if !createdDomains[domainId] {
						_, err = tx.Insert(&Domain{
							Owner:       role.Owner,
							Name:        domainName,
							CreatedTime: time.Now().Format("2006-01-02T15:04:05Z07:00"),
							DisplayName: domainName,
							Domains:     []string{},
							IsEnabled:   true,
						})
						if err != nil {
							return err
						}
						createdDomains[domainId] = true
					}
				}
				_, err = tx.Where("owner = ? and name = ?", role.Owner, role.Name).Cols("domains").Update(role)
				if err != nil {
					return err
				}
			}

			permissions := []*Permission{}
			err = tx.Table("permission").Find(&permissions)
			if err != nil {
				return err
			}

			for _, permission := range permissions {
				for _, domainName := range permission.Domains {
					domainId := util.GetId(permission.Owner, domainName)
					permission.Domains = util.ReplaceVal(permission.Domains, domainName, domainId)
					if !createdDomains[domainId] {
						_, err = tx.Insert(&Domain{
							Owner:       permission.Owner,
							Name:        domainName,
							CreatedTime: time.Now().Format("2006-01-02T15:04:05Z07:00"),
							DisplayName: domainName,
							Domains:     []string{},
							IsEnabled:   true,
						})
						if err != nil {
							return err
						}
						createdDomains[domainId] = true
					}
				}
				_, err = tx.Where("owner = ? and name = ?", permission.Owner, permission.Name).Cols("domains").Update(permission)
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
