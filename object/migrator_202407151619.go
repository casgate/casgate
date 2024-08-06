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

type Migrator_202407151619 struct{}

func (*Migrator_202407151619) IsMigrationNeeded() bool {
	return true
}

func (*Migrator_202407151619) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20240715LDAPSyncHistory -- add tables to store ldap sync history and ldap sync info",
		Migrate: func(engine *xorm.Engine) error {
			tx := engine.NewSession()
			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}
			sql := `
CREATE TABLE ldap_sync_history (
    id SERIAL NOT NULL PRIMARY KEY,
    ldap_sync_id INT NOT NULL ,
    ldap_id TEXT NOT NULL,
    started_at TIMESTAMP NOT NULL,
    ended_at TIMESTAMP,
    reason TEXT NOT NULL,
    synced_by_user_id TEXT NOT NULL,
    result JSONB
);
`
			_, err = engine.Exec(sql)
			if err != nil {
				return err
			}

			sql = `
CREATE TABLE ldap_sync (
    id SERIAL NOT NULL PRIMARY KEY,
    ldap_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMP not null,
    updated_at TIMESTAMP not null
);
`
			_, err = engine.Exec(sql)
			if err != nil {
				return err
			}
			tx.Commit()

			return nil
		},
	}

	return &migration
}
