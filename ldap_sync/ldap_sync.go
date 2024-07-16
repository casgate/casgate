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

package ldap_sync

import (
	"errors"
	"github.com/casdoor/casdoor/orm"
	"time"
)

type LdapSyncHistory struct {
	Id             int                   `xorm:"int notnull pk" json:"id"`
	LdapSyncID     string                `xorm:"'ldap_sync_id' varchar(100) notnull" json:"ldap_sync_id"`
	StartedAt      time.Time             `xorm:"datetime notnull" json:"started_at"`
	EndedAt        time.Time             `xorm:"datetime" json:"ended_at"`
	Reason         string                `xorm:"varchar(100) notnull" json:"reason"`
	SyncedByUserID string                `xorm:"'synced_by_user_id' varchar(100) notnull" json:"synced_by_user_id"`
	Result         []LdapSyncHistoryUser `xorm:"json" json:"result"`
}

type LdapSync struct {
	Id        int       `xorm:"int notnull pk" json:"id"`
	LdapID    string    `xorm:"'ldap_id' varchar(100) notnull" json:"ldap_id"`
	Status    string    `xorm:"varchar(100) notnull" json:"status"`
	CreatedAt time.Time `xorm:"datetime notnull" json:"created_at"`
	UpdatedAt time.Time `xorm:"datetime notnull" json:"updated_at"`
}

type LdapSyncHistoryUser struct {
	UUID   string
	Action string
}

type LdapSyncStatus string

const LdapSyncStatusOn = LdapSyncStatus("on")
const LdapSyncStatusOff = LdapSyncStatus("off")

// LdapSyncTimeout Assume the sync operation failed
// if it is running more than 15 minutes.
const LdapSyncTimeout = 15 * time.Minute

var (
	LDAPSyncInProgress = errors.New("failed to lock ldap for sync: sync already in progress")
)

type LdapSyncRepository struct{}

func (r *LdapSyncRepository) LockLDAPForSync(ldapId string) error {
	exists, err := orm.AppOrmer.Engine.Exist(&LdapSync{LdapID: ldapId})
	if err != nil {
		return err
	}
	if exists {
		res, err := orm.AppOrmer.Engine.Exec(
			`UPDATE ldap_sync SET status = ?, updated_at = ? WHERE ldap_id = ? AND 
                                                         (status = 'off' OR (status = 'on' AND updated_at < ?))`,
			LdapSyncStatusOn,
			time.Now().UTC(),
			ldapId,
			time.Now().UTC().Add(-LdapSyncTimeout))
		if err != nil {
			return err
		}
		// For use with PostgreSQL rewrite using "Returning" clause
		rows, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if rows == 0 {
			return LDAPSyncInProgress
		}
		return nil
	}

	_, err = orm.AppOrmer.Engine.Exec(
		`INSERT INTO ldap_sync (ldap_id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		ldapId,
		LdapSyncStatusOn,
		time.Now().UTC(),
		time.Now().UTC())
	if err != nil {
		return err
	}
	return nil
}

func (r *LdapSyncRepository) UnlockLDAPForSync(ldapId string) error {
	_, err := orm.AppOrmer.Engine.Exec(
		`UPDATE ldap_sync SET status = ?, updated_at = ? WHERE ldap_id = ?`,
		LdapSyncStatusOff,
		time.Now().UTC(),
		ldapId)
	if err != nil {
		return err
	}
	return nil
}
