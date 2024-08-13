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
	"fmt"
	"github.com/casdoor/casdoor/orm"
	"strconv"
	"time"
)

type LdapSync struct {
	Id        int       `xorm:"int notnull pk" json:"id"`
	LdapID    string    `xorm:"'ldap_id' varchar(100) notnull" json:"ldap_id"`
	Status    string    `xorm:"varchar(100) notnull" json:"status"`
	CreatedAt time.Time `xorm:"datetime notnull" json:"created_at"`
	UpdatedAt time.Time `xorm:"datetime notnull" json:"updated_at"`
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

func (r *LdapSyncRepository) LockLDAPForSync(ldapId string) (int, error) {
	ldapSync := &LdapSync{LdapID: ldapId}
	exists, err := orm.AppOrmer.Engine.Get(ldapSync)
	if err != nil {
		return 0, err
	}
	if exists {
		res, err := orm.AppOrmer.Engine.QueryString(
			`UPDATE ldap_sync SET status = ?, updated_at = ? WHERE ldap_id = ? AND 
                                                         (status = 'off' OR (status = 'on' AND updated_at < ?)) RETURNING id`,
			LdapSyncStatusOn,
			time.Now().UTC(),
			ldapId,
			time.Now().UTC().Add(-LdapSyncTimeout))
		if err != nil {
			return 0, err
		}
		if res == nil {
			return 0, LDAPSyncInProgress
		}
		id := fmt.Sprintf("%s", res[0]["id"])
		ldapSyncID, err := strconv.Atoi(id)
		if err != nil {
			return 0, err
		}
		return ldapSyncID, nil
	}

	_, err = orm.AppOrmer.Engine.Exec(
		`INSERT INTO ldap_sync (ldap_id, status, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		ldapId,
		LdapSyncStatusOn,
		time.Now().UTC(),
		time.Now().UTC())
	if err != nil {
		return 0, err
	}
	_, err = orm.AppOrmer.Engine.Get(ldapSync)
	if err != nil {
		return 0, err
	}
	return ldapSync.Id, nil
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
