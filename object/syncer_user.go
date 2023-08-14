// Copyright 2021 The Casdoor Authors. All Rights Reserved.
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
	"fmt"
	"strings"
	"time"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

type OriginalUser = User

type Credential struct {
	Value string `json:"value"`
	Salt  string `json:"salt"`
}

func (syncer *Syncer) getOriginalUsers() ([]*OriginalUser, error) {
	sql := fmt.Sprintf("select * from %s", syncer.getTable())
	results, err := syncer.Ormer.Engine.QueryString(sql)
	if err != nil {
		return nil, err
	}

	// Memory leak problem handling
	// https://github.com/casdoor/casdoor/issues/1256
	users := syncer.getOriginalUsersFromMap(results)
	for _, m := range results {
		for k := range m {
			delete(m, k)
		}
	}

	return users, nil
}

func (syncer *Syncer) getOriginalUserMap() ([]*OriginalUser, map[string]*OriginalUser, error) {
	users, err := syncer.getOriginalUsers()
	if err != nil {
		return users, nil, err
	}

	m := map[string]*OriginalUser{}
	for _, user := range users {
		m[user.Id] = user
	}
	return users, m, nil
}

func (syncer *Syncer) addUser(user *OriginalUser) (bool, error) {
	m := syncer.getMapFromOriginalUser(user)
	keyString, valueString := syncer.getSqlKeyValueStringFromMap(m)

	sql := fmt.Sprintf("insert into %s (%s) values (%s)", syncer.getTable(), keyString, valueString)
	res, err := syncer.Ormer.Engine.Exec(sql)
	if err != nil {
		return false, err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

/*func (syncer *Syncer) getOriginalColumns() []string {
	res := []string{}
	for _, tableColumn := range syncer.TableColumns {
		if tableColumn.CasdoorName != "Id" {
			res = append(res, tableColumn.Name)
		}
	}
	return res
}*/

func (syncer *Syncer) getCasdoorColumns() []string {
	res := []string{}
	for _, tableColumn := range syncer.TableColumns {
		if tableColumn.CasdoorName != "Id" {
			v := util.CamelToSnakeCase(tableColumn.CasdoorName)
			res = append(res, v)
		}
	}
	return res
}

func (syncer *Syncer) updateUser(user *OriginalUser) (bool, error) {
	m := syncer.getMapFromOriginalUser(user)
	pkValue := m[syncer.TablePrimaryKey]
	delete(m, syncer.TablePrimaryKey)
	setString := syncer.getSqlSetStringFromMap(m)

	sql := fmt.Sprintf("update %s set %s where %s = %s", syncer.getTable(), setString, syncer.TablePrimaryKey, pkValue)
	res, err := syncer.Ormer.Engine.Exec(sql)
	if err != nil {
		return false, err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (syncer *Syncer) updateUserForOriginalFields(user *User) (bool, error) {
	var err error
	owner, name := util.GetOwnerAndNameFromId(user.GetId())
	oldUser, err := getUserById(owner, name)
	if oldUser == nil || err != nil {
		return false, err
	}

	if user.Avatar != oldUser.Avatar && user.Avatar != "" {
		user.PermanentAvatar, err = getPermanentAvatarUrl(user.Owner, user.Name, user.Avatar, true)
		if err != nil {
			return false, err
		}
	}

	columns := syncer.getCasdoorColumns()
	columns = append(columns, "affiliation", "hash", "pre_hash")
	affected, err := ormer.Engine.ID(core.PK{oldUser.Owner, oldUser.Name}).Cols(columns...).Update(user)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (syncer *Syncer) calculateHash(user *OriginalUser) string {
	values := []string{}
	m := syncer.getMapFromOriginalUser(user)
	for _, tableColumn := range syncer.TableColumns {
		if tableColumn.IsHashed {
			values = append(values, m[tableColumn.Name])
		}
	}

	s := strings.Join(values, "|")
	return util.GetMd5Hash(s)
}

func (syncer *Syncer) initAdapter() {
	if syncer.Ormer == nil {
		var dataSourceName string
		if syncer.DatabaseType == "mssql" {
			dataSourceName = fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s", syncer.User, syncer.Password, syncer.Host, syncer.Port, syncer.Database)
		} else if syncer.DatabaseType == "postgres" {
			dataSourceName = fmt.Sprintf("user=%s password=%s host=%s port=%d sslmode=disable dbname=%s", syncer.User, syncer.Password, syncer.Host, syncer.Port, syncer.Database)
		} else {
			dataSourceName = fmt.Sprintf("%s:%s@tcp(%s:%d)/", syncer.User, syncer.Password, syncer.Host, syncer.Port)
		}

		if !isCloudIntranet {
			dataSourceName = strings.ReplaceAll(dataSourceName, "dbi.", "db.")
		}

		syncer.Ormer = NewAdapter(syncer.DatabaseType, dataSourceName, syncer.Database)
	}
}

func RunSyncUsersJob() {
	syncers, err := GetSyncers("admin")
	if err != nil {
		panic(err)
	}

	for _, syncer := range syncers {
		addSyncerJob(syncer)
	}

	time.Sleep(time.Duration(1<<63 - 1))
}
