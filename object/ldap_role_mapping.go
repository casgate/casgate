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
	"github.com/casdoor/casdoor/ldap_sync"
	"github.com/casdoor/casdoor/util"
)

func SyncLdapAttributes(syncUser ldap_sync.LdapUser, name, owner string) error {
	userId := util.GetId(owner, name)
	user, err := GetUser(userId)
	if err != nil {
		return err
	}

	return SyncAttributesToUser(
		user,
		syncUser.BuildLdapDisplayName(),
		syncUser.Email,
		syncUser.Mobile,
		user.Avatar,
		[]string{syncUser.Address},
	)
}

func SyncLdapRoles(syncUser ldap_sync.LdapUser, name, owner string) error {
	userId := util.GetId(owner, name)
	user, err := GetUser(userId)
	if err != nil {
		return err
	}

	return SyncRolesToUser(user, syncUser.Roles)
}
