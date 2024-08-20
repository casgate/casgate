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
	"context"
	"strings"

	"github.com/casdoor/casdoor/util"
)

type (
	RoleMappingItemValue  string
	RoleMappingItemRoleId string
	RoleMappingItemRoles  []RoleMappingItemRoleId
	RoleMappingMapItem    map[RoleMappingItemValue]RoleMappingItemRoles
	RoleMappingAttribute  string
	RoleMappingMap        map[RoleMappingAttribute]RoleMappingMapItem
)

func (r RoleMappingItemRoles) Contains(item RoleMappingItemRoleId) bool {
	for _, val := range r {
		if val == item {
			return true
		}
	}
	return false
}

func (r RoleMappingItemRoles) StrRoles() []string {
	result := make([]string, 0, len(r))
	for _, role := range r {
		result = append(result, string(role))
	}
	return result
}

func buildRoleMappingMap(roleMappingItems []*RoleMappingItem, enableCaseInsensitivity bool) RoleMappingMap {
	roleMappingMap := make(RoleMappingMap)
	for _, roleMappingItem := range roleMappingItems {
		for _, roleMappingItemValue := range roleMappingItem.Values {
			if roleMappingItem.Role == "" {
				continue
			}

			var roleMappingAttribute RoleMappingAttribute
			if enableCaseInsensitivity {
				roleMappingAttribute = RoleMappingAttribute(strings.ToLower(roleMappingItem.Attribute))
			} else {
				roleMappingAttribute = RoleMappingAttribute(roleMappingItem.Attribute)
			}

			if _, ok := roleMappingMap[roleMappingAttribute]; !ok {
				roleMappingMap[roleMappingAttribute] = make(RoleMappingMapItem)
			}

			var roleMappingValue RoleMappingItemValue
			if enableCaseInsensitivity {
				roleMappingValue = RoleMappingItemValue(strings.ToLower(roleMappingItemValue))
			} else {
				roleMappingValue = RoleMappingItemValue(roleMappingItemValue)
			}

			if _, ok := roleMappingMap[roleMappingAttribute][roleMappingValue]; !ok {
				roleMappingMap[roleMappingAttribute][roleMappingValue] = make([]RoleMappingItemRoleId, 0)
			}

			roleMappingRole := RoleMappingItemRoleId(roleMappingItem.Role)
			if !roleMappingMap[roleMappingAttribute][roleMappingValue].Contains(roleMappingRole) {
				roleMappingMap[roleMappingAttribute][roleMappingValue] = append(roleMappingMap[roleMappingAttribute][roleMappingValue], roleMappingRole)
			}

		}
	}
	return roleMappingMap
}

func SyncLdapAttributes(syncUser LdapUser, name, owner string) error {
	userId := util.GetId(owner, name)
	user, err := GetUser(userId)
	if err != nil {
		return err
	}

	return SyncAttributesToUser(user, syncUser.buildLdapDisplayName(), syncUser.Email, syncUser.Mobile, user.Avatar, []string{syncUser.Address})
}

func SyncLdapRoles(ctx context.Context, syncUser LdapUser, name, owner string) error {
	userId := util.GetId(owner, name)
	user, err := GetUser(userId)
	if err != nil {
		return err
	}

	return SyncRolesToUser(ctx, user, syncUser.Roles)
}
