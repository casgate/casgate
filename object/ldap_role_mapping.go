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

func buildRoleMappingMap(roleMappingItems []*RoleMappingItem) RoleMappingMap {
	roleMappingMap := make(RoleMappingMap)
	for _, roleMappingItem := range roleMappingItems {
		for _, roleMappingItemValue := range roleMappingItem.Values {
			if roleMappingItem.Role == "" {
				continue
			}

			roleMappingAttribute := RoleMappingAttribute(roleMappingItem.Attribute)
			if _, ok := roleMappingMap[roleMappingAttribute]; !ok {
				roleMappingMap[roleMappingAttribute] = make(RoleMappingMapItem)
			}

			roleMappingValue := RoleMappingItemValue(roleMappingItemValue)
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

func SyncRoles(syncUser LdapUser, name, owner string) error {
	userId := util.GetId(owner, name)

	currentUserRoles, err := GetRolesByUser(userId)
	if err != nil {
		return err
	}

	for _, role := range currentUserRoles {
		if !util.InSlice(syncUser.Roles, role.GetId()) {
			role.Roles = util.DeleteVal(role.Roles, userId)
			_, err = UpdateRole(role.GetId(), role)
			if err != nil {
				return err
			}
		}
	}

	for _, roleId := range syncUser.Roles {
		role, err := GetRole(roleId)
		if err != nil {
			return err
		}

		if role == nil {
			// we can't add role that doesn't exist
			continue
		}

		if role.Owner != owner {
			// we shouldn't add role from another organization (if it happened by any reason) to user, so skip
			continue
		}

		if !util.InSlice(role.Users, userId) {
			role.Users = append(role.Users, userId)

			_, err = UpdateRole(role.GetId(), role)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
