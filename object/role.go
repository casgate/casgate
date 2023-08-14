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

	"github.com/casdoor/casdoor/conf"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

type Role struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Description string `xorm:"varchar(100)" json:"description"`

	Users     []string `xorm:"mediumtext" json:"users"`
	Roles     []string `xorm:"mediumtext" json:"roles"`
	Domains   []string `xorm:"mediumtext" json:"domains"`
	IsEnabled bool     `json:"isEnabled"`
}

func GetRoleCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Role{})
}

func GetRoles(owner string) ([]*Role, error) {
	roles := []*Role{}
	err := ormer.Engine.Desc("created_time").Find(&roles, &Role{Owner: owner})
	if err != nil {
		return roles, err
	}

	return roles, nil
}

func GetPaginationRoles(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Role, error) {
	roles := []*Role{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&roles)
	if err != nil {
		return roles, err
	}

	return roles, nil
}

func getRole(owner string, name string) (*Role, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	role := Role{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&role)
	if err != nil {
		return &role, err
	}

	if existed {
		return &role, nil
	} else {
		return nil, nil
	}
}

func GetRole(id string) (*Role, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	return getRole(owner, name)
}

func UpdateRole(id string, role *Role) (bool, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	oldRole, err := getRole(owner, name)
	if err != nil {
		return false, err
	}

	if oldRole == nil {
		return false, nil
	}

	visited := map[string]struct{}{}

	permissions, err := GetPermissionsByRole(id)
	if err != nil {
		return false, err
	}

	for _, permission := range permissions {
		removeGroupingPolicies(permission)
		removePolicies(permission)
		visited[permission.GetId()] = struct{}{}
	}

	ancestorRoles, err := GetAncestorRoles(id)
	if err != nil {
		return false, err
	}

	for _, r := range ancestorRoles {
		permissions, err := GetPermissionsByRole(r.GetId())
		if err != nil {
			return false, err
		}

		for _, permission := range permissions {
			permissionId := permission.GetId()
			if _, ok := visited[permissionId]; !ok {
				removeGroupingPolicies(permission)
				visited[permissionId] = struct{}{}
			}
		}
	}

	if name != role.Name {
		err := roleChangeTrigger(name, role.Name)
		if err != nil {
			return false, err
		}
	}

	affected, err := ormer.Engine.ID(core.PK{owner, name}).AllCols().Update(role)
	if err != nil {
		return false, err
	}

	visited = map[string]struct{}{}
	newRoleID := role.GetId()
	permissions, err = GetPermissionsByRole(newRoleID)
	if err != nil {
		return false, err
	}

	for _, permission := range permissions {
		addGroupingPolicies(permission)
		addPolicies(permission)
		visited[permission.GetId()] = struct{}{}
	}

	ancestorRoles, err = GetAncestorRoles(newRoleID)
	if err != nil {
		return false, err
	}

	for _, r := range ancestorRoles {
		permissions, err := GetPermissionsByRole(r.GetId())
		if err != nil {
			return false, err
		}
		for _, permission := range permissions {
			permissionId := permission.GetId()
			if _, ok := visited[permissionId]; !ok {
				addGroupingPolicies(permission)
				visited[permissionId] = struct{}{}
			}
		}
	}

	return affected != 0, nil
}

func AddRole(role *Role) (bool, error) {
	affected, err := ormer.Engine.Insert(role)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func AddRoles(roles []*Role) bool {
	if len(roles) == 0 {
		return false
	}
	affected, err := ormer.Engine.Insert(roles)
	if err != nil {
		if !strings.Contains(err.Error(), "Duplicate entry") {
			panic(err)
		}
	}
	return affected != 0
}

func AddRolesInBatch(roles []*Role) bool {
	batchSize := conf.GetConfigBatchSize()

	if len(roles) == 0 {
		return false
	}

	affected := false
	for i := 0; i < (len(roles)-1)/batchSize+1; i++ {
		start := i * batchSize
		end := (i + 1) * batchSize
		if end > len(roles) {
			end = len(roles)
		}

		tmp := roles[start:end]
		// TODO: save to log instead of standard output
		// fmt.Printf("Add users: [%d - %d].\n", start, end)
		if AddRoles(tmp) {
			affected = true
		}
	}

	return affected
}

func DeleteRole(role *Role) (bool, error) {
	roleId := role.GetId()
	permissions, err := GetPermissionsByRole(roleId)
	if err != nil {
		return false, err
	}

	for _, permission := range permissions {
		permission.Roles = util.DeleteVal(permission.Roles, roleId)
		_, err := UpdatePermission(permission.GetId(), permission)
		if err != nil {
			return false, err
		}
	}

	affected, err := ormer.Engine.ID(core.PK{role.Owner, role.Name}).Delete(&Role{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (role *Role) GetId() string {
	return fmt.Sprintf("%s/%s", role.Owner, role.Name)
}

func GetRolesByUser(userId string) ([]*Role, error) {
	roles := []*Role{}
	err := ormer.Engine.Where("users like ?", "%"+userId+"\"%").Find(&roles)
	if err != nil {
		return roles, err
	}

	allRolesIds := make([]string, 0, len(roles))

	for _, role := range roles {
		allRolesIds = append(allRolesIds, role.GetId())
	}

	allRoles, err := GetAncestorRoles(allRolesIds...)
	if err != nil {
		return nil, err
	}

	for i := range allRoles {
		allRoles[i].Users = nil
	}

	return allRoles, nil
}

func roleChangeTrigger(oldName string, newName string) error {
	session := ormer.Engine.NewSession()
	defer session.Close()

	err := session.Begin()
	if err != nil {
		return err
	}

	var roles []*Role
	err = ormer.Engine.Find(&roles)
	if err != nil {
		return err
	}

	for _, role := range roles {
		for j, u := range role.Roles {
			owner, name := util.GetOwnerAndNameFromId(u)
			if name == oldName {
				role.Roles[j] = util.GetId(owner, newName)
			}
		}
		_, err = session.Where("name=?", role.Name).And("owner=?", role.Owner).Update(role)
		if err != nil {
			return err
		}
	}

	var permissions []*Permission
	err = ormer.Engine.Find(&permissions)
	if err != nil {
		return err
	}

	for _, permission := range permissions {
		for j, u := range permission.Roles {
			// u = organization/username
			owner, name := util.GetOwnerAndNameFromId(u)
			if name == oldName {
				permission.Roles[j] = util.GetId(owner, newName)
			}
		}
		_, err = session.Where("name=?", permission.Name).And("owner=?", permission.Owner).Update(permission)
		if err != nil {
			return err
		}
	}

	return session.Commit()
}

func GetMaskedRoles(roles []*Role) []*Role {
	for _, role := range roles {
		role.Users = nil
	}

	return roles
}

func GetRolesByNamePrefix(owner string, prefix string) ([]*Role, error) {
	roles := []*Role{}
	err := ormer.Engine.Where("owner=? and name like ?", owner, prefix+"%").Find(&roles)
	if err != nil {
		return roles, err
	}

	return roles, nil
}

// GetAncestorRoles returns a list of roles that contain the given roleIds
func GetAncestorRoles(roleIds ...string) ([]*Role, error) {
	var (
		result  = []*Role{}
		roleMap = make(map[string]*Role)
		visited = make(map[string]bool)
	)
	if len(roleIds) == 0 {
		return result, nil
	}

	for _, roleId := range roleIds {
		visited[roleId] = true
	}

	owner, _ := util.GetOwnerAndNameFromIdNoCheck(roleIds[0])

	allRoles, err := GetRoles(owner)
	if err != nil {
		return nil, err
	}

	for _, r := range allRoles {
		roleMap[r.GetId()] = r
	}

	// Second, find all the roles that contain father roles
	for _, r := range allRoles {
		isContain, ok := visited[r.GetId()]
		if isContain {
			result = append(result, r)
		} else if !ok {
			rId := r.GetId()
			visited[rId] = containsRole(r, roleMap, visited, roleIds...)
			if visited[rId] {
				result = append(result, r)
			}
		}
	}

	return result, nil
}

// containsRole is a helper function to check if a roles is related to any role in the given list roles
func containsRole(role *Role, roleMap map[string]*Role, visited map[string]bool, roleIds ...string) bool {
	roleId := role.GetId()
	if isContain, ok := visited[roleId]; ok {
		return isContain
	}

	visited[role.GetId()] = false

	for _, subRole := range role.Roles {
		if util.HasString(roleIds, subRole) {
			return true
		}

		r, ok := roleMap[subRole]
		if ok && containsRole(r, roleMap, visited, roleIds...) {
			return true
		}
	}

	return false
}
