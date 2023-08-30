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
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/util"
)

var defaultPolicyMappingRules = [][]string{
	{"p", "permission.user", "permission.resource", "permission.action", "permission.effect"},
	{"p", "role.name", "permission.resource", "permission.action", "permission.effect"},
	{"g", "role.subrole", "role.name"},
	{"g", "role.user", "role.name"},
}

var defaultPolicyDomainMappingRules = [][]string{
	{"p", "permission.user", "permission.domain", "permission.resource", "permission.action", "permission.effect"},
	{"p", "role.name", "permission.domain", "permission.resource", "permission.action", "permission.effect"},
	{"g", "role.subrole", "role.name", "permission.domain"},
	{"g", "role.user", "role.name", "permission.domain"},
}

func spawnPolicyPermissions(permission *Permission) []policyPermission {
	policyPermissions := make([]policyPermission, 0, 1)
	policyPermissions = append(policyPermissions, policyPermission{
		id:     permission.GetId(),
		effect: permission.Effect,
	})

	if len(permission.Domains) > 0 {
		policyPermissions = spawnPolicyPermissionsByField(policyPermissions, "domain", permission.Domains)
	}
	if len(permission.Resources) > 0 {
		policyPermissions = spawnPolicyPermissionsByField(policyPermissions, "resource", permission.Resources)
	}
	if len(permission.Users) > 0 {
		policyPermissions = spawnPolicyPermissionsByField(policyPermissions, "user", permission.Users)
	}
	if len(permission.Actions) > 0 {
		policyPermissions = spawnPolicyPermissionsByField(policyPermissions, "action", permission.Actions)
	}
	return policyPermissions
}

func spawnPolicyPermissionsByField(permissions []policyPermission, field string, values []string) []policyPermission {
	policyPermissions := make([]policyPermission, 0, len(values)*len(permissions))
	for _, value := range values {
		for _, permission := range permissions {
			newPolicyPermission := permission
			switch field {
			case "domain":
				newPolicyPermission.domain = value
			case "user":
				newPolicyPermission.user = value
			case "resource":
				newPolicyPermission.resource = value
			case "action":
				newPolicyPermission.action = strings.ToLower(value)
			}
			policyPermissions = append(policyPermissions, newPolicyPermission)
		}
	}
	return policyPermissions
}

func calcRolePolicies(role *Role) ([]policyRole, error) {
	roleGroups, err := GetAncestorGroups(role.Groups...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorGroups: %w", err)
	}

	policyGroups := make([]policyGroup, 0, len(roleGroups))
	for _, group := range roleGroups {
		var parentId string
		if group.Owner != group.ParentId {
			parentId = util.GetId(group.Owner, group.ParentId)
		}
		policyGroups = append(policyGroups, policyGroup{
			id:          group.GetId(),
			name:        group.GetId(),
			parentGroup: parentId,
		})
	}

	policyRoles := joinEntitiesWithRole(role, policyGroups)

	return policyRoles, nil
}

func joinEntitiesWithRole(role *Role, groups []policyGroup) []policyRole {
	policyRoles := spawnPolicyRoles(role)

	for _, policyPermissionItem := range policyRoles {
		for _, group := range groups {
			newRole := policyRole{
				id: role.GetId(),
			}
			if Contains(role.Groups, group.id) {
				newRole = policyPermissionItem
			}
			newRole.group = group
			policyRoles = append(policyRoles, newRole)
		}
	}

	return policyRoles
}

func spawnPolicyRoles(role *Role) []policyRole {
	policyRoles := make([]policyRole, 0)
	policyRoles = append(policyRoles, policyRole{
		id:   role.GetId(),
		name: role.GetId(),
	})

	if len(role.Domains) > 0 {
		policyRoles = spawnPolicyRoleByField(policyRoles, "domain", role.Domains)
	}
	if len(role.Users) > 0 {
		policyRoles = spawnPolicyRoleByField(policyRoles, "user", role.Users)
	}
	if len(role.Roles) > 0 {
		policyRoles = spawnPolicyRoleByField(policyRoles, "subrole", role.Roles)
	}
	return policyRoles
}

func spawnPolicyRoleByField(roles []policyRole, field string, values []string) []policyRole {
	policyRoles := make([]policyRole, 0, len(values))
	for _, value := range values {
		for _, role := range roles {
			newPolicyRole := role
			switch field {
			case "domain":
				newPolicyRole.domain = value
			case "user":
				newPolicyRole.user = value
			case "subrole":
				newPolicyRole.subRole = value
			}
			policyRoles = append(policyRoles, newPolicyRole)
		}
	}
	return policyRoles
}

// getPermissionPolicies get policies from db by permissions with same model
func getPermissionPolicies(permissions []*Permission) ([][]string, error) {
	if len(permissions) == 0 {
		return nil, nil
	}

	permissionIds := make([]string, len(permissions))
	for _, permission := range permissions {
		permissionIds = append(permissionIds, permission.GetId())
	}
	enforcer := getPermissionEnforcer(permissions[0], permissionIds...)
	enforcer.GetPolicy()

	result := make([][]string, 0)
	for _, policy := range enforcer.GetNamedPolicy("p") {
		result = append(result, append([]string{"p"}, policy...))
	}

	model := enforcer.GetModel()
	for gType := range model["g"] {
		for _, policy := range enforcer.GetNamedGroupingPolicy(gType) {
			result = append(result, append([]string{gType}, policy...))
		}
	}

	return result, nil
}

func calcPermissionPolicies(permission *Permission) ([][]string, error) {
	policyRoles := make([]policyRole, 0)

	permissionRoles, err := GetAncestorRoles(permission.Roles...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorRoles: %w", err)
	}

	for _, role := range permissionRoles {
		newPolicyRoles, err := calcRolePolicies(role)
		if err != nil {
			return nil, fmt.Errorf("calcRolePolicies: %w", err)
		}
		policyRoles = append(policyRoles, newPolicyRoles...)
	}

	permissionGroups, err := GetAncestorGroups(permission.Groups...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorGroups: %w", err)
	}

	policyGroups := make([]policyGroup, 0, len(permissionGroups))
	for _, group := range permissionGroups {
		var parentId string
		if group.Owner != group.ParentId {
			parentId = util.GetId(group.Owner, group.ParentId)
		}
		policyGroups = append(policyGroups, policyGroup{
			id:          group.GetId(),
			name:        group.GetId(),
			parentGroup: parentId,
		})
	}

	policyPermissions := joinEntitiesWithPermission(permission, policyRoles, policyGroups)

	strPolicies, err := generatePolicies(policyPermissions, permission)
	if err != nil {
		return nil, fmt.Errorf("generatePolicies: %w", err)
	}

	return strPolicies, nil
}

func joinEntitiesWithPermission(permission *Permission, roles []policyRole, groups []policyGroup) []policyPermission {
	policyPermissions := spawnPolicyPermissions(permission)
	for _, policyPermissionItem := range policyPermissions {
		for _, role := range roles {
			newPermission := policyPermission{
				id: permission.GetId(),
			}
			if Contains(permission.Roles, role.id) {
				newPermission = policyPermissionItem
			}
			newPermission.role = role
			policyPermissions = append(policyPermissions, newPermission)
		}
	}
	for _, policyPermissionItem := range policyPermissions {
		for _, group := range groups {
			newPermission := policyPermission{
				id: permission.GetId(),
			}
			if Contains(permission.Groups, group.id) {
				newPermission = policyPermissionItem
			}
			newPermission.group = group
			policyPermissions = append(policyPermissions, newPermission)
		}
	}

	return policyPermissions
}

func subRolePermissions(role *Role) ([]*Permission, error) {
	result := make([]*Permission, 0)

	visited := map[string]struct{}{}
	subRoles, err := getRolesInRole(role.GetId(), visited)
	if err != nil {
		return nil, fmt.Errorf("getRolesInRole: %w", err)
	}

	for _, subRole := range subRoles {
		permissions, err := GetPermissionsByRole(subRole.GetId())
		if err != nil {
			return nil, fmt.Errorf("GetPermissionsByRole: %w", err)
		}
		if len(permissions) > 0 {
			result = append(result, permissions...)
		}
	}

	return result, nil
}

func subGroupPermissions(group *Group) ([]*Permission, error) {
	result := make([]*Permission, 0)

	subGroups, err := getGroupsInGroup(group.GetId())
	if err != nil {
		return nil, fmt.Errorf("getGroupsInGroup: %w", err)
	}
	for _, subGroup := range subGroups {
		permissions, err := GetPermissionsByGroup(subGroup.GetId())
		if err != nil {
			return nil, fmt.Errorf("GetPermissionsByGroup: %w", err)
		}
		if len(permissions) > 0 {
			result = append(result, permissions...)
		}

		groupRoles, err := GetPaginationRoles(group.Owner, -1, -1, "groups", group.GetId(), "", "")
		if err != nil {
			return nil, fmt.Errorf("GetPaginationRoles: %w", err)
		}

		for _, role := range groupRoles {
			rolePermissions, err := subRolePermissions(role)
			if err != nil {
				return nil, fmt.Errorf("subRolePermissions: %w", err)
			}
			if len(rolePermissions) > 0 {
				result = append(result, rolePermissions...)
			}
		}

	}

	return result, nil
}
