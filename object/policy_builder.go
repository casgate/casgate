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
	policyPermissions := make([]policyPermission, 0, multiplyLenEntities(len(permission.Resources), len(permission.Users), len(permission.Actions)))
	policyPermissions = append(policyPermissions, policyPermission{
		id:     permission.GetId(),
		effect: permission.Effect,
	})

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

func calcRolePolicies(role *Role, entities Entities) ([]policyRole, error) {
	roleGroups, err := getAncestorGroups(entities.GroupsTree, role.Groups...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorGroups: %w", err)
	}

	policyGroups := make([]policyGroup, 0, len(roleGroups))
	for _, group := range roleGroups {
		newPolicyGroups, err := calcGroupPolicies(entities.UsersByGroup[group.GetId()], group)
		if err != nil {
			return nil, fmt.Errorf("calcRolePolicies: %w", err)
		}
		policyGroups = append(policyGroups, newPolicyGroups...)
	}

	roleDomains, err := getAncestorDomains(entities.DomainsTree, role.Domains...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorDomains: %w", err)
	}

	policyDomains := make([]policyDomain, 0, len(roleDomains))
	for _, domain := range roleDomains {
		policyDomains = append(policyDomains, policyDomain{
			id:   domain.GetId(),
			name: domain.GetId(),
		})
		for _, subdomainId := range domain.Domains {
			policyDomains = append(policyDomains, policyDomain{
				id:        domain.GetId(),
				name:      domain.GetId(),
				subDomain: subdomainId,
			})
		}
	}

	policyRoles := joinEntitiesWithRole(role, policyGroups, policyDomains)

	return policyRoles, nil
}

func joinEntitiesWithRole(role *Role, groups []policyGroup, domains []policyDomain) []policyRole {
	spawnedPolicyRoles := spawnPolicyRoles(role)
	policyRoles := make([]policyRole, 0, multiplyLenEntities(len(spawnedPolicyRoles), len(groups), len(domains)))
	policyRoles = append(policyRoles, spawnedPolicyRoles...)

	for _, policyPermissionItem := range policyRoles {
		for _, group := range groups {
			newRole := policyRole{
				id:    policyPermissionItem.id,
				empty: true,
			}
			if Contains(role.Groups, group.id) {
				newRole = policyPermissionItem
			}
			newRole.group = group
			policyRoles = append(policyRoles, newRole)
		}
	}

	for _, policyPermissionItem := range policyRoles {
		if policyPermissionItem.empty {
			continue
		}

		for _, domain := range domains {
			newRole := policyRole{
				id:    policyPermissionItem.id,
				empty: true,
			}
			if Contains(role.Domains, domain.id) {
				newRole = policyPermissionItem
			}
			newRole.domain = domain
			policyRoles = append(policyRoles, newRole)
		}
	}

	return policyRoles
}

func spawnPolicyRoles(role *Role) []policyRole {
	policyRoles := make([]policyRole, 0, multiplyLenEntities(len(role.Users), len(role.Roles)))
	policyRoles = append(policyRoles, policyRole{
		id:   role.GetId(),
		name: role.GetId(),
	})

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

	permissionIds := make([]string, 0, len(permissions))
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

func calcPermissionPolicies(permission *Permission, entities Entities) ([][]string, error) {
	permissionRoles, err := getAncestorRoles(entities.RolesTree, permission.Roles...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorRoles: %w", err)
	}

	policyRoles := make([]policyRole, 0, len(permissionRoles))
	for _, role := range permissionRoles {
		newPolicyRoles, err := calcRolePolicies(role, entities)
		if err != nil {
			return nil, fmt.Errorf("calcRolePolicies: %w", err)
		}
		policyRoles = append(policyRoles, newPolicyRoles...)
	}

	permissionGroups, err := getAncestorGroups(entities.GroupsTree, permission.Groups...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorGroups: %w", err)
	}

	policyGroups := make([]policyGroup, 0, len(permissionGroups))
	for _, group := range permissionGroups {
		newPolicyGroups, err := calcGroupPolicies(entities.UsersByGroup[group.GetId()], group)
		if err != nil {
			return nil, fmt.Errorf("calcRolePolicies: %w", err)
		}
		policyGroups = append(policyGroups, newPolicyGroups...)
	}

	permissionDomains, err := getAncestorDomains(entities.DomainsTree, permission.Domains...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorDomains: %w", err)
	}

	policyDomains := make([]policyDomain, 0, len(permissionDomains))
	for _, domain := range permissionDomains {
		policyDomains = append(policyDomains, policyDomain{
			id:   domain.GetId(),
			name: domain.GetId(),
		})
		for _, subdomainId := range domain.Domains {
			policyDomains = append(policyDomains, policyDomain{
				id:        domain.GetId(),
				name:      domain.GetId(),
				subDomain: subdomainId,
			})
		}
	}

	policyPermissions := joinEntitiesWithPermission(permission, policyRoles, policyGroups, policyDomains)

	strPolicies, err := generatePolicies(policyPermissions, permission, entities.Model)
	if err != nil {
		return nil, fmt.Errorf("generatePolicies: %w", err)
	}

	return strPolicies, nil
}

func joinEntitiesWithPermission(permission *Permission, roles []policyRole, groups []policyGroup, domains []policyDomain) []policyPermission {
	spawnedPolicyPermissions := spawnPolicyPermissions(permission)
	policyPermissions := make([]policyPermission, 0, multiplyLenEntities(len(spawnedPolicyPermissions), len(roles), len(groups), len(domains)))
	policyPermissions = append(policyPermissions, spawnedPolicyPermissions...)
	for _, policyPermissionItem := range policyPermissions {
		for _, role := range roles {
			newPermission := policyPermission{
				id:    policyPermissionItem.id,
				empty: true,
			}
			if Contains(permission.Roles, role.id) {
				newPermission = policyPermissionItem
			}
			newPermission.role = role
			policyPermissions = append(policyPermissions, newPermission)
		}
	}

	for _, policyPermissionItem := range policyPermissions {
		if policyPermissionItem.empty {
			continue
		}

		for _, group := range groups {
			newPermission := policyPermission{
				id:    policyPermissionItem.id,
				empty: true,
			}
			if Contains(permission.Groups, group.id) {
				newPermission = policyPermissionItem
			}
			newPermission.group = group
			policyPermissions = append(policyPermissions, newPermission)
		}
	}

	for _, policyPermissionItem := range policyPermissions {
		if policyPermissionItem.empty {
			continue
		}

		for _, domain := range domains {
			newPermission := policyPermission{
				id:    policyPermissionItem.id,
				empty: true,
			}
			if Contains(permission.Domains, domain.id) {
				newPermission = policyPermissionItem
			}
			newPermission.domain = domain
			policyPermissions = append(policyPermissions, newPermission)
		}
	}

	return policyPermissions
}

func calcGroupPolicies(users []*User, group *Group) ([]policyGroup, error) {
	policyGroups := make([]policyGroup, 1)

	var parentId string
	if group.Owner != group.ParentId {
		parentId = util.GetId(group.Owner, group.ParentId)
	}
	policyGroups = append(policyGroups, policyGroup{
		id:          group.GetId(),
		name:        group.GetId(),
		parentGroup: parentId,
	})

	for _, user := range users {
		policyGroups = append(policyGroups, policyGroup{
			id:          group.GetId(),
			name:        group.GetId(),
			parentGroup: parentId,
			user:        user.GetId(),
		})
	}

	return policyGroups, nil
}

func multiplyLenEntities(sizes ...int) int {
	result := 1
	for _, size := range sizes {
		result = result * (size + 1)
	}
	return result + 1
}
