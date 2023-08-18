package object

import (
	"fmt"
	"strings"
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

func spawnPolicyPermissions(permission Permission) []policyPermission {
	policyPermissions := make([]policyPermission, 0, 1)
	policyPermissions = append(policyPermissions, policyPermission{
		name:   permission.GetId(),
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

func spawnPolicyRoles(role *Role) []policyRole {
	policyRoles := make([]policyRole, 0)
	policyRoles = append(policyRoles, policyRole{
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

func getPolicyPermissions(permission *Permission) ([][]string, map[string]*Permission, error) {
	permissionMap := make(map[string]*Permission, 1)
	policyPermissions := spawnPolicyPermissions(*permission)
	permissionMap[permission.GetId()] = permission

	policyRoles := make([]policyRole, 0)
	for _, roleID := range permission.Roles {
		role, err := GetRole(roleID)
		if err != nil {
			return nil, nil, fmt.Errorf("GetRole: %w", err)
		}

		newPolicyRoles := spawnPolicyRoles(role)
		policyRoles = append(policyRoles, newPolicyRoles...)
	}

	policyPermissions = joinPolicyPermissionsWithRoles(policyPermissions, policyRoles)

	strPolicies, err := generatePolicies(policyPermissions, permissionMap)
	if err != nil {
		return nil, nil, fmt.Errorf("generatePolicies: %w", err)
	}

	return strPolicies, permissionMap, nil
}

func joinPolicyPermissionsWithRoles(permissions []policyPermission, roles []policyRole) []policyPermission {
	for _, permission := range permissions {
		for _, role := range roles {
			newPermission := permission
			newPermission.role = role
			permissions = append(permissions, newPermission)
		}
	}
	return permissions
}

func getPolicyPermissionsByRole(role *Role) ([][]string, map[string]*Permission, error) {
	policyRoles := spawnPolicyRoles(role)

	permissions, err := GetPermissionsByRole(role.GetId())
	if err != nil {
		return nil, nil, err
	}

	policyPermissions := make([]policyPermission, 0, len(permissions))
	permissionMap := make(map[string]*Permission, len(permissions))

	if len(permissions) == 0 {
		permissions, err = subRolePermissions(role)
		if err != nil {
			return nil, nil, fmt.Errorf("subRolePermissions: %w", err)
		}
	}

	for _, permission := range permissions {
		for _, policyRoleItem := range policyRoles {
			newPolicyPermissions := make([]policyPermission, 0)
			newPolicyPermissions = append(newPolicyPermissions, policyPermission{
				name: permission.GetId(),
			})
			if Contains(permission.Roles, policyRoleItem.name) {
				newPolicyPermissions = spawnPolicyPermissions(*permission)
			}
			newPolicyPermissions = joinPolicyPermissionsWithRoles(newPolicyPermissions, []policyRole{policyRoleItem})
			permissionMap[permission.GetId()] = permission

			policyPermissions = append(policyPermissions, newPolicyPermissions...)
		}
	}

	strPolicies, err := generatePolicies(policyPermissions, permissionMap)
	if err != nil {
		return nil, nil, fmt.Errorf("generatePolicies: %w", err)
	}

	return strPolicies, permissionMap, nil
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
