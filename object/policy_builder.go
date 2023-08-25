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

	roleIds := make([]string, 0, len(permission.Roles))
	for _, roleID := range permission.Roles {
		roleIds = append(roleIds, roleID)
	}
	permissionRoles, err := GetAncestorRoles(roleIds...)
	if err != nil {
		return nil, fmt.Errorf("GetAncestorRoles: %w", err)
	}

	for _, role := range permissionRoles {
		newPolicyRoles := spawnPolicyRoles(role)
		policyRoles = append(policyRoles, newPolicyRoles...)
	}

	policyPermissions := joinEntitiesWithPermission(permission, policyRoles)

	strPolicies, err := generatePolicies(policyPermissions, permission)
	if err != nil {
		return nil, fmt.Errorf("generatePolicies: %w", err)
	}

	return strPolicies, nil
}

func joinEntitiesWithPermission(permission *Permission, roles []policyRole) []policyPermission {
	policyPermissions := spawnPolicyPermissions(*permission)
	for _, policyPermissionItem := range policyPermissions {
		for _, role := range roles {
			newPermission := policyPermission{
				name: permission.GetId(),
			}
			if Contains(permission.Roles, role.name) {
				newPermission = policyPermissionItem
			}
			newPermission.role = role
			policyPermissions = append(policyPermissions, newPermission)
		}
	}

	return policyPermissions
}

func subRolePermissions(role *Role) ([]*Permission, error) {
	result := make([]*Permission, 0)

	rolePermissions, err := GetPermissionsByRole(role.GetId())
	if err != nil {
		return nil, err
	}
	result = append(result, rolePermissions...)

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
