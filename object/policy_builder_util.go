package object

import (
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/util"
)

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
			if util.InSlice(permission.Roles, role.id) {
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
			if util.InSlice(permission.Groups, group.id) {
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
			if util.InSlice(permission.Domains, domain.id) {
				newPermission = policyPermissionItem
			}
			newPermission.domain = domain
			policyPermissions = append(policyPermissions, newPermission)
		}
	}

	return policyPermissions
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
			if util.InSlice(role.Groups, group.id) {
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
			if util.InSlice(role.Domains, domain.id) {
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

func getOwnerEntities(owner, model string) (*Entities, error) {
	var ownerEntities Entities
	ownerDomains, err := GetDomains(owner)
	if err != nil {
		return nil, fmt.Errorf("GetDomains: %w", err)
	}
	ownerRoles, err := GetRoles(owner)
	if err != nil {
		return nil, fmt.Errorf("GetRoles: %w", err)
	}
	ownerGroups, err := GetGroups(owner)
	if err != nil {
		return nil, fmt.Errorf("GetGroups: %w", err)
	}
	ownerUsers, err := GetUsers(owner)
	if err != nil {
		return nil, fmt.Errorf("GetUsers: %w", err)
	}
	permissionModel, err := getModel(owner, model)
	if err != nil {
		return nil, fmt.Errorf("getModel: %w", err)
	}
	ownerEntities.DomainsTree = makeAncestorDomainsTreeMap(ownerDomains)
	ownerEntities.RolesTree = makeAncestorRolesTreeMap(ownerRoles)
	ownerEntities.GroupsTree = makeAncestorGroupsTreeMap(ownerGroups)
	ownerEntities.UsersByGroup = groupUsersByGroups(ownerUsers)
	ownerEntities.Model = permissionModel

	return &ownerEntities, nil
}

func getValueByItem(policyPermissionItem policyPermission, policyItem string) (string, bool) {
	if policyItem == "" {
		return policyItem, true
	}

	if policyItem[:5] == "const" {
		return policyItem[6:], true
	}

	var value string

	switch policyItem {
	case "role.name":
		value = policyPermissionItem.role.name
	case "role.subrole":
		value = policyPermissionItem.role.subRole
	case "role.domain.name":
		value = policyPermissionItem.role.domain.name
	case "role.domain.subdomain":
		value = policyPermissionItem.role.domain.subDomain
	case "role.user":
		value = policyPermissionItem.role.user
	case "role.group.name":
		value = policyPermissionItem.role.group.name
	case "role.group.parentgroup":
		value = policyPermissionItem.role.group.parentGroup
	case "role.group.user":
		value = policyPermissionItem.role.group.user
	case "permission.action":
		value = policyPermissionItem.action
	case "permission.resource":
		value = policyPermissionItem.resource
	case "permission.user":
		value = policyPermissionItem.user
	case "permission.effect":
		value = policyPermissionItem.effect
	case "permission.domain.name":
		value = policyPermissionItem.domain.name
	case "permission.domain.subdomain":
		value = policyPermissionItem.domain.subDomain
	case "permission.group.name":
		value = policyPermissionItem.group.name
	case "permission.group.parentgroup":
		value = policyPermissionItem.group.parentGroup
	case "permission.group.user":
		value = policyPermissionItem.group.user
	}

	if value == "" {
		return value, false
	}

	return value, true
}

func getPolicyMappingRules(model *Model, permission *Permission) [][]string {
	if model.CustomPolicyMapping {
		return model.CustomPolicyMappingRules
	}

	if len(permission.Domains) > 0 {
		return defaultPolicyDomainMappingRules
	}

	return defaultPolicyMappingRules
}

func multiplyLenEntities(sizes ...int) int {
	result := 1
	for _, size := range sizes {
		result = result * (size + 1)
	}
	return result + 1
}
