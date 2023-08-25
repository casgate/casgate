package object

import (
	"fmt"

	"github.com/casdoor/casdoor/util"
)

type policyRole struct {
	name    string
	domain  string
	user    string
	subRole string
}

type policyPermission struct {
	name     string
	domain   string
	resource string
	action   string
	role     policyRole
	user     string
	effect   string
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
	case "role.domain":
		value = policyPermissionItem.role.domain
	case "role.user":
		value = policyPermissionItem.role.user
	case "permission.action":
		value = policyPermissionItem.action
	case "permission.resource":
		value = policyPermissionItem.resource
	case "permission.user":
		value = policyPermissionItem.user
	case "permission.effect":
		value = policyPermissionItem.effect
	case "permission.domain":
		value = policyPermissionItem.domain
	}

	if value == "" {
		return value, false
	}

	return value, true
}

func refillWithEmptyStrings(row []string) []string {
	for len(row) < 7 {
		row = append(row, "")
	}
	return row
}

func generatePolicies(policyPermissions []policyPermission, permissionsMap map[string]*Permission) ([][]string, error) {
	policies := make([][]string, 0)

	permissionModels := make(map[string]*Model)
	for _, policyPermissionItem := range policyPermissions {
		permission := permissionsMap[policyPermissionItem.name]
		modelID := util.GetId(permission.Owner, permission.Model)
		if _, ok := permissionModels[modelID]; !ok {
			permissionModel, err := getModel(permission.Owner, permission.Model)
			if err != nil {
				return nil, fmt.Errorf("getModel: %w", err)
			}
			permissionModels[modelID] = permissionModel
		}
		permissionModel := permissionModels[modelID]
		policyRules := permissionModel.policyMappingRules(len(permission.Domains) > 0)
	PolicyLoop:
		for _, policyRule := range policyRules {
			policyType := policyRule[0]
			policyRow := make([]string, 0, len(policyRule)-1)
			policyRow = append(policyRow, policyType)
			for _, policyItem := range policyRule[1:] {
				policyRowItem, found := getValueByItem(policyPermissionItem, policyItem)
				if !found {
					continue PolicyLoop
				}
				policyRow = append(policyRow, policyRowItem)
			}
			policyRow = refillWithEmptyStrings(policyRow)
			policyRow[6] = policyPermissionItem.name

			policies = append(policies, policyRow)
		}
	}

	return policies, nil
}

type groupedPolicy struct {
	g [][]string
	p [][]string
}

func groupPolicies(policies [][]string) (map[string]groupedPolicy, error) {
	groupedPolicies := make(map[string]groupedPolicy, len(policies))
	for _, policy := range policies {
		if _, ok := groupedPolicies[policy[6]]; !ok {
			groupedPolicies[policy[6]] = groupedPolicy{g: make([][]string, 0), p: make([][]string, 0)}
		}
		switch policy[0][0] {
		case 'p':
			temp := groupedPolicies[policy[6]]
			temp.p = append(groupedPolicies[policy[6]].p, policy)
			groupedPolicies[policy[6]] = temp
		case 'g':
			temp := groupedPolicies[policy[6]]
			temp.g = append(groupedPolicies[policy[6]].g, policy)
			groupedPolicies[policy[6]] = temp
		default:
			return nil, fmt.Errorf("wrong policy type")
		}
	}
	return groupedPolicies, nil
}

func createPolicy(policies [][]string, permissionMap map[string]*Permission, withSave bool) error {
	groupedPolicies, err := groupPolicies(policies)
	if err != nil {
		return fmt.Errorf("groupPolicies: %w", err)
	}

	created := make(map[string]bool, len(policies))

	for permissionID, groupedPolicy := range groupedPolicies {

		enforcer := getPermissionEnforcer(permissionMap[permissionID])
		enforcer.EnableAutoSave(withSave)
		for _, policy := range groupedPolicy.p {
			key := fmt.Sprintf("%s_%s_%s_%s_%s_%s", policy[0], policy[1], policy[2], policy[3], policy[4], policy[5])
			if !created[key] {
				enforcer.AddNamedPolicy(policy[0], policy[1:])
				created[key] = true
			}
		}

		for _, policy := range groupedPolicy.g {
			key := fmt.Sprintf("%s_%s_%s_%s_%s_%s", policy[0], policy[1], policy[2], policy[3], policy[4], policy[5])
			if !created[key] {
				enforcer.AddNamedGroupingPolicy(policy[0], policy[1:])
				created[key] = true
			}
		}
	}

	return nil
}

func removePolicy(policies [][]string, permissionMap map[string]*Permission) error {
	groupedPolicies, err := groupPolicies(policies)
	if err != nil {
		return fmt.Errorf("groupPolicies: %w", err)
	}

	for permissionID, groupedPolicy := range groupedPolicies {
		enforcer := getPermissionEnforcer(permissionMap[permissionID])

		for _, policy := range groupedPolicy.p {
			if _, ok := enforcer.GetModel()["p"][policy[0]]; ok {
				enforcer.RemoveNamedPolicy(policy[0], policy[1:])
			}
		}

		for _, policy := range groupedPolicy.g {
			if _, ok := enforcer.GetModel()["g"][policy[0]]; ok {
				enforcer.RemoveNamedGroupingPolicy(policy[0], policy[1:])
			}
		}
	}

	return nil
}

func Contains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}
