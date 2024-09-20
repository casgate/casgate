package ldap_sync

import "strings"

type RoleMappingItem struct {
	Attribute string   `json:"attribute"`
	Values    []string `json:"values"`
	Role      string   `json:"role"`
}

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
				roleMappingMap[roleMappingAttribute][roleMappingValue] = append(
					roleMappingMap[roleMappingAttribute][roleMappingValue],
					roleMappingRole,
				)
			}

		}
	}
	return roleMappingMap
}
