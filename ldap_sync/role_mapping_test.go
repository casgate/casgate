package ldap_sync

import (
	"testing"
)

func TestRoleMappingItemRolesStrRoles(t *testing.T) {
	tests := []struct {
		name           string
		roles          RoleMappingItemRoles
		expectedResult []string
	}{
		{
			name:           "Multiple roles",
			roles:          RoleMappingItemRoles{"admin", "user"},
			expectedResult: []string{"admin", "user"},
		},
		{
			name:           "Single role",
			roles:          RoleMappingItemRoles{"manager"},
			expectedResult: []string{"manager"},
		},
		{
			name:           "No roles",
			roles:          RoleMappingItemRoles{},
			expectedResult: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result := tt.roles.StrRoles()
				if len(result) != len(tt.expectedResult) {
					t.Errorf("expected %v, got %v", tt.expectedResult, result)
				}

				for i, role := range result {
					if role != tt.expectedResult[i] {
						t.Errorf("expected role %v, got %v", tt.expectedResult[i], role)
					}
				}
			},
		)
	}
}

func TestRoleMappingItemRolesContains(t *testing.T) {
	tests := []struct {
		name           string
		roles          RoleMappingItemRoles
		item           RoleMappingItemRoleId
		expectedResult bool
	}{
		{
			name:           "Role exists",
			roles:          RoleMappingItemRoles{"admin", "user"},
			item:           "admin",
			expectedResult: true,
		},
		{
			name:           "Role does not exist",
			roles:          RoleMappingItemRoles{"admin", "user"},
			item:           "manager",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result := tt.roles.Contains(tt.item)
				if result != tt.expectedResult {
					t.Errorf("expected %v, got %v", tt.expectedResult, result)
				}
			},
		)
	}
}

func TestBuildRoleMappingMap(t *testing.T) {
	tests := []struct {
		name                    string
		roleMappingItems        []*RoleMappingItem
		enableCaseInsensitivity bool
		expectedMap             RoleMappingMap
	}{
		{
			name: "Basic mapping without case insensitivity",
			roleMappingItems: []*RoleMappingItem{
				{
					Attribute: "department",
					Values:    []string{"Engineering", "DevOps"},
					Role:      "admin",
				},
				{
					Attribute: "department",
					Values:    []string{"HR"},
					Role:      "manager",
				},
			},
			enableCaseInsensitivity: false,
			expectedMap: RoleMappingMap{
				"department": {
					"Engineering": {"admin"},
					"DevOps":      {"admin"},
					"HR":          {"manager"},
				},
			},
		},
		{
			name: "Mapping with case insensitivity",
			roleMappingItems: []*RoleMappingItem{
				{
					Attribute: "DEPARTMENT",
					Values:    []string{"engineering", "DEVOPS"},
					Role:      "admin",
				},
				{
					Attribute: "department",
					Values:    []string{"hr"},
					Role:      "manager",
				},
			},
			enableCaseInsensitivity: true,
			expectedMap: RoleMappingMap{
				"department": {
					"engineering": {"admin"},
					"devops":      {"admin"},
					"hr":          {"manager"},
				},
			},
		},
		{
			name: "Empty role ignored",
			roleMappingItems: []*RoleMappingItem{
				{
					Attribute: "department",
					Values:    []string{"Engineering"},
					Role:      "",
				},
			},
			enableCaseInsensitivity: false,
			expectedMap:             RoleMappingMap{},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result := buildRoleMappingMap(tt.roleMappingItems, tt.enableCaseInsensitivity)
				if len(result) != len(tt.expectedMap) {
					t.Errorf("expected map length %d, got %d", len(tt.expectedMap), len(result))
				}

				for key, val := range tt.expectedMap {
					if len(result[key]) != len(val) {
						t.Errorf("expected %v, got %v for key %v", val, result[key], key)
					}
					for innerKey, innerVal := range val {
						if len(result[key][innerKey]) != len(innerVal) {
							t.Errorf(
								"expected %v, got %v for key %v and innerKey %v",
								innerVal,
								result[key][innerKey],
								key,
								innerKey,
							)
						}
					}
				}
			},
		)
	}
}
