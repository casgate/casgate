package role_mapper

import (
	"slices"

	"github.com/casdoor/casdoor/ldap_sync"
)

type SamlMapper struct {
	rules []*ldap_sync.RoleMappingItem
	data  map[string]interface{}
}

func NewSamlMapper(rules []*ldap_sync.RoleMappingItem, data map[string]interface{}) (*SamlMapper, error) {
	strData := make(map[string]interface{}, len(data))
	for k, v := range data {
		strData[k] = v
	}

	return &SamlMapper{
		rules: rules,
		data:  strData,
	}, nil
}

func (m *SamlMapper) GetRoles() []string {
	roles := make([]string, 0)

	for _, rule := range m.rules {
		if idpRoles, ok := m.data[rule.Attribute].([]string); ok {
			for _, idpRole := range idpRoles {
				if slices.Contains(rule.Values, idpRole) {
					roles = append(roles, rule.Role)
				}
			}
		}
	}

	return roles
}
