package role_mapper

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
)

type SamlMapper struct {
	rules []*object.RoleMappingItem
	data  map[string]string
}

func NewSamlMapper(rules []*object.RoleMappingItem, data map[string]interface{}) (*SamlMapper, error) {
	strData := make(map[string]string, len(data))
	for k, v := range data {
		value, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("wrong value type (not string) for saml mapper: %v", v)
		}
		strData[k] = value
	}

	return &SamlMapper{
		rules: rules,
		data:  strData,
	}, nil
}

func (m *SamlMapper) GetRoles() []string {
	roles := make([]string, 0)
	for _, rule := range m.rules {
		value := m.data[rule.Attribute]
		if value == "" {
			continue
		}
		for _, ruleValue := range rule.Values {
			if value == ruleValue {
				roles = append(roles, rule.Role)
			}
		}
	}

	return roles
}
