package role_mapper

import (
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/ldap_sync"
)

type OAuthMapper struct {
	rules []*ldap_sync.RoleMappingItem
	data  map[string]interface{}
}

func NewOAuthMapper(rules []*ldap_sync.RoleMappingItem, data map[string]interface{}) (*OAuthMapper, error) {
	return &OAuthMapper{
		rules: rules,
		data:  data,
	}, nil
}

func (m *OAuthMapper) GetRoles() []string {
	roles := make([]string, 0)
	for _, rule := range m.rules {
		values := getValues(m.data, strings.Split(rule.Attribute, "."))
		if values == nil {
			continue
		}

	CheckRuleLoop:
		for _, valueItem := range values {
			for _, ruleValue := range rule.Values {
				if valueItem == ruleValue {
					roles = append(roles, rule.Role)
					break CheckRuleLoop
				}
			}
		}

	}

	return roles
}

func getValues(data map[string]interface{}, attributeLevels []string) []string {
	if len(attributeLevels) == 0 {
		return nil
	}

	currentLevel := attributeLevels[0]
	value := data[currentLevel]

	switch v := value.(type) {
	case map[string]interface{}:
		return getValues(v, attributeLevels[1:])
	case []string:
		return v
	case []interface{}:
		s := make([]string, len(v))
		for i, v := range v {
			s[i] = fmt.Sprint(v)
		}
		return s
	default:
		if len(attributeLevels) == 1 {
			return []string{fmt.Sprint(v)}
		}
	}

	return nil
}
