package role_mapper

import (
	"fmt"

	"github.com/casdoor/casdoor/ldap_sync"
)

type RoleMapper interface {
	GetRoles() []string
}

func NewRoleMapper(category string, rules []*ldap_sync.RoleMappingItem, data map[string]interface{}) (RoleMapper, error) {
	switch category {
	case "OAuth":
		return NewOAuthMapper(rules, data)
	case "SAML":
		return NewSamlMapper(rules, data)
	}

	return nil, fmt.Errorf("unknown category: %s", category)
}
