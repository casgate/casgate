package object

import (
	"fmt"
	"strings"
)

func HasOrganizationDependencies(orgName string) (bool, error) {
	tables := []string{
		"adapter", "application", "cert", "domain", "enforcer", "group", "ldap", "model",
		"payment", "permission", "plan", "pricing", "product", "provider", "radius_accounting",
		"resource", "role", "subscription", "syncer", "token", "user", "webhook",
	}

	var queryParts []string
	for _, table := range tables {
		queryParts = append(queryParts, fmt.Sprintf("SELECT 1 FROM \"%s\" WHERE owner = $1", table))
	}
	generalQuery := fmt.Sprintf("SELECT EXISTS (%s)", strings.Join(queryParts, " UNION ALL "))

	var exists bool
	if _, err := ormer.Engine.SQL(generalQuery, orgName).Get(&exists); err != nil {
		return false, fmt.Errorf("error executing query: %w", err)
	}

	return exists, nil
}

