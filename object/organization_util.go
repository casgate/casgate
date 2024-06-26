package object

func HasOrganizationDependencies(orgName string) (bool, error) {
	tables := []string{
		"adapter", "application", "cert", "domain", "enforcer", "group", "ldap", "model",
		"payment", "permission", "plan", "pricing", "product", "provider", "radius_accounting",
		"resource", "role", "subscription", "syncer", "token", "user", "webhook",
	}

	for _, table := range tables {
		exists, err := ormer.Engine.Table(table).Where("owner = ?", orgName).Exist()
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}

	return false, nil
}
