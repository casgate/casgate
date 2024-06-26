package object

func HasOrganizationDependencies(orgName string) (bool, error) {
	tables := map[string]string{
		"adapter":           "owner",
		"application":       "organization",
		"cert":              "owner",
		"domain":            "owner",
		"enforcer":          "owner",
		"group":             "owner",
		"ldap":              "owner",
		"model":             "owner",
		"payment":           "owner",
		"permission":        "owner",
		"plan":              "owner",
		"pricing":           "owner",
		"product":           "owner",
		"provider":          "owner",
		"radius_accounting": "owner",
		"resource":          "owner",
		"role":              "owner",
		"subscription":      "owner",
		"syncer":            "owner",
		"token":             "owner",
		"user":              "owner",
		"webhook":           "owner",
	}

	for table, field := range tables {
		exists, err := ormer.Engine.Table(table).Where(field+" = ?", orgName).Exist()
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}

	return false, nil
}
