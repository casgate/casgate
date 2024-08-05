package object

import "github.com/casdoor/casdoor/orm"

func HasOrganizationDependencies(orgName string) (bool, error) {
	tables := map[string]string{
		"adapter":     "owner",
		"application": "organization",
		"cert":        "owner",
		"domain":      "owner",
		"enforcer":    "owner",
		"group":       "owner",
		"ldap":        "owner",
		"model":       "owner",
		"permission":  "owner",
		"provider":    "owner",
		"role":        "owner",
		"syncer":      "organization",
		"token":       "organization",
		"user":        "owner",
		"webhook":     "organization",
	}

	for table, field := range tables {
		exists, err := orm.AppOrmer.Engine.Table(table).Where(field+" = ?", orgName).Exist()
		if err != nil {
			return false, err
		}
		if exists {
			return true, nil
		}
	}

	return false, nil
}
