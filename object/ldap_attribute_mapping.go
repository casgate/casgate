package object

import (
	"github.com/casdoor/casdoor/util"
	goldap "github.com/go-ldap/ldap/v3"
)

type (
	AttributeMappingAttribute  string
	AttributeMappingUserField  string
	AttributeMappingUserFields []AttributeMappingUserField
	AttributeMappingMap        map[AttributeMappingAttribute]AttributeMappingUserFields
)

func (a AttributeMappingMap) Keys() []string {
	keys := make([]string, 0, len(a))
	for key, _ := range a {
		keys = append(keys, string(key))
	}
	return keys
}

func buildAttributeMappingMap(attributeMappingItems []*AttributeMappingItem) AttributeMappingMap {
	attributeMappingMap := make(AttributeMappingMap)
	for _, item := range attributeMappingItems {
		if item.Attribute == "" || item.UserField == "" {
			continue
		}

		itemAttribute := AttributeMappingAttribute(item.Attribute)
		itemUserField := AttributeMappingUserField(item.UserField)

		if _, ok := attributeMappingMap[itemAttribute]; !ok {
			attributeMappingMap[itemAttribute] = make(AttributeMappingUserFields, 0, 1)
		}
		attributeMappingMap[itemAttribute] = append(attributeMappingMap[itemAttribute], itemUserField)
	}

	return attributeMappingMap
}

func MapAttributeToUser(attribute *goldap.EntryAttribute, user *LdapUser, attributeMappingMap AttributeMappingMap) {
	if attributeMappingMap == nil {
		return
	}

	if attribute == nil {
		return
	}

	userFields := attributeMappingMap[AttributeMappingAttribute(attribute.Name)]
	attributeValue := attribute.Values[0]

	for _, userField := range userFields {
		switch userField {
		case "uid":
			user.Uid = util.TruncateIfTooLong(attributeValue, 100)
		case "email":
			user.Email = util.TruncateIfTooLong(attributeValue, 100)
		case "displayName":
			user.Cn = util.TruncateIfTooLong(attributeValue, 100)
		case "Phone":
			user.Phone = util.TruncateIfTooLong(attributeValue, 20)
		case "Address":
			user.Address = attributeValue
		}
	}
}
