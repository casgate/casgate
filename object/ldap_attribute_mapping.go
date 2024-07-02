package object

import (
	"strings"

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

func buildAttributeMappingMap(attributeMappingItems []*AttributeMappingItem, enableCaseInsesitivity bool) AttributeMappingMap {
	attributeMappingMap := make(AttributeMappingMap)
	for _, item := range attributeMappingItems {
		if item.Attribute == "" || item.UserField == "" {
			continue
		}

		var itemAttribute AttributeMappingAttribute
		if enableCaseInsesitivity {
			itemAttribute = AttributeMappingAttribute(strings.ToLower(item.Attribute))
		} else {
			itemAttribute = AttributeMappingAttribute(item.Attribute)
		}

		itemUserField := AttributeMappingUserField(item.UserField)

		if _, ok := attributeMappingMap[itemAttribute]; !ok {
			attributeMappingMap[itemAttribute] = make(AttributeMappingUserFields, 0, 1)
		}
		attributeMappingMap[itemAttribute] = append(attributeMappingMap[itemAttribute], itemUserField)
	}

	return attributeMappingMap
}

func MapAttributesToUser(entry *goldap.Entry, user *LdapUser, attributeMappingMap AttributeMappingMap, enableCaseInsensitivity bool) []string {
	unmappedAttributes := make([]string, 0)

	// creating map for quick access to LDAP attributes by name
	ldapAttributes := make(map[string]*goldap.EntryAttribute)
	for _, attribute := range entry.Attributes {
		if enableCaseInsensitivity {
			ldapAttributes[strings.ToLower(attribute.Name)] = attribute
		} else {
			ldapAttributes[attribute.Name] = attribute
		}
		
	}
	

	// iterating over expected attributes from attributeMappingMap
	for mappingAttr, userFields := range attributeMappingMap {
		attribute, ok := ldapAttributes[string(mappingAttr)]
		if !ok {
			// attribute from map was not found in LDAP, we add it to the list of unmapped
			unmappedAttributes = append(unmappedAttributes, string(mappingAttr))
			continue
		}

		// if attribute is found, process its values
		attributeValue := attribute.Values[0] // take first value as specified in original function
		for _, userField := range userFields {
			switch userField {
			case "uid":
				user.Uid = util.TruncateIfTooLong(attributeValue, 100)
			case "email":
				user.Email = util.TruncateIfTooLong(attributeValue, 100)
			case "displayName":
				user.Cn = util.TruncateIfTooLong(attributeValue, 100)
			case "Phone":
				user.MobileTelephoneNumber = util.TruncateIfTooLong(attributeValue, 20)
			case "Address":
				user.Address = attributeValue
			}
		}
	}

	return unmappedAttributes
}
