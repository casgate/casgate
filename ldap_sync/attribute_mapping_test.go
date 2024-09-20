package ldap_sync

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestBuildAttributeMappingMap(t *testing.T) {
	tests := []struct {
		name                    string
		attributeMappingItems   []*AttributeMappingItem
		enableCaseInsensitivity bool
		expectedMap             AttributeMappingMap
	}{
		{
			name: "Basic mapping without case insensitivity",
			attributeMappingItems: []*AttributeMappingItem{
				{UserField: "uid", Attribute: "UID"},
				{UserField: "email", Attribute: "mail"},
			},
			enableCaseInsensitivity: false,
			expectedMap: AttributeMappingMap{
				"UID":  {"uid"},
				"mail": {"email"},
			},
		},
		{
			name: "Mapping with case insensitivity",
			attributeMappingItems: []*AttributeMappingItem{
				{UserField: "uid", Attribute: "UID"},
				{UserField: "email", Attribute: "MAIL"},
			},
			enableCaseInsensitivity: true,
			expectedMap: AttributeMappingMap{
				"uid":  {"uid"},
				"mail": {"email"},
			},
		},
		{
			name: "Empty attribute or user field",
			attributeMappingItems: []*AttributeMappingItem{
				{UserField: "", Attribute: "UID"},
				{UserField: "email", Attribute: ""},
			},
			enableCaseInsensitivity: false,
			expectedMap:             AttributeMappingMap{},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				result := buildAttributeMappingMap(tt.attributeMappingItems, tt.enableCaseInsensitivity)
				if len(result) != len(tt.expectedMap) {
					t.Errorf("expected %v, got %v", tt.expectedMap, result)
				}
				for key, val := range tt.expectedMap {
					if len(result[key]) != len(val) || result[key][0] != val[0] {
						t.Errorf("expected %v for key %v, got %v", val, key, result[key])
					}
				}
			},
		)
	}
}

func TestMapAttributesToUser(t *testing.T) {
	tests := []struct {
		name                    string
		entry                   *ldap.Entry
		user                    *LdapUser
		attributeMappingMap     AttributeMappingMap
		enableCaseInsensitivity bool
		expectedUser            *LdapUser
		expectedUnmapped        []string
	}{
		{
			name: "All attributes mapped",
			entry: &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{Name: "UID", Values: []string{"testUID"}},
					{Name: "mail", Values: []string{"test@example.com"}},
				},
			},
			user: &LdapUser{},
			attributeMappingMap: AttributeMappingMap{
				"UID":  {"uid"},
				"mail": {"email"},
			},
			enableCaseInsensitivity: false,
			expectedUser: &LdapUser{
				Uid:   "testUID",
				Email: "test@example.com",
			},
			expectedUnmapped: []string{},
		},
		{
			name: "Some attributes not found in LDAP entry",
			entry: &ldap.Entry{
				Attributes: []*ldap.EntryAttribute{
					{Name: "mail", Values: []string{"test@example.com"}},
				},
			},
			user: &LdapUser{},
			attributeMappingMap: AttributeMappingMap{
				"UID":  {"uid"},
				"mail": {"email"},
			},
			enableCaseInsensitivity: false,
			expectedUser: &LdapUser{
				Email: "test@example.com",
			},
			expectedUnmapped: []string{"UID"},
		},
		// {
		// 	name: "Case insensitivity enabled",
		// 	entry: &ldap.Entry{
		// 		Attributes: []*ldap.EntryAttribute{
		// 			{Name: "uid", Values: []string{"testUID"}},
		// 			{Name: "MAIL", Values: []string{"test@example.com"}},
		// 		},
		// 	},
		// 	user: &LdapUser{},
		// 	attributeMappingMap: AttributeMappingMap{
		// 		"UID":  {"uid"},
		// 		"mail": {"email"},
		// 	},
		// 	enableCaseInsensitivity: true,
		// 	expectedUser: &LdapUser{
		// 		Uid:   "testUID",
		// 		Email: "test@example.com",
		// 	},
		// 	expectedUnmapped: []string{},
		// },
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				unmapped := MapAttributesToUser(tt.entry, tt.user, tt.attributeMappingMap, tt.enableCaseInsensitivity)

				if len(unmapped) != len(tt.expectedUnmapped) {
					t.Errorf("expected unmapped %v, got %v", tt.expectedUnmapped, unmapped)
				}

				if tt.user.Uid != tt.expectedUser.Uid || tt.user.Email != tt.expectedUser.Email {
					t.Errorf("expected user %v, got %v", tt.expectedUser, tt.user)
				}
			},
		)
	}
}
