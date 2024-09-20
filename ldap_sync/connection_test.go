package ldap_sync

import (
	"testing"

	"github.com/casdoor/casdoor/ldap_sync/mocks"
)

func TestBuildAuthFilterString(t *testing.T) {
	tests := []struct {
		name           string
		ldap           *Ldap
		userName       string
		userEmail      string
		expectedFilter string
	}{
		{
			name: "without filter fields and without attribute mapping",
			ldap: &Ldap{
				Filter:                  "(objectClass=user)",
				FilterFields:            nil,
				EnableCaseInsensitivity: false,
				EnableAttributeMapping:  true,
				AttributeMappingItems:   nil,
			},
			userName:       "test@test",
			userEmail:      "",
			expectedFilter: "(&(objectClass=user)(uid=test@test))",
		},
		{
			name: "without filter fields and with attribute mapping",
			ldap: &Ldap{
				Filter:                  "(objectClass=user)",
				FilterFields:            nil,
				EnableCaseInsensitivity: false,
				EnableAttributeMapping:  true,
				AttributeMappingItems: []*AttributeMappingItem{
					{
						"email",
						"userPrincipalName",
					},
					{
						"uid",
						"userPrincipalName",
					},
				},
			},
			userName:       "test@test",
			userEmail:      "",
			expectedFilter: "(&(objectClass=user)(userPrincipalName=test@test))",
		},
		{
			name: "with filter fields and attribute mapping",
			ldap: &Ldap{
				Filter:                  "(objectClass=user)",
				FilterFields:            []string{"userPrincipalName"},
				EnableCaseInsensitivity: false,
				EnableAttributeMapping:  true,
				AttributeMappingItems: []*AttributeMappingItem{
					{
						"email",
						"userPrincipalName",
					},
					{
						"uid",
						"userPrincipalName",
					},
				},
			},
			userName:       "test@test",
			userEmail:      "",
			expectedFilter: "(&(objectClass=user)(|(userPrincipalName=)(userPrincipalName=test@test)))",
		},
		{
			name: "with filter fields and attribute mapping with case insensitivity",
			ldap: &Ldap{
				Filter:                  "(objectClass=user)",
				FilterFields:            []string{"userPrincipalName"},
				EnableCaseInsensitivity: true,
				EnableAttributeMapping:  true,
				AttributeMappingItems: []*AttributeMappingItem{
					{
						"email",
						"userPrincipalName",
					},
					{
						"uid",
						"userPrincipalName",
					},
				},
			},
			userName:       "test@test",
			userEmail:      "",
			expectedFilter: "(&(objectClass=user)(|(userprincipalname=)(userprincipalname=test@test)))",
		},
		{
			name: "with filter fields and without attribute mapping",
			ldap: &Ldap{
				Filter:                  "(objectClass=user)",
				FilterFields:            []string{"userPrincipalName"},
				EnableCaseInsensitivity: false,
				EnableAttributeMapping:  true,
				AttributeMappingItems:   nil,
			},
			userName:       "test@test",
			userEmail:      "testEmail@test",
			expectedFilter: "(&(objectClass=user)(|(userPrincipalName=testEmail@test)))",
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				user := mocks.NewLdapRelatedUser(t)
				user.EXPECT().GetUserField("uid").Return(tt.userName).Maybe()
				user.EXPECT().GetUserField("email").Return(tt.userEmail).Maybe()
				user.EXPECT().GetName().Return(tt.userName).Maybe()
				user.EXPECT().GetFieldByLdapAttribute("userPrincipalName").Return(tt.userEmail).Maybe()
				filter := tt.ldap.BuildAuthFilterString(user)
				if filter != tt.expectedFilter {
					t.Errorf("expected filter %v, got %v", tt.expectedFilter, filter)
				}
			},
		)
	}
}
