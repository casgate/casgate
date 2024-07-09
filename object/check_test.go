package object_test

import (
	"testing"

	"github.com/casdoor/casdoor/object"
	"github.com/go-ldap/ldap/v3"
)

func TestCheckIsUserDisabled(t *testing.T) {
	tests := []struct {
		userAttributes []*ldap.EntryAttribute
		expected       bool
	}{
		{
			[]*ldap.EntryAttribute{
				{Name: "userAccountControl", Values: []string{"514"}},
				{Name: "cn", Values: []string{"John Doe"}},
				{Name: "mail", Values: []string{"johndoe@example.com"}},
			},
			true,
		},
		{
			[]*ldap.EntryAttribute{
				{Name: "userAccountControl", Values: []string{"512"}},
				{Name: "cn", Values: []string{"Jane Smith"}},
				{Name: "mail", Values: []string{"janesmith@example.com"}},
			},
			false,
		},
		{
			[]*ldap.EntryAttribute{
				{Name: "userAccountControl", Values: []string{"66050"}},
				{Name: "cn", Values: []string{"Alice Johnson"}},
				{Name: "mail", Values: []string{"alicejohnson@example.com"}},
			},
			true,
		},
		{
			[]*ldap.EntryAttribute{
				{Name: "userAccountControl", Values: []string{"66048"}},
				{Name: "cn", Values: []string{"Bob Brown"}},
				{Name: "mail", Values: []string{"bobbrown@example.com"}},
			},
			false,
		},
		{
			[]*ldap.EntryAttribute{
				{Name: "userAccountControl", Values: []string{"514"}},
				{Name: "cn", Values: []string{"Charlie Davis"}},
				{Name: "mail", Values: []string{"charliedavis@example.com"}},
				{Name: "title", Values: []string{"Manager"}},
				{Name: "telephoneNumber", Values: []string{"123-456-7890"}},
			},
			true,
		},
		{
			[]*ldap.EntryAttribute{
				{Name: "userAccountControl", Values: []string{"512"}},
				{Name: "cn", Values: []string{"Dana White"}},
				{Name: "mail", Values: []string{"danawhite@example.com"}},
				{Name: "title", Values: []string{"Developer"}},
				{Name: "telephoneNumber", Values: []string{"987-654-3210"}},
			},
			false,
		},
	}

	for _, test := range tests {
		result, err := object.CheckIsUserDisabled(test.userAttributes)
		if err != nil {
			t.Errorf("CheckIsUserDisabled returned an error: %v", err)
		}
		if result != test.expected {
			t.Errorf("CheckIsUserDisabled(%v) = %v; want %v", test.userAttributes, result, test.expected)
		}
	}
}
