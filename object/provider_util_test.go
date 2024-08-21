package object

import (
	"testing"

	"github.com/casdoor/casdoor/ldap_sync"
)

func TestCompareStringSlices(t *testing.T) {
	tests := []struct {
		name   string
		slice1 []string
		slice2 []string
		want   bool
	}{
		{"both slices are empty", []string{}, []string{}, true},
		{"one slice is empty", []string{}, []string{"a"}, false},
		{"slices have different lengths", []string{"a"}, []string{"a", "b"}, false},
		{"slices are equal", []string{"a", "b"}, []string{"a", "b"}, true},
		{"slices are not equal", []string{"a", "b"}, []string{"b", "a"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareStringSlices(tt.slice1, tt.slice2); got != tt.want {
				t.Errorf("CompareStringSlices() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRoleMappingsEqual(t *testing.T) {
	tests := []struct {
		name   string
		slice1 []*ldap_sync.RoleMappingItem
		slice2 []*ldap_sync.RoleMappingItem
		want   bool
	}{
		{
			"both slices are empty",
			[]*ldap_sync.RoleMappingItem{},
			[]*ldap_sync.RoleMappingItem{},
			true,
		},
		{
			"one slice is empty",
			[]*ldap_sync.RoleMappingItem{},
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val1"}, "role1"}},
			false,
		},
		{
			"slices have different lengths",
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val1"}, "role1"}},
			[]*ldap_sync.RoleMappingItem{}, false,
		},
		{
			"slices are equal",
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val1"}, "role1"}},
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val1"}, "role1"}},
			true,
		},
		{
			"slices are not equal by attribute",
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val1"}, "role1"}},
			[]*ldap_sync.RoleMappingItem{{"attr2", []string{"val1"}, "role1"}},
			false,
		},
		{
			"slices are not equal by values",
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val1"}, "role1"}},
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val2"}, "role1"}},
			false,
		},
		{
			"slices are not equal by role",
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val1"}, "role1"}},
			[]*ldap_sync.RoleMappingItem{{"attr1", []string{"val1"}, "role2"}},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRoleMappingsEqual(tt.slice1, tt.slice2); got != tt.want {
				t.Errorf("IsRoleMappingsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
