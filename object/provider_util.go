package object

import "github.com/casdoor/casdoor/ldap_sync"

func mapProvidersToNames(providers []*ProviderItem) []string {
	providerNames := make([]string, 0, len(providers))
	for _, provider := range providers {
		providerNames = append(providerNames, provider.Name)
	}

	return providerNames
}

// IsRoleMappingsEqual compares two slices of RoleMappingItem for equality.
// Returns true if both slices have the same length and their corresponding elements are equal.
// The elements are compared based on their Attribute, Role, and Values fields.
func IsRoleMappingsEqual(slice1, slice2 []*ldap_sync.RoleMappingItem) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	for i := range slice1 {
		notEqual := slice1[i].Attribute != slice2[i].Attribute ||
			slice1[i].Role != slice2[i].Role ||
			!CompareStringSlices(slice1[i].Values, slice2[i].Values)

		if notEqual {
			return false
		}
	}

	return true
}

// CompareStringSlices compares two slices of strings for equality.
// Returns true if both slices have the same length and their corresponding elements are equal.
func CompareStringSlices(slice1, slice2 []string) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}

	return true
}
