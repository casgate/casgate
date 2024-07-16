package object

func mapProvidersToNames(providers []*ProviderItem) []string {
	providerNames := make([]string, 0, len(providers))
	for _, provider := range providers {
		providerNames = append(providerNames, provider.Name)
	}

	return providerNames
}

func CompareRoleMappingSlices(slice1, slice2 []*RoleMappingItem) bool {
	if len(slice1) != len(slice2) {
		return false
	}

	for i := range slice1 {
		isEqual := slice1[i].Attribute != slice2[i].Attribute ||
			slice1[i].Role != slice2[i].Role ||
			!CompareStringSlices(slice1[i].Values, slice2[i].Values)

		if !isEqual {
			return false
		}
	}

	return true
}

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
