package object

func mapProvidersToNames(providers []*ProviderItem) []string {
	providerNames := make([]string, 0, len(providers))
	for _, provider := range providers {
		providerNames = append(providerNames, provider.Name)
	}

	return providerNames
}
