package util

import "net/http"

type ProviderInfo struct {
	Cert     string
	ConfURL  string
	TokenURL string
}

type HttpClientProvider interface {
	GetProviderHttpClient(info ProviderInfo) (*http.Client, error)
}
