// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/idp"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	defaultFirstNameOid = "urn:oid:2.5.4.42"
	defaultLastNameOid  = "urn:oid:2.5.4.4"
	defaultEmailOid     = "urn:oid:1.2.840.113549.1.9.1"

	nameIdFormatAliasPersistent   = "Persistent"
	nameIdFormatAliasTransient    = "Transient"
	nameIdFormatAliasEmailAddress = "Email"
	nameIdFormatAliasUnspecified  = "Unspecified"

	sha1CryptoAlgorithm   = "RSA-SHA1"
	sha256CryptoAlgorithm = "RSA-SHA256"
	sha512CryptoAlgorithm = "RSA-SHA512"
)

var nameIdFormats = map[string]string{
	nameIdFormatAliasPersistent:   saml2.NameIdFormatPersistent,
	nameIdFormatAliasTransient:    saml2.NameIdFormatTransient,
	nameIdFormatAliasEmailAddress: saml2.NameIdFormatEmailAddress,
	nameIdFormatAliasUnspecified:  saml2.NameIdFormatUnspecified,
}

var signatureAlgorithms = map[string]string{
	sha1CryptoAlgorithm:   dsig.RSASHA1SignatureMethod,
	sha256CryptoAlgorithm: dsig.RSASHA256SignatureMethod,
	sha512CryptoAlgorithm: dsig.RSASHA512SignatureMethod,
}

var samlSertRegex = regexp.MustCompile("<[[[:alpha:]]+:]?X509Certificate>([\\s\\S]*?)</[[[:alpha:]]+:]?X509Certificate>")

func ParseSamlResponse(samlResponse string, provider *Provider, host string) (*idp.UserInfo, map[string]any, error) {
	samlResponse, _ = url.QueryUnescape(samlResponse)
	sp, err := BuildSp(provider, samlResponse, host)
	if err != nil {
		return nil, nil, err
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(samlResponse)
	if err != nil {
		return nil, nil, err
	}

	dataMap := map[string]string{
		"id":          assertionInfo.NameID,
		"username":    assertionInfo.NameID,
		"displayName": fmt.Sprintf("%s %s", assertionInfo.Values.Get(defaultFirstNameOid), assertionInfo.Values.Get(defaultLastNameOid)),
		"email":       assertionInfo.Values.Get(defaultEmailOid),
		"avatarUrl":   "",
	}

	if strings.Trim(dataMap["displayName"], " ") == "" {
		dataMap["displayName"] = assertionInfo.NameID
	}

	for k, attrArr := range provider.UserMapping {
		if len(attrArr) > 0 {
			dataMap[k] = ""
		}

		for _, attr := range attrArr {
			var value string

			value = assertionInfo.Values.Get(attr)
			if attr == "ID" {
				value = assertionInfo.NameID
			}

			switch k {
			case "displayName":
				if value != "" {
					// few values are concatenated by space for displayName
					dataMap[k] = strings.Trim(strings.Join([]string{dataMap[k], value}, " "), " ")
				}
			default:
				if value != "" {
					dataMap[k] = value
					// the first non-empty attribute is taken for default case
					break
				}
			}
		}
	}

	authData := getAuthData(assertionInfo, provider)

	userInfo := idp.UserInfo{
		Id:          dataMap["id"],
		Username:    dataMap["username"],
		DisplayName: dataMap["displayName"],
		Email:       dataMap["email"],
		AvatarUrl:   dataMap["avatarUrl"],
	}
	return &userInfo, authData, nil
}

func getAuthData(assertionInfo *saml2.AssertionInfo, provider *Provider) map[string]interface{} {
	authData := map[string]interface{}{
		"ID": assertionInfo.NameID,
	}

	for key := range assertionInfo.Values {
		if !slices.ContainsFunc(provider.RoleMappingItems, func(item *RoleMappingItem) bool {
			return item.Role == key
		}) {
			authData[key] = assertionInfo.Values.Get(key)
		}
	}

	for _, mappItem := range provider.RoleMappingItems {
		for _, assertion := range assertionInfo.Assertions {
			roles := make([]string, 0)

			for _, attribute := range assertion.AttributeStatement.Attributes {
				if attribute.Name == mappItem.Attribute {

					for _, val := range attribute.Values {
						roles = append(roles, val.Value)
					}

				}
			}

			authData[mappItem.Attribute] = roles
		}
	}

	return authData
}

func GenerateSamlRequest(id, relayState, host, lang string) (auth string, method string, err error) {
	provider, err := GetProvider(id)
	if err != nil {
		return "", "", err
	}
	if provider.Category != "SAML" {
		return "", "", fmt.Errorf(i18n.Translate(lang, "saml_sp:provider %s's category is not SAML"), provider.Name)
	}

	sp, err := BuildSp(provider, "", host)
	if err != nil {
		return "", "", err
	}

	method = getSAMLRequestMethod(provider)
	data, err := buildSAMLRequest(sp, method, relayState)
	if err != nil {
		return "", "", err
	}

	return data, method, nil
}

func getSAMLRequestMethod(provider *Provider) string {
	if provider.EndpointType == "HTTP-POST" {
		return http.MethodPost
	}

	return http.MethodGet
}

func buildSAMLRequest(sp *saml2.SAMLServiceProvider, httpMethod string, relayState string) (auth string, err error) {
	if httpMethod == http.MethodGet {
		return sp.BuildAuthURL(relayState)
	}

	postData, err := sp.BuildAuthBodyPost(relayState)
	return string(postData[:]), err
}

func BuildSp(provider *Provider, samlResponse string, host string) (*saml2.SAMLServiceProvider, error) {
	_, origin := getOriginFromHostWithConfPriority(host)

	issuer := provider.ClientId
	if issuer == "" {
		issuer = fmt.Sprintf("%s/api/acs", origin)
	}

	nameIdFormat, err := getFullNameIdFormat(provider.NameIdFormat)
	if err != nil {
		return nil, err
	}

	sp := &saml2.SAMLServiceProvider{
		ServiceProviderIssuer:          issuer,
		AssertionConsumerServiceURL:    fmt.Sprintf("%s/api/acs", origin),
		NameIdFormat:                   nameIdFormat,
		SignAuthnRequests:              false,
		SPKeyStore:                     dsig.RandomKeyStoreForTest(),
		SkipSignatureValidation:        !provider.ValidateIdpSignature,
		ServiceProviderSLOURL:          provider.SingleLogoutServiceUrl,
		SignAuthnRequestsCanonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""),
	}

	if provider.Endpoint != "" {
		sp.IdentityProviderSSOURL = provider.Endpoint
		sp.IdentityProviderIssuer = provider.IssuerUrl
	}
	if provider.RequestSignature != NotToSign {
		sp.SignAuthnRequests = true
		sp.SignAuthnRequestsAlgorithm, err = getFullSignatureAlgorithm(provider.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}
		sp.SPKeyStore, err = buildSpKeyStore(provider)
		if err != nil {
			return nil, err
		}
	}
	if provider.ValidateIdpSignature && samlResponse != "" {
		sp.IDPCertificateStore, err = buildIdPCertificateStore(provider, samlResponse)
		if err != nil {
			return nil, err
		}
	}

	return sp, nil
}

func buildSpKeyStore(provider *Provider) (dsig.X509KeyStore, error) {
	var (
		certificate *Cert
		keyPair     tls.Certificate
		err         error
	)
	if provider.RequestSignature == SignWithCertificate {
		if provider.Cert == "" {
			return nil, errors.New("certificate for request signature was not selected")
		}
		certificate, err = GetCert(fmt.Sprintf("%s/%s", provider.Owner, provider.Cert))
		if err != nil {
			return nil, err
		}
		if certificate == nil {
			return nil, ErrCertDoesNotExist
		}

		if certificate.Scope != scopeClientCert {
			return nil, ErrCertInvalidScope
		}

		keyPair, err = tls.X509KeyPair([]byte(certificate.Certificate), []byte(certificate.PrivateKey))
		if err != nil {
			return nil, err
		}
	} else if provider.RequestSignature == SignWithFile {
		keyPair, err = tls.LoadX509KeyPair("object/token_jwt_key.pem", "object/token_jwt_key.key")
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New(fmt.Sprintf("unknown request signature type: %s", provider.RequestSignature))
	}

	return &dsig.TLSCertKeyStore{
		PrivateKey:  keyPair.PrivateKey,
		Certificate: keyPair.Certificate,
	}, nil
}

func buildIdPCertificateStore(provider *Provider, samlResponse string) (certStore *dsig.MemoryX509CertificateStore, err error) {
	certEncodedData, err := getCertificateFromSamlResponse(samlResponse)
	if err != nil {
		return &dsig.MemoryX509CertificateStore{}, err
	}
	certData, err := base64.StdEncoding.DecodeString(certEncodedData)
	if err != nil {
		return &dsig.MemoryX509CertificateStore{}, err
	}
	idpCert, err := x509.ParseCertificate(certData)
	if err != nil {
		return &dsig.MemoryX509CertificateStore{}, err
	}

	certStore = &dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{idpCert},
	}
	return certStore, nil
}

func getCertificateFromSamlResponse(samlResponse string) (string, error) {
	de, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return "", err
	}

	deStr := strings.Replace(string(de), "\n", "", -1)

	res := samlSertRegex.FindStringSubmatch(deStr)
	if res == nil {
		return "", errors.New("could not obtain signature certificate from SAML response")
	}

	return res[1], nil
}

func getFullNameIdFormat(nameIdFormat string) (string, error) {
	if result, ok := nameIdFormats[nameIdFormat]; ok {
		return result, nil
	}
	return "", errors.New(fmt.Sprintf("Unknown Name ID Format: %s", nameIdFormat))
}

func getFullSignatureAlgorithm(signatureAlgorithm string) (string, error) {
	if result, ok := signatureAlgorithms[signatureAlgorithm]; ok {
		return result, nil
	}
	return "", errors.New(fmt.Sprintf("Unknown signature algorithm: %s", signatureAlgorithm))
}
