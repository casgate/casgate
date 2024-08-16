package ldap_sync

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/pkg/errors"
	"github.com/thanhpk/randstr"

	casdoorcert "github.com/casdoor/casdoor/cert"
	"github.com/casdoor/casdoor/orm"
)

type LdapConn struct {
	Conn *goldap.Conn
	IsAD bool
}

func GetLdapConn(_ context.Context, ldap *Ldap) (*LdapConn, error) {
	var (
		conn *goldap.Conn
		err  error
	)

	dialer := &net.Dialer{
		Timeout: goldap.DefaultTimeout,
	}

	if ldap.EnableSsl {
		tlsConf := &tls.Config{}

		if ldap.Cert != "" {
			tlsConf, err = casdoorcert.GetTlsConfigForCert(ldap.Cert)
			if err != nil {
				return nil, errors.Wrap(err, "get tls config")
			}
		}

		if ldap.EnableCryptographicAuth {
			var clientCerts []tls.Certificate
			if ldap.ClientCert != "" {
				cert, err := casdoorcert.GetCertByName(ldap.ClientCert)
				if err != nil {
					return nil, errors.Wrap(err, "get cert by name failed")
				}
				if cert == nil {
					return nil, casdoorcert.ErrCertDoesNotExist
				}
				if cert.Scope != casdoorcert.ScopeClientCert {
					return nil, casdoorcert.ErrCertInvalidScope
				}
				clientCert, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
				if err != nil {
					return nil, errors.Wrap(err, "load client certificate failed")
				}

				clientCerts = []tls.Certificate{clientCert}
			}
			tlsConf.Certificates = clientCerts
		}
		conn, err = goldap.DialURL(
			fmt.Sprintf("ldaps://%s:%d", ldap.Host, ldap.Port),
			goldap.DialWithTLSConfig(tlsConf),
			goldap.DialWithDialer(dialer),
		)
	} else {
		conn, err = goldap.DialURL(fmt.Sprintf("ldap://%s:%d", ldap.Host, ldap.Port), goldap.DialWithDialer(dialer))
	}
	if err != nil {
		return nil, errors.Wrap(err, "goldap connect failed")
	}

	if ldap.EnableSsl && ldap.EnableCryptographicAuth {
		err = conn.ExternalBind()
	} else {
		err = conn.Bind(ldap.Username, ldap.Password)
	}
	if err != nil {
		return nil, errors.Wrap(err, "bind failed")
	}

	isAD, err := isMicrosoftAD(conn)
	if err != nil {
		return nil, err
	}
	return &LdapConn{Conn: conn, IsAD: isAD}, nil
}

func (l *LdapConn) Close() {
	// if l.Conn == nil {
	// 	return
	// }

	// err := l.Conn.Unbind()
	// if err != nil {
	// 	panic(err)
	// }
}

func isMicrosoftAD(Conn *goldap.Conn) (bool, error) {
	SearchFilter := "(objectClass=*)"
	SearchAttributes := []string{"vendorname", "vendorversion", "isGlobalCatalogReady", "forestFunctionality"}

	searchReq := goldap.NewSearchRequest(
		"",
		goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		SearchFilter, SearchAttributes, nil,
	)
	searchResult, err := Conn.Search(searchReq)
	if err != nil {
		return false, err
	}
	if len(searchResult.Entries) == 0 {
		return false, nil
	}
	isMicrosoft := false

	type ldapServerType struct {
		Vendorname           string
		Vendorversion        string
		IsGlobalCatalogReady string
		ForestFunctionality  string
	}
	var ldapServerTypes ldapServerType
	for _, entry := range searchResult.Entries {
		for _, attribute := range entry.Attributes {
			switch attribute.Name {
			case "vendorname":
				ldapServerTypes.Vendorname = attribute.Values[0]
			case "vendorversion":
				ldapServerTypes.Vendorversion = attribute.Values[0]
			case "isGlobalCatalogReady":
				ldapServerTypes.IsGlobalCatalogReady = attribute.Values[0]
			case "forestFunctionality":
				ldapServerTypes.ForestFunctionality = attribute.Values[0]
			}
		}
	}
	if ldapServerTypes.Vendorname == "" &&
		ldapServerTypes.Vendorversion == "" &&
		ldapServerTypes.IsGlobalCatalogReady == "TRUE" &&
		ldapServerTypes.ForestFunctionality != "" {
		isMicrosoft = true
	}
	return isMicrosoft, err
}

type RecordBuilder interface {
	AddReason(string)
}

type LdapRelatedUser interface {
	GetFieldByLdapAttribute(string) string
	GetName() string
}

func (l *LdapConn) GetUsersFromLDAP(
	ldapServer *Ldap,
	selectedUser LdapRelatedUser,
	rb RecordBuilder,
) ([]LdapUser, error) {
	SearchAttributes := []string{
		"uidNumber", "cn", "sn", "gidNumber", "entryUUID", "displayName", "mail", "email",
		"emailAddress", "telephoneNumber", "mobile", "mobileTelephoneNumber", "registeredAddress", "postalAddress",
	}
	if l.IsAD {
		SearchAttributes = append(SearchAttributes, "sAMAccountName", "userPrincipalName")
	} else {
		SearchAttributes = append(SearchAttributes, "uid")
	}

	for _, roleMappingItem := range ldapServer.RoleMappingItems {
		SearchAttributes = append(SearchAttributes, roleMappingItem.Attribute)
	}

	var attributeMappingMap AttributeMappingMap
	if ldapServer.EnableAttributeMapping {
		attributeMappingMap = buildAttributeMappingMap(
			ldapServer.AttributeMappingItems,
			ldapServer.EnableCaseInsensitivity,
		)
		SearchAttributes = append(SearchAttributes, attributeMappingMap.Keys()...)
	}

	ldapFilter := ldapServer.Filter
	if selectedUser != nil {
		ldapFilter = ldapServer.BuildAuthFilterString(selectedUser)
	}

	searchReq := goldap.NewSearchRequest(
		ldapServer.BaseDn, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false,
		ldapFilter, SearchAttributes, nil,
	)
	searchResult, err := l.Conn.SearchWithPaging(searchReq, 100)
	if err != nil {
		return nil, err
	}

	if len(searchResult.Entries) == 0 {
		return nil, errors.New("no result")
	}

	var roleMappingMap RoleMappingMap
	if ldapServer.EnableRoleMapping {
		roleMappingMap = buildRoleMappingMap(ldapServer.RoleMappingItems, ldapServer.EnableCaseInsensitivity)
	}

	var ldapUsers []LdapUser
	for _, entry := range searchResult.Entries {
		var user LdapUser

		if ldapServer.EnableAttributeMapping {
			unmappedAttributes := MapAttributesToUser(
				entry,
				&user,
				attributeMappingMap,
				ldapServer.EnableCaseInsensitivity,
			)
			if len(unmappedAttributes) > 0 {
				rb.AddReason(
					fmt.Sprintf(
						"User (%s) has unmapped attributes: %s",
						entry.DN,
						strings.Join(unmappedAttributes, ", "),
					),
				)
			}
		}

		for _, attribute := range entry.Attributes {
			// check attribute value with role mapping rules
			if ldapServer.EnableRoleMapping {
				attributeName := attribute.Name
				if ldapServer.EnableCaseInsensitivity {
					attributeName = strings.ToLower(attributeName)
				}

				if roleMappingMapItem, ok := roleMappingMap[RoleMappingAttribute(attributeName)]; ok {
					for _, value := range attribute.Values {
						if ldapServer.EnableCaseInsensitivity {
							value = strings.ToLower(value)
						}
						if roleMappingMapRoles, ok := roleMappingMapItem[RoleMappingItemValue(value)]; ok {
							user.Roles = append(user.Roles, roleMappingMapRoles.StrRoles()...)
						}
					}
				}
			}

			if ldapServer.EnableAttributeMapping {
				continue
			}

			switch attribute.Name {
			case "uidNumber":
				user.UidNumber = attribute.Values[0]
			case "uid":
				user.Uid = attribute.Values[0]
			case "sAMAccountName":
				user.Uid = attribute.Values[0]
			case "cn":
				user.Cn = attribute.Values[0]
			case "gidNumber":
				user.GidNumber = attribute.Values[0]
			case "entryUUID":
				user.Uuid = attribute.Values[0]
			case "objectGUID":
				user.Uuid = attribute.Values[0]
			case "userPrincipalName":
				user.UserPrincipalName = attribute.Values[0]
			case "displayName":
				user.DisplayName = attribute.Values[0]
			case "mail":
				user.Mail = attribute.Values[0]
			case "email":
				user.Email = attribute.Values[0]
			case "emailAddress":
				user.EmailAddress = attribute.Values[0]
			case "telephoneNumber":
				user.TelephoneNumber = attribute.Values[0]
			case "mobile":
				user.Mobile = attribute.Values[0]
			case "mobileTelephoneNumber":
				user.MobileTelephoneNumber = attribute.Values[0]
			case "registeredAddress":
				user.RegisteredAddress = attribute.Values[0]
			case "postalAddress":
				user.PostalAddress = attribute.Values[0]
			case "memberOf":
				user.MemberOf = attribute.Values[0]
			}
		}

		ldapUsers = append(ldapUsers, user)
	}

	return ldapUsers, nil
}

func (ldap *Ldap) BuildAuthFilterString(user LdapRelatedUser) string {
	if len(ldap.FilterFields) == 0 {
		return fmt.Sprintf("(&%s(uid=%s))", ldap.Filter, user.GetName())
	}

	filter := fmt.Sprintf("(&%s(|", ldap.Filter)
	for _, field := range ldap.FilterFields {
		filter = fmt.Sprintf("%s(%s=%s)", filter, field, user.GetFieldByLdapAttribute(field))
	}
	filter = fmt.Sprintf("%s))", filter)

	return filter
}

type Ldap struct {
	Id          string `xorm:"varchar(100) notnull pk" json:"id"`
	Owner       string `xorm:"varchar(100)" json:"owner"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	ServerName              string   `xorm:"varchar(100)" json:"serverName"`
	Host                    string   `xorm:"varchar(100)" json:"host"`
	Port                    int      `xorm:"int" json:"port"`
	EnableSsl               bool     `xorm:"bool" json:"enableSsl"`
	EnableCryptographicAuth bool     `xorm:"bool" json:"enableCryptographicAuth"`
	Username                string   `xorm:"varchar(100)" json:"username"`
	Password                string   `xorm:"varchar(100)" json:"password"`
	BaseDn                  string   `xorm:"varchar(100)" json:"baseDn"`
	Filter                  string   `xorm:"varchar(200)" json:"filter"`
	FilterFields            []string `xorm:"varchar(100)" json:"filterFields"`

	EnableRoleMapping bool               `xorm:"bool" json:"enableRoleMapping"`
	RoleMappingItems  []*RoleMappingItem `xorm:"text" json:"roleMappingItems"`

	EnableCaseInsensitivity bool `xorm:"bool" json:"enableCaseInsensitivity"`

	AutoSync int    `json:"autoSync"`
	LastSync string `xorm:"varchar(100)" json:"lastSync"`

	Cert       string `xorm:"varchar(100)" json:"cert"`
	ClientCert string `xorm:"varchar(100)" json:"clientCert"`

	EnableAttributeMapping bool                    `xorm:"bool" json:"enableAttributeMapping"`
	AttributeMappingItems  []*AttributeMappingItem `xorm:"text" json:"attributeMappingItems"`

	UserMappingStrategy string `xorm:"varchar(50)" json:"userMappingStrategy"`
}

type LdapUser struct {
	UidNumber string `json:"uidNumber"`
	Uid       string `json:"uid"`
	Cn        string `json:"cn"`
	GidNumber string `json:"gidNumber"`
	// Gcn                   string
	Uuid                  string `json:"uuid"`
	UserPrincipalName     string `json:"userPrincipalName"`
	DisplayName           string `json:"displayName"`
	Mail                  string
	Email                 string `json:"email"`
	EmailAddress          string
	TelephoneNumber       string
	Mobile                string `json:"mobile"`
	MobileTelephoneNumber string
	RegisteredAddress     string
	PostalAddress         string

	GroupId  string `json:"groupId"`
	Address  string `json:"address"`
	MemberOf string `json:"memberOf"`

	Roles []string `json:"roles"`
}

func (ldapUser *LdapUser) GetLdapUuid() string {
	if ldapUser.Uuid != "" {
		return ldapUser.Uuid
	}
	if ldapUser.Uid != "" {
		return ldapUser.Uid
	}

	return ldapUser.Cn
}

// BuildNameForNewLdapUser builds unique name for new user
func (ldapUser *LdapUser) BuildNameForNewLdapUser() (string, error) {
	if ldapUser.Uid == "" {
		return "", errors.New("can't build name for new ldap user")
	}
	return fmt.Sprintf("%s_%s_%s", ldapUser.Uid, ldapUser.UidNumber, randstr.Hex(6)), nil
}

// GetLocalIDForExistingLdapUser select identification for new user by ldap field value
func (ldapUser *LdapUser) GetLocalIDForExistingLdapUser() (string, error) {
	uidWithNumber := fmt.Sprintf("%s_%s", ldapUser.Uid, ldapUser.UidNumber)
	result, err := orm.AppOrmer.Engine.QueryString(
		`SELECT id FROM "user" WHERE ldap = ? OR ldap = ?`,
		ldapUser.Uid,
		uidWithNumber,
	)
	if err != nil {
		return "", err
	}
	if len(result) == 0 {
		return "", errors.New("previously imported user not found")
	}
	return result[0]["id"], nil
}

func (ldapUser *LdapUser) BuildLdapDisplayName() string {
	if ldapUser.DisplayName != "" {
		return ldapUser.DisplayName
	}

	return ldapUser.Cn
}
