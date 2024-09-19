package ldap_sync

import (
	"github.com/pkg/errors"

	"github.com/casdoor/casdoor/orm"
)

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

func (ldapUser *LdapUser) GetLdapUserID() string {
	if ldapUser.Uid != "" {
		return ldapUser.Uid
	}
	if ldapUser.Uuid != "" {
		return ldapUser.Uuid
	}

	return ldapUser.Cn
}

// BuildNameForNewLdapUser builds unique name for new user
func (ldapUser *LdapUser) BuildNameForNewLdapUser() (string, error) {
	if ldapUser.Uid != "" {
		return ldapUser.Uid, nil
	}
	if ldapUser.Uuid != "" {
		return ldapUser.Uuid, nil
	}
	if ldapUser.Cn != "" {
		return ldapUser.Cn, nil
	}
	return "", errors.New("failed to identify ldap user. User has empty uid, uuid, cn")
}

// GetLocalIDForExistingLdapUser select identification for new user by ldap field value
func GetLocalIDForExistingLdapUser(owner string, ldapUserID string) (string, error) {
	result, err := orm.AppOrmer.Engine.QueryString(
		`SELECT id FROM "user" WHERE ldap = ? AND owner = ?`,
		ldapUserID,
		owner,
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
