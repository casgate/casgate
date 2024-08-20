// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/casdoor/casdoor/ldap_sync"
	"github.com/casdoor/casdoor/orm"
	"github.com/pkg/errors"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/thanhpk/randstr"

	"github.com/casdoor/casdoor/util"
)

type LdapConn struct {
	Conn *goldap.Conn
	IsAD bool
}

//type ldapGroup struct {
//	GidNumber string
//	Cn        string
//}

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

var ErrX509CertsPEMParse = errors.New("x509: malformed CA certificate")

func (ldap *Ldap) GetLdapConn(ctx context.Context) (*LdapConn, error) {
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
			tlsConf, err = GetTlsConfigForCert(ldap.Cert)
			if err != nil {
				return nil, errors.Wrap(err, "get tls config")
			}
		}

		if ldap.EnableCryptographicAuth {
			var clientCerts []tls.Certificate
			if ldap.ClientCert != "" {
				cert, err := getCertByName(ldap.ClientCert)
				if err != nil {
					return nil, errors.Wrap(err, "get cert by name failed")
				}
				if cert == nil {
					return nil, ErrCertDoesNotExist
				}
				if cert.Scope != scopeClientCert {
					return nil, ErrCertInvalidScope
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

	searchReq := goldap.NewSearchRequest("",
		goldap.ScopeBaseObject, goldap.NeverDerefAliases, 0, 0, false,
		SearchFilter, SearchAttributes, nil)
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

func (l *LdapConn) GetLdapUsers(ldapServer *Ldap, selectedUser *User, rb *RecordBuilder) ([]LdapUser, error) {
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
		attributeMappingMap = buildAttributeMappingMap(ldapServer.AttributeMappingItems, ldapServer.EnableCaseInsensitivity)
		SearchAttributes = append(SearchAttributes, attributeMappingMap.Keys()...)
	}

	ldapFilter := ldapServer.Filter
	if selectedUser != nil {
		ldapFilter = ldapServer.buildAuthFilterString(selectedUser)
	}

	searchReq := goldap.NewSearchRequest(ldapServer.BaseDn, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false,
		ldapFilter, SearchAttributes, nil)
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
			unmappedAttributes := MapAttributesToUser(entry, &user, attributeMappingMap, ldapServer.EnableCaseInsensitivity)
			if len(unmappedAttributes) > 0 {
				rb.AddReason(fmt.Sprintf("User (%s) has unmapped attributes: %s", entry.DN, strings.Join(unmappedAttributes, ", ")))
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

func AutoAdjustLdapUser(users []LdapUser) []LdapUser {
	res := make([]LdapUser, len(users))
	for i, user := range users {
		res[i] = LdapUser{
			UidNumber:             user.UidNumber,
			Uid:                   user.Uid,
			Cn:                    user.Cn,
			GroupId:               user.GidNumber,
			Uuid:                  user.GetLdapUuid(),
			DisplayName:           user.DisplayName,
			Email:                 util.ReturnAnyNotEmpty(user.Email, user.EmailAddress, user.Mail),
			Mobile:                util.ReturnAnyNotEmpty(user.Mobile, user.MobileTelephoneNumber, user.TelephoneNumber),
			MobileTelephoneNumber: user.MobileTelephoneNumber,
			RegisteredAddress:     util.ReturnAnyNotEmpty(user.PostalAddress, user.RegisteredAddress),
			Address:               user.Address,
			Roles:                 user.Roles,
		}
	}
	return res
}

type SyncLdapUsersResult struct {
	Added   []LdapUser
	Failed  []LdapUser
	Updated []LdapUser
	Exist   []LdapUser
}

type LdapSyncCommand struct {
	LdapUsers      []LdapUser
	LdapId         string
	Reason         string
	SyncedByUserID string
}

// SyncLdapUsers
// Read users from LDAP server and sync them to database, applying role mapping and attribute mapping if set.
func SyncLdapUsers(
	ctx context.Context,
	command LdapSyncCommand,
) (SyncLdapUsersResult, error) {
	historyEntry := ldap_sync.LdapSyncHistory{
		LdapID:         command.LdapId,
		StartedAt:      time.Now().UTC(),
		Reason:         command.Reason,
		SyncedByUserID: command.SyncedByUserID,
	}
	var err error
	syncDetails := SyncLdapUsersResult{
		Added:   make([]LdapUser, 0),
		Failed:  make([]LdapUser, 0),
		Updated: make([]LdapUser, 0),
		Exist:   make([]LdapUser, 0),
	}
	repository := ldap_sync.LdapSyncRepository{}
	ldapSyncID, err := repository.LockLDAPForSync(command.LdapId)
	if err != nil {
		err = errors.Wrap(err, "LDAP sync error: failed to lock LDAP for sync")

		return syncDetails, err
	}
	historyEntry.LdapSyncID = ldapSyncID
	updatedUsers := make(map[string]LdapUser)
	err = trm.WithTx(ctx, func(ctx context.Context) error {
		ldap, err := GetLdap(command.LdapId)
		if err != nil {
			err = errors.Wrap(err, "LDAP sync error: failed to GetLdap for sync")
			return err
		}
		var uuids []string
		for _, user := range command.LdapUsers {
			uuids = append(uuids, user.GetLdapUuid())
		}
		existUuids, err := GetExistUuids(ldap.Owner, uuids)
		if err != nil {
			err = errors.Wrap(err, "LDAP sync error: failed to GetExistUuids for sync")
			return err
		}
		existUuidsMap := make(map[string]bool)
		for _, uuid := range existUuids {
			existUuidsMap[uuid] = true
		}
		organization, err := getOrganization("admin", ldap.Owner)
		if err != nil {
			err = errors.Wrap(err, "LDAP sync error: failed to getOrganization for sync")
			return err
		}

		var dc []string
		for _, basedn := range strings.Split(ldap.BaseDn, ",") {
			if strings.Contains(basedn, "dc=") {
				dc = append(dc, basedn[3:])
			}
		}
		affiliation := strings.Join(dc, ".")

		var ou []string
		for _, admin := range strings.Split(ldap.Username, ",") {
			if strings.Contains(admin, "ou=") {
				ou = append(ou, admin[3:])
			}
		}
		tag := strings.Join(ou, ".")

		for _, ldapUser := range command.LdapUsers {
			userExists := false
			if len(existUuids) > 0 {
				userExists = existUuidsMap[ldapUser.Uuid]
				if userExists {
					syncDetails.Exist = append(syncDetails.Exist, ldapUser)
				}
			}

			name, err := ldapUser.ldapUserNameFromDatabase()
			if err != nil {
				return errors.Wrap(err, "ldapUserNameFromDatabase")
			}

			if !userExists {
				score, err := organization.GetInitScore()
				if err != nil {
					err = errors.Wrap(err, "LDAP sync error: failed to GetInitScore for sync")
					return errors.Wrap(err, "GetInitScore")
				}

				newUser := &User{
					Owner:             ldap.Owner,
					Name:              name,
					CreatedTime:       util.GetCurrentTime(),
					DisplayName:       ldapUser.buildLdapDisplayName(),
					SignupApplication: organization.DefaultApplication,
					Type:              "normal-user",
					Avatar:            organization.DefaultAvatar,
					Email:             ldapUser.Email,
					Phone:             ldapUser.Mobile,
					Address:           []string{ldapUser.Address},
					Affiliation:       affiliation,
					Tag:               tag,
					Score:             score,
					Ldap:              ldapUser.Uuid,
					Properties:        map[string]string{},
					MappingStrategy:   ldap.UserMappingStrategy,
				}

				if organization.DefaultApplication != "" {
					newUser.SignupApplication = organization.DefaultApplication
				}

				affected, err := AddUser(ctx, newUser)
				if err != nil {
					err = errors.Wrap(err, "LDAP sync error: failed to AddUser")
					return err
				}

				if !affected {
					syncDetails.Failed = append(syncDetails.Failed, ldapUser)
					continue
				}

				userIdProvider := &UserIdProvider{
					Owner:           organization.Name,
					LdapId:          command.LdapId,
					UsernameFromIdp: ldapUser.Uuid,
					CreatedTime:     util.GetCurrentTime(),
					UserId:          newUser.Id,
				}
				_, err = AddUserIdProvider(context.Background(), userIdProvider)
				if err != nil {
					err = errors.Wrap(err, "LDAP sync error: failed to AddUserIdProvider")
					return err
				}
				syncDetails.Added = append(syncDetails.Added, ldapUser)
			}

			if userExists && ldap.EnableAttributeMapping {
				err = SyncLdapAttributes(ldapUser, name, ldap.Owner)
				if err != nil {
					return errors.Wrap(err, "SyncLdapAttributes")
				}
				updatedUsers[ldapUser.Uuid] = ldapUser
			}

			if ldap.EnableRoleMapping {
				err = SyncLdapRoles(ldapUser, name, ldap.Owner)
				if err != nil {
					return errors.Wrap(err, "SyncLdapRoles")
				}
				updatedUsers[ldapUser.Uuid] = ldapUser
			}
		}

		err = UpdateLdapSyncTime(command.LdapId)
		if err != nil {
			err = errors.Wrap(err, "UpdateLdapSyncTime")
			return err
		}

		return nil
	})
	if err != nil {
		return syncDetails, errors.Wrap(err, "ldap user sync transaction failed")
	}
	for _, updatedUser := range updatedUsers {
		syncDetails.Updated = append(syncDetails.Updated, updatedUser)
	}
	err = repository.UnlockLDAPForSync(command.LdapId)
	historyEntry.EndedAt = time.Now().UTC()
	_, err = orm.AppOrmer.Engine.Insert(SetSyncHistoryUsers(historyEntry, syncDetails))
	if err != nil {
		return syncDetails, errors.Wrap(err, "failed to save LDAP sync history result")
	}

	return syncDetails, err
}

func SetSyncHistoryUsers(historyEntry ldap_sync.LdapSyncHistory, result SyncLdapUsersResult) ldap_sync.LdapSyncHistory {
	for _, user := range result.Added {
		historyEntry.Result = append(historyEntry.Result, ldap_sync.LdapSyncHistoryUser{Action: "added", UUID: user.GetLdapUuid()})
	}
	for _, user := range result.Updated {
		historyEntry.Result = append(historyEntry.Result, ldap_sync.LdapSyncHistoryUser{Action: "updated", UUID: user.GetLdapUuid()})
	}
	for _, user := range result.Failed {
		historyEntry.Result = append(historyEntry.Result, ldap_sync.LdapSyncHistoryUser{Action: "failed", UUID: user.GetLdapUuid()})
	}

	return historyEntry
}

func GetExistUuids(owner string, uuids []string) ([]string, error) {
	var existUuids []string

	err := orm.AppOrmer.Engine.Table("user").Where("owner = ?", owner).Cols("ldap").
		In("ldap", uuids).Select("DISTINCT ldap").Find(&existUuids)
	if err != nil {
		return existUuids, err
	}

	return existUuids, nil
}

func (ldapUser *LdapUser) ldapUserNameFromDatabase() (string, error) {
	user := User{}
	uidWithNumber := fmt.Sprintf("%s_%s", ldapUser.Uid, ldapUser.UidNumber)
	has, err := orm.AppOrmer.Engine.Where("name = ? or name = ?", ldapUser.Uid, uidWithNumber).Get(&user)
	if err != nil {
		return "", err
	}

	if has {
		if user.Ldap == ldapUser.Uuid {
			return user.Name, nil
		}
		if user.Name == ldapUser.Uid {
			return uidWithNumber, nil
		}
		return fmt.Sprintf("%s_%s", uidWithNumber, randstr.Hex(6)), nil
	}

	if ldapUser.Uid != "" {
		return ldapUser.Uid, nil
	}

	return ldapUser.Cn, nil
}

func (ldapUser *LdapUser) buildLdapDisplayName() string {
	if ldapUser.DisplayName != "" {
		return ldapUser.DisplayName
	}

	return ldapUser.Cn
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

func (ldap *Ldap) buildAuthFilterString(user *User) string {
	if len(ldap.FilterFields) == 0 {
		return fmt.Sprintf("(&%s(uid=%s))", ldap.Filter, user.Name)
	}

	filter := fmt.Sprintf("(&%s(|", ldap.Filter)
	for _, field := range ldap.FilterFields {
		filter = fmt.Sprintf("%s(%s=%s)", filter, field, user.getFieldFromLdapAttribute(field))
	}
	filter = fmt.Sprintf("%s))", filter)

	return filter
}

func (user *User) getFieldFromLdapAttribute(attribute string) string {
	switch attribute {
	case "uid":
		return user.Name
	case "sAMAccountName":
		return user.Name
	case "mail":
		return user.Email
	case "mobile":
		return user.Phone
	case "userPrincipalName":
		return user.Email
	default:
		return ""
	}
}

func SyncUserFromLdap(ctx context.Context, organization string, ldapId string, userName string, password string, lang string, rb *RecordBuilder) (*LdapUser, error) {
	ldaps, err := GetLdaps(organization)
	if err != nil {
		return nil, err
	}

	user := &User{
		Name: userName,
	}

	for _, ldapServer := range ldaps {
		if len(ldapId) > 0 && ldapServer.Id != ldapId {
			continue
		}

		conn, err := ldapServer.GetLdapConn(context.Background())
		if err != nil {
			continue
		}

		res, _ := conn.GetLdapUsers(ldapServer, user, rb)
		if len(res) == 0 {
			conn.Close()
			continue
		}

		_, err = CheckLdapUserPassword(user, password, lang, ldapId)
		if err != nil {
			conn.Close()
			return nil, err
		}

		_, err = SyncLdapUsers(ctx, LdapSyncCommand{LdapUsers: AutoAdjustLdapUser(res), SyncedByUserID: userName, LdapId: ldapServer.Id, Reason: "manual"})
		return &res[0], err
	}

	return nil, nil
}
