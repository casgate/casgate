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
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/casdoor/casdoor/ldap_sync"
	"github.com/casdoor/casdoor/orm"
	"github.com/casdoor/casdoor/util/logger"

	"github.com/casdoor/casdoor/util"
)

func AutoAdjustLdapUser(users []ldap_sync.LdapUser) []ldap_sync.LdapUser {
	res := make([]ldap_sync.LdapUser, len(users))
	for i, user := range users {
		res[i] = ldap_sync.LdapUser{
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
	Added   []ldap_sync.LdapUser
	Failed  map[string]ldap_sync.LdapUser
	Updated map[string]ldap_sync.LdapUser
	Exist   []ldap_sync.LdapUser
}

type LdapSyncCommand struct {
	LdapUsers      []ldap_sync.LdapUser
	LdapId         string
	Reason         string
	SyncedByUserID string
}

// SyncLdapUsers
// Read users from LDAP server and sync them to database, applying role mapping and attribute mapping if set.
func SyncLdapUsers(
	ctx context.Context,
	command LdapSyncCommand,
) (*SyncLdapUsersResult, error) {
	var err error
	historyEntry := ldap_sync.LdapSyncHistory{
		LdapID:         command.LdapId,
		StartedAt:      time.Now().UTC(),
		Reason:         command.Reason,
		SyncedByUserID: command.SyncedByUserID,
	}
	syncDetails := &SyncLdapUsersResult{
		Added:   make([]ldap_sync.LdapUser, 0),
		Failed:  make(map[string]ldap_sync.LdapUser),
		Updated: make(map[string]ldap_sync.LdapUser),
		Exist:   make([]ldap_sync.LdapUser, 0),
	}
	ldap, err := GetLdap(command.LdapId)
	if err != nil {
		err = errors.Wrap(err, "LDAP sync error: failed to GetLdap for sync")
		return syncDetails, err
	}
	locker := ldap_sync.LdapSyncLocker{}
	ldapSyncID, err := locker.LockLDAPForSync(command.LdapId)
	if err != nil {
		err = errors.Wrap(err, "LDAP sync error: failed to lock LDAP for sync")
		return syncDetails, err
	}
	historyEntry.LdapSyncID = ldapSyncID

	var uuids []string
	for _, user := range command.LdapUsers {
		uuids = append(uuids, user.GetLdapUuid())
	}
	existUuids, err := GetExistUuids(ldap.Owner, uuids)
	if err != nil {
		err = errors.Wrap(err, "LDAP sync error: failed to GetExistUuids for sync")
		return syncDetails, err
	}
	existUuidsMap := make(map[string]bool)
	for _, uuid := range existUuids {
		existUuidsMap[uuid] = true
	}
	organization, err := getOrganization("admin", ldap.Owner)
	if err != nil {
		err = errors.Wrap(err, "LDAP sync error: failed to getOrganization for sync")
		return syncDetails, err
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
		userSyncError := SyncSingle(
			ctx,
			command,
			existUuidsMap,
			ldapUser,
			syncDetails,
			organization,
			ldap,
			affiliation,
			tag,
		)
		if userSyncError != nil {
			if command.Reason == ldap_sync.LdapSyncReasonManual {
				logger.SetItem(ctx, "usr", command.SyncedByUserID)
			}
			logger.Error(
				ctx,
				"user sync error",
				"error", userSyncError,
				"ldap_user_id", ldapUser.GetLdapUuid(),
				"ldap_id", ldap.Id,
				"ldap_owner", ldap.Owner,
				"act", logger.OperationNameLdapSyncUsers,
				"r", logger.OperationResultFailure,
			)
		}
	}

	err = UpdateLdapSyncTime(command.LdapId)
	if err != nil {
		err = errors.Wrap(err, "UpdateLdapSyncTime")
		return syncDetails, err
	}

	err = locker.UnlockLDAPForSync(command.LdapId)
	historyEntry.EndedAt = time.Now().UTC()
	_, err = orm.AppOrmer.Engine.Insert(SetSyncHistoryUsers(historyEntry, syncDetails))
	if err != nil {
		return syncDetails, errors.Wrap(err, "failed to save LDAP sync history result")
	}

	return syncDetails, err
}

func SyncSingle(
	ctx context.Context,
	command LdapSyncCommand,
	existUuidsMap map[string]bool,
	ldapUser ldap_sync.LdapUser,
	syncDetails *SyncLdapUsersResult,
	organization *Organization,
	ldap *ldap_sync.Ldap,
	affiliation string,
	tag string,
) error {
	userExists := false
	userExists = existUuidsMap[ldapUser.Uuid]
	if userExists {
		syncDetails.Exist = append(syncDetails.Exist, ldapUser)
	}

	name, err := ldapUser.LdapUserNameFromDatabase()
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
			DisplayName:       ldapUser.BuildLdapDisplayName(),
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
			syncDetails.Failed[ldapUser.Uuid] = ldapUser
			err = errors.Wrap(err, "LDAP sync error: failed to AddUser")
			return err
		}

		if !affected {
			syncDetails.Failed[ldapUser.Uuid] = ldapUser
			return errors.New("LDAP sync error: failed to AddUser")
		}

		userIdProvider := &UserIdProvider{
			Owner:           organization.Name,
			LdapId:          command.LdapId,
			UsernameFromIdp: ldapUser.Uuid,
			CreatedTime:     util.GetCurrentTime(),
			UserId:          newUser.Id,
		}
		_, err = AddUserIdProvider(ctx, userIdProvider)
		if err != nil {
			syncDetails.Failed[ldapUser.Uuid] = ldapUser
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
		syncDetails.Updated[ldapUser.Uuid] = ldapUser
	}

	if ldap.EnableRoleMapping {
		err = SyncLdapRoles(ldapUser, name, ldap.Owner)
		if err != nil {
			return errors.Wrap(err, "SyncLdapRoles")
		}
		syncDetails.Updated[ldapUser.Uuid] = ldapUser
	}
	return nil
}

func SetSyncHistoryUsers(
	historyEntry ldap_sync.LdapSyncHistory,
	result *SyncLdapUsersResult,
) ldap_sync.LdapSyncHistory {
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

func (user *User) GetFieldByLdapAttribute(attribute string) string {
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

func SyncLdapUserOnSignIn(
	ctx context.Context,
	organization string,
	ldapId string,
	userName string,
	password string,
	lang string,
	rb *RecordBuilder,
) (*ldap_sync.LdapUser, error) {
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

		conn, err := ldap_sync.GetLdapConn(context.Background(), ldapServer)
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

		_, err = SyncLdapUsers(
			ctx,
			LdapSyncCommand{
				LdapUsers:      AutoAdjustLdapUser(res),
				SyncedByUserID: userName,
				LdapId:         ldapServer.Id,
				Reason:         ldap_sync.LdapSyncReasonManual,
			},
		)
		return &res[0], err
	}

	return nil, nil
}
