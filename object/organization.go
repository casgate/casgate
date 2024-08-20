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
	"context"
	"fmt"
	"strconv"

	"github.com/casdoor/casdoor/orm"

	"github.com/xorm-io/builder"
	"github.com/xorm-io/core"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/cred"
	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/util"
)

const DefaultOrganizationPasswordSpecialChars = `~!@#$%^&*_\-+=` + "`" + `|(){}[]:;"'<>,.?/`

type AccountItem struct {
	Name       string `json:"name"`
	Visible    bool   `json:"visible"`
	ViewRule   string `json:"viewRule"`
	ModifyRule string `json:"modifyRule"`
}

type ThemeData struct {
	ThemeType    string `xorm:"varchar(30)" json:"themeType"`
	ColorPrimary string `xorm:"varchar(10)" json:"colorPrimary"`
	BorderRadius int    `xorm:"int" json:"borderRadius"`
	IsCompact    bool   `xorm:"bool" json:"isCompact"`
	IsEnabled    bool   `xorm:"bool" json:"isEnabled"`
}

type MfaItem struct {
	Name string `json:"name"`
	Rule string `json:"rule"`
}

type Organization struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	DisplayName            string     `xorm:"varchar(100)" json:"displayName"`
	WebsiteUrl             string     `xorm:"varchar(100)" json:"websiteUrl"`
	Favicon                string     `xorm:"varchar(100)" json:"favicon"`
	PasswordType           string     `xorm:"varchar(100)" json:"passwordType"`
	PasswordSalt           string     `xorm:"varchar(100)" json:"passwordSalt"`
	PasswordOptions        []string   `xorm:"varchar(100)" json:"passwordOptions"`
	PasswordChangeInterval int        `json:"passwordChangeInterval"`
	PasswordMaxLength      int        `json:"passwordMaxLength"`
	PasswordMinLength      int        `json:"passwordMinLength"`
	CountryCodes           []string   `xorm:"varchar(200)"  json:"countryCodes"`
	DefaultAvatar          string     `xorm:"varchar(200)" json:"defaultAvatar"`
	DefaultApplication     string     `xorm:"varchar(100)" json:"defaultApplication"`
	Tags                   []string   `xorm:"mediumtext" json:"tags"`
	Languages              []string   `xorm:"varchar(255)" json:"languages"`
	ThemeData              *ThemeData `xorm:"json" json:"themeData"`
	MasterPassword         string     `xorm:"varchar(100)" json:"masterPassword"`
	InitScore              int        `json:"initScore"`
	EnableSoftDeletion     bool       `json:"enableSoftDeletion"`
	IsProfilePublic        bool       `json:"isProfilePublic"`
	PasswordSpecialChars   string     `xorm:"mediumtext" json:"passwordSpecialChars"`

	MfaItems     []*MfaItem     `xorm:"varchar(300)" json:"mfaItems"`
	AccountItems []*AccountItem `xorm:"varchar(5000)" json:"accountItems"`
}

func GetOrganizationCount(owner, field, value string) (int64, error) {
	session := orm.GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Organization{})
}

func GetOrganizations(owner string, name ...string) ([]*Organization, error) {
	organizations := []*Organization{}
	if name != nil && len(name) > 0 {
		err := orm.AppOrmer.Engine.Desc("created_time").Where(builder.In("name", name)).Find(&organizations)
		if err != nil {
			return nil, err
		}
	} else {
		err := orm.AppOrmer.Engine.Desc("created_time").Find(&organizations, &Organization{Owner: owner})
		if err != nil {
			return nil, err
		}
	}

	return organizations, nil
}

func GetOrganizationsByFields(owner string, fields ...string) ([]*Organization, error) {
	organizations := []*Organization{}
	err := orm.AppOrmer.Engine.Desc("created_time").Cols(fields...).Find(&organizations, &Organization{Owner: owner})
	if err != nil {
		return nil, err
	}

	return organizations, nil
}

func GetPaginationOrganizations(owner string, name string, offset, limit int, field, value, sortField, sortOrder string) ([]*Organization, error) {
	organizations := []*Organization{}
	session := orm.GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	var err error
	if name != "" {
		err = session.Find(&organizations, &Organization{Name: name})
	} else {
		err = session.Find(&organizations)
	}
	if err != nil {
		return nil, err
	}

	return organizations, nil
}

func getOrganization(owner string, name string) (*Organization, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	organization := Organization{Owner: owner, Name: name}
	existed, err := orm.AppOrmer.Engine.Get(&organization)
	if err != nil {
		return nil, err
	}

	if existed {
		return &organization, nil
	}

	return nil, nil
}

func GetOrganization(id string) (*Organization, error) {
	owner, name, err := util.GetOwnerAndNameFromId(id)
	if err != nil {
		return nil, err
	}
	return getOrganization(owner, name)
}

func GetMaskedOrganization(organization *Organization, errs ...error) (*Organization, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	if organization == nil {
		return nil, nil
	}

	if organization.MasterPassword != "" {
		organization.MasterPassword = "***"
	}
	return organization, nil
}

func GetMaskedOrganizations(organizations []*Organization, errs ...error) ([]*Organization, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	var err error
	for _, organization := range organizations {
		organization, err = GetMaskedOrganization(organization)
		if err != nil {
			return nil, err
		}
	}

	return organizations, nil
}

func UpdateOrganization(ctx context.Context, id string, organization *Organization, lang string) (bool, error) {
	var affected int64
	err := trm.WithTx(ctx, func(ctx context.Context) error {
		owner, name, err := util.GetOwnerAndNameFromId(id)
		if err != nil {
			return err
		}
		org, err := repo.GetOrganization(ctx, owner, name, true)
		if err != nil {
			return err
		}
		if org == nil {
			return nil
		}

		if name == "built-in" {
			organization.Name = name
		}

		if name != organization.Name {
			err := organizationChangeTrigger(ctx, name, organization.Name)
			if err != nil {
				return err
			}
		}

		if org.PasswordChangeInterval != organization.PasswordChangeInterval {
			err = updateOrganizationUsersPasswordChangeTime(ctx, organization.Name, org.PasswordChangeInterval, organization.PasswordChangeInterval)
			if err != nil {
				return err
			}
		}

		if organization.MasterPassword != "" && organization.MasterPassword != "***" {
			credManager := cred.GetCredManager(organization.PasswordType)
			if credManager != nil {
				hashedPassword := credManager.GetHashedPassword(organization.MasterPassword, organization.PasswordSalt)
				organization.MasterPassword = hashedPassword
			}
		}
		if organization.MasterPassword == "***" {
			organization.MasterPassword = org.MasterPassword
		}

		err = checkPasswordLength(organization, lang)
		if err != nil {
			return err
		}

		err = checkSpecialCharsIsFilled(organization, lang)
		if err != nil {
			return err
		}

		affected, err = repo.UpdateOrganization(ctx, owner, name, organization)
		if err != nil {
			return err
		}
		return nil
	})

	return affected != 0, err
}

func AddOrganization(organization *Organization) (bool, error) {
	if organization.PasswordMaxLength <= 0 {
		maxLen, err := GetUserTablePasswordMaxLength()
		if err != nil {
			return false, err
		}
		organization.PasswordMaxLength = maxLen
	}
	if organization.PasswordMinLength <= 0 {
		organization.PasswordMinLength = 1
	}
	if organization.PasswordSpecialChars == "" {
		organization.PasswordSpecialChars = DefaultOrganizationPasswordSpecialChars
	}
	affected, err := orm.AppOrmer.Engine.Insert(organization)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteOrganization(lang string, organization *Organization) (bool, error) {
	if organization.Name == "built-in" {
		return false, nil
	}

	hasDependencies, err := HasOrganizationDependencies(organization.Name)
	if err != nil {
		return false, err
	}

	if hasDependencies {
		return false, fmt.Errorf(i18n.Translate(lang, "util:The organization %s has dependencies and cannot be deleted"), organization.DisplayName)
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{organization.Owner, organization.Name}).Delete(&Organization{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func GetOrganizationByUser(user *User) (*Organization, error) {
	if user == nil {
		return nil, nil
	}

	return getOrganization("admin", user.Owner)
}

func GetAccountItemByName(name string, organization *Organization) *AccountItem {
	if organization == nil {
		return nil
	}
	for _, accountItem := range organization.AccountItems {
		if accountItem.Name == name {
			return accountItem
		}
	}
	return nil
}

func CheckAccountItemModifyRule(accountItem *AccountItem, isAdmin bool, lang string) (bool, string) {
	if accountItem == nil {
		return true, ""
	}

	switch accountItem.ModifyRule {
	case "Admin":
		if !isAdmin {
			return false, fmt.Sprintf(i18n.Translate(lang, "organization:Only admin can modify the %s."), accountItem.Name)
		}
	case "Immutable":
		return false, fmt.Sprintf(i18n.Translate(lang, "organization:The %s is immutable."), accountItem.Name)
	case "Self":
		break
	default:
		return false, fmt.Sprintf(i18n.Translate(lang, "organization:Unknown modify rule %s."), accountItem.ModifyRule)
	}
	return true, ""
}

func GetDefaultApplication(ctx context.Context, id string) (*Application, error) {
	organization, err := GetOrganization(id)
	if err != nil {
		return nil, err
	}

	if organization == nil {
		return nil, fmt.Errorf("The organization: %s does not exist", id)
	}

	if organization.DefaultApplication != "" {
		defaultApplication, err := getApplication(ctx, "admin", organization.DefaultApplication, nil)
		if err != nil {
			return nil, err
		}

		if defaultApplication == nil {
			return nil, fmt.Errorf("The default application: %s does not exist", organization.DefaultApplication)
		} else {
			return defaultApplication, nil
		}
	}

	applications := []*Application{}
	err = orm.AppOrmer.Engine.Asc("created_time").Find(&applications, &Application{Organization: organization.Name})
	if err != nil {
		return nil, err
	}

	if len(applications) == 0 {
		return nil, fmt.Errorf("The application does not exist")
	}

	defaultApplication := applications[0]
	for _, application := range applications {
		if application.EnableInternalSignUp || application.EnableIdpSignUp {
			defaultApplication = application
			break
		}
	}

	err = extendApplicationWithProviders(ctx, defaultApplication, false)
	if err != nil {
		return nil, err
	}

	err = extendApplicationWithOrg(defaultApplication)
	if err != nil {
		return nil, err
	}

	return defaultApplication, nil
}

func organizationChangeTrigger(ctx context.Context, oldName string, newName string) error {
	err := repo.UpdateEntitiesFieldValue(ctx, "application", "organization", newName, map[string]interface{}{"organization": oldName})
	if err != nil {
		return err
	}

	err = repo.UpdateEntitiesFieldValue(ctx, "user", "owner", newName, map[string]interface{}{"owner": oldName})
	if err != nil {
		return err
	}

	err = repo.UpdateEntitiesFieldValue(ctx, "group", "owner", newName, map[string]interface{}{"owner": oldName})
	if err != nil {
		return err
	}

	roles, err := repo.GetRoles(ctx, oldName)
	if err != nil {
		return err
	}

	for _, role := range roles {
		for i, u := range role.Users {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(u)
			if err != nil {
				return err
			}
			if owner == oldName {
				role.Users[i] = util.GetId(newName, name)
			}
		}
		for i, u := range role.Roles {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(u)
			if err != nil {
				return err
			}
			if owner == oldName {
				role.Roles[i] = util.GetId(newName, name)
			}
		}
		for i, g := range role.Groups {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(g)
			if err != nil {
				return err
			}
			if owner == oldName {
				role.Groups[i] = util.GetId(newName, name)
			}
		}
		for i, d := range role.Domains {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(d)
			if err != nil {
				return err
			}
			if owner == oldName {
				role.Domains[i] = util.GetId(newName, name)
			}
		}

		role.Owner = newName
		_, err = repo.UpdateRole(ctx, oldName, role.Name, role)
		if err != nil {
			return err
		}
	}

	permissions, err := repo.GetPermissions(ctx, oldName)
	if err != nil {
		return err
	}

	for _, permission := range permissions {
		for i, u := range permission.Users {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(u)
			if err != nil {
				return err
			}
			if owner == oldName {
				permission.Users[i] = util.GetId(newName, name)
			}
		}
		for i, u := range permission.Roles {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(u)
			if err != nil {
				return err
			}
			if owner == oldName {
				permission.Roles[i] = util.GetId(newName, name)
			}
		}
		for i, g := range permission.Groups {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(g)
			if err != nil {
				return err
			}
			if owner == oldName {
				permission.Groups[i] = util.GetId(newName, name)
			}
		}
		for i, d := range permission.Domains {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(d)
			if err != nil {
				return err
			}
			if owner == oldName {
				permission.Domains[i] = util.GetId(newName, name)
			}
		}
		permission.Owner = newName
		_, err = repo.UpdatePermission(ctx, oldName, permission.Name, permission)
		if err != nil {
			return err
		}
	}

	domains, err := repo.GetDomains(ctx, oldName)
	if err != nil {
		return err
	}

	for _, domain := range domains {
		for i, u := range domain.Domains {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(u)
			if err != nil {
				return err
			}
			if owner == oldName {
				domain.Domains[i] = util.GetId(newName, name)
			}
		}
		domain.Owner = newName
		_, err = repo.UpdateDomain(ctx, oldName, domain.Name, domain)
		if err != nil {
			return err
		}
	}

	err = repo.UpdateEntitiesFieldValue(ctx, "adapter", "owner", newName, map[string]interface{}{"owner": oldName})
	if err != nil {
		return err
	}

	err = repo.UpdateEntitiesFieldValue(ctx, "ldap", "owner", newName, map[string]interface{}{"owner": oldName})
	if err != nil {
		return err
	}

	err = repo.UpdateEntitiesFieldValue(ctx, "model", "owner", newName, map[string]interface{}{"owner": oldName})
	if err != nil {
		return err
	}

	err = repo.UpdateEntitiesFieldValue(ctx, "token", "organization", newName, map[string]interface{}{"organization": oldName})
	if err != nil {
		return err
	}

	err = repo.UpdateEntitiesFieldValue(ctx, "webhook", "organization", newName, map[string]interface{}{"organization": oldName})
	if err != nil {
		return err
	}

	return nil
}

func IsNeedPromptMfa(org *Organization, user *User) bool {
	if org == nil || user == nil {
		return false
	}
	for _, item := range org.MfaItems {
		if item.Rule == "Required" {
			if item.Name == EmailType && !user.MfaEmailEnabled {
				return true
			}
			if item.Name == SmsType && !user.MfaPhoneEnabled {
				return true
			}
			if item.Name == TotpType && user.TotpSecret == "" {
				return true
			}
		}
	}
	return false
}

func (org *Organization) GetInitScore() (int, error) {
	if org != nil {
		return org.InitScore, nil
	} else {
		return strconv.Atoi(conf.GetConfigString("initScore"))
	}
}

func updateOrganizationUsersPasswordChangeTime(ctx context.Context, owner string, oldInterval int, newInterval int) error {
	if newInterval == 0 {
		err := repo.ResetUsersPasswordChangeTime(ctx, owner)
		if err != nil {
			return fmt.Errorf("repo.ResetUsersPasswordChangeTime: %w", err)
		}
	} else {
		users, err := repo.GetUsersWithoutRequiredPasswordChange(ctx, owner)
		if err != nil {
			return fmt.Errorf("repo.GetUsersWithoutRequiredPasswordChange: %w", err)
		}
		for _, user := range users {
			if user.PasswordChangeTime.IsZero() {
				user.PasswordChangeTime = getNextPasswordChangeTime(newInterval)
			} else {
				user.PasswordChangeTime = user.PasswordChangeTime.
					Add(-1 * getIntervalFromdays(oldInterval)).
					Add(getIntervalFromdays(newInterval))
			}

			err := repo.UpdateUserPasswordChangeTime(ctx, user)
			if err != nil {
				return fmt.Errorf("repo.UpdateUserPasswordChangeTime: %w", err)
			}
		}
	}
	return nil
}

func checkPasswordLength(org *Organization, lang string) error {
	maxLen, err := GetUserTablePasswordMaxLength()
	minLen := 1
	if err != nil {
		return err
	}
	if org.PasswordMaxLength == 0 && org.PasswordMinLength == 0 {
		org.PasswordMaxLength = maxLen
		org.PasswordMinLength = 1
		return nil
	}
	if maxLen < org.PasswordMaxLength || org.PasswordMinLength < minLen {
		return fmt.Errorf(i18n.Translate(lang, "check:The password must be between %d and %d characters long"), minLen, maxLen)
	}
	return nil
}

func checkSpecialCharsIsFilled(org *Organization, lang string) error {
	for _, opt := range org.PasswordOptions {
		if opt == "SpecialChar" {
			if len(org.PasswordSpecialChars) == 0 {
				return fmt.Errorf(i18n.Translate(
					lang, "check:You must fill 'Password special chars' if option 'The password must contain at least one special character' was set on",
				))
			}
		}
	}
	return nil
}
