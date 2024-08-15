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
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/casdoor/casdoor/cred"
	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/util"
)

type CheckUserPasswordOptions struct {
	Lang                      string
	LdapId                    string
	EnableCaptcha             bool
	IsSigninViaLdap           bool
	IsPasswordWithLdapEnabled bool
}

const (
	SigninWrongTimesLimit     = 4
	LastSignWrongTimeDuration = time.Minute * 5

	DefaultFailedSigninLimit      = 5
	DefaultFailedSigninFrozenTime = 15

	builtInOrganization = "built-in"
)

func CheckUserSignup(application *Application, organization *Organization, form *form.AuthForm, lang string) string {
	if organization == nil {
		return i18n.Translate(lang, "check:Organization does not exist")
	}

	if application.IsSignupItemVisible("Username") {
		if len(form.Username) <= 1 {
			return i18n.Translate(lang, "check:Username must have at least 2 characters")
		}
		if unicode.IsDigit(rune(form.Username[0])) {
			return i18n.Translate(lang, "check:Username cannot start with a digit")
		}
		if util.ReWhiteSpace.MatchString(form.Username) {
			return i18n.Translate(lang, "check:Username cannot contain white spaces")
		}

		if msg := CheckUsername(form.Username, lang); msg != "" {
			return msg
		}

		if form.Id == "" && HasUserByField(organization.Name, "name", form.Username) {
			return i18n.Translate(lang, "check:Username already exists")
		}
		if form.Id == "" && HasUserByField(organization.Name, "email", form.Email) {
			return i18n.Translate(lang, "check:Email already exists")
		}
		if HasUserByField(organization.Name, "phone", form.Phone) {
			return i18n.Translate(lang, "check:Phone already exists")
		}
	}

	if application.IsSignupItemVisible("Password") {
		msg := CheckPasswordComplexityByOrg(organization, form.Password, lang)
		if msg != "" {
			return msg
		}
	}

	if application.IsSignupItemVisible("Email") {
		if form.Email == "" {
			if application.IsSignupItemRequired("Email") {
				return i18n.Translate(lang, "check:Email cannot be empty")
			}
		} else {
			if form.Id == "" && HasUserByField(organization.Name, "email", form.Email) {
				return i18n.Translate(lang, "check:Email already exists")
			} else if !util.IsEmailValid(form.Email) {
				return i18n.Translate(lang, "check:Email is invalid")
			}
		}
	}

	if application.IsSignupItemVisible("Phone") {
		if form.Phone == "" {
			if application.IsSignupItemRequired("Phone") {
				return i18n.Translate(lang, "check:Phone cannot be empty")
			}
		} else {
			if HasUserByField(organization.Name, "phone", form.Phone) {
				return i18n.Translate(lang, "check:Phone already exists")
			} else if !util.IsPhoneAllowInRegin(form.CountryCode, organization.CountryCodes) {
				return i18n.Translate(lang, "check:Your region is not allow to signup by phone")
			} else if !util.IsPhoneValid(form.Phone, form.CountryCode) {
				return i18n.Translate(lang, "check:Phone number is invalid")
			}
		}
	}

	if application.IsSignupItemVisible("Display name") {
		if application.GetSignupItemRule("Display name") == "First, last" && (form.FirstName != "" || form.LastName != "") {
			if form.FirstName == "" {
				return i18n.Translate(lang, "check:FirstName cannot be blank")
			} else if form.LastName == "" {
				return i18n.Translate(lang, "check:LastName cannot be blank")
			}
		} else {
			if form.Name == "" {
				return i18n.Translate(lang, "check:DisplayName cannot be blank")
			} else if application.GetSignupItemRule("Display name") == "Real name" {
				if !isValidRealName(form.Name) {
					return i18n.Translate(lang, "check:DisplayName is not valid real name")
				}
			}
		}
	}

	if application.IsSignupItemVisible("Affiliation") {
		if form.Affiliation == "" {
			return i18n.Translate(lang, "check:Affiliation cannot be blank")
		}
	}

	if len(application.InvitationCodes) > 0 {
		if form.InvitationCode == "" {
			if application.IsSignupItemRequired("Invitation code") {
				return i18n.Translate(lang, "check:Invitation code cannot be blank")
			}
		} else {
			if !util.InSlice(application.InvitationCodes, form.InvitationCode) {
				return i18n.Translate(lang, "check:Invitation code is invalid")
			}
		}
	}

	return ""
}

func checkSigninErrorTimes(ctx context.Context, user *User, lang string) error {
	failedSigninLimit, failedSigninFrozenTime, err := GetFailedSigninConfigByUser(ctx, user)
	if err != nil {
		return err
	}

	if user.SigninWrongTimes >= failedSigninLimit {
		lastSignWrongTime, _ := time.Parse(time.RFC3339, user.LastSigninWrongTime)
		passedTime := time.Now().UTC().Sub(lastSignWrongTime)
		minutes := failedSigninFrozenTime - int(passedTime.Minutes())

		// deny the login if the error times is greater than the limit and the last login time is less than the duration
		if minutes > 0 {
			return fmt.Errorf(i18n.Translate(lang, "check:You have entered the wrong password or code too many times, please wait for %d minutes and try again"), minutes)
		}

		// reset the error times
		user.SigninWrongTimes = 0

		_, err := UpdateUser(user.GetId(), user, []string{"signin_wrong_times"}, false)
		return err
	}

	return nil
}

func CheckPassword(ctx context.Context, user *User, password string, lang string, options ...bool) error {
	enableCaptcha := false
	if len(options) > 0 {
		enableCaptcha = options[0]
	}
	// check the login error times
	if !enableCaptcha {
		err := checkSigninErrorTimes(ctx, user, lang)
		if err != nil {
			return err
		}
	}

	organization, err := GetOrganizationByUser(user)
	if err != nil {
		return err
	}

	if organization == nil {
		return fmt.Errorf(i18n.Translate(lang, "check:Organization does not exist"))
	}

	passwordType := user.PasswordType
	if passwordType == "" {
		passwordType = organization.PasswordType
	}
	credManager := cred.GetCredManager(passwordType)
	if credManager != nil {
		if organization.MasterPassword != "" {
			if credManager.IsPasswordCorrect(password, organization.MasterPassword, "") {
				return resetUserSigninErrorTimes(user)
			}
		}

		if credManager.IsPasswordCorrect(password, user.Password, user.PasswordSalt) {
			return resetUserSigninErrorTimes(user)
		}

		return recordSigninErrorInfo(ctx, user, lang, enableCaptcha)
	} else {
		return fmt.Errorf(i18n.Translate(lang, "check:unsupported password type: %s"), organization.PasswordType)
	}
}

func CheckOneTimePassword(ctx context.Context, user *User, dest, code, lang string) error {
	// check the login error times
	if err := checkSigninErrorTimes(ctx, user, lang); err != nil {
		return err
	}
	result := CheckVerificationCode(dest, code, lang)
	if result.Code != VerificationSuccess {
		return recordSigninErrorInfo(ctx, user, lang)
	}
	resetUserSigninErrorTimes(user)
	return nil
}

func CheckPasswordComplexityByOrg(organization *Organization, password string, lang string) string {
	maxLen := organization.PasswordMaxLength
	minLen := organization.PasswordMinLength
	if maxLen < len(password) || len(password) < minLen {
		return fmt.Sprintf(i18n.Translate(lang, "check:The password must be between %d and %d characters long"), minLen, maxLen)
	}
	errorMsg := checkPasswordComplexity(password, organization.PasswordOptions, organization.PasswordSpecialChars)
	return errorMsg
}

func CheckPasswordComplexity(user *User, password string, lang string) string {
	organization, _ := GetOrganizationByUser(user)
	return CheckPasswordComplexityByOrg(organization, password, lang)
}

// check user pwd only in selected ldap
func CheckLdapUserPassword(user *User, password string, lang string, ldapId string) (string, error) {
	var ldaps []*Ldap
	var err error

	if ldapId == "" {
		ldaps, err = GetLdaps(user.Owner)
	} else {
		var ldap *Ldap
		ldap, err = GetLdap(ldapId)
		ldaps = append(ldaps, ldap)
	}

	if err != nil {
		return "", err
	}

	ldapLoginSuccess := false
	hit := false
	var ldapServerId string
	userDisabled := false

	for _, ldapServer := range ldaps {
		conn, err := ldapServer.GetLdapConn(context.Background())
		if err != nil {
			continue
		}

		searchReq := goldap.NewSearchRequest(ldapServer.BaseDn, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
			0, 0, false, ldapServer.buildAuthFilterString(user), []string{}, nil)

		searchResult, err := conn.Conn.Search(searchReq)
		if err != nil {
			conn.Close()
			return "", err
		}

		if len(searchResult.Entries) == 0 {
			conn.Close()
			continue
		}
		if len(searchResult.Entries) > 1 {
			conn.Close()
			return ldapServer.Id, fmt.Errorf(i18n.Translate(lang, "check:Multiple accounts with same uid, please check your ldap server"))
		}

		userDisabled, err = CheckIsUserDisabled(searchResult.Entries[0].Attributes)
		if err != nil {
			conn.Close()
			return "", err
		}

		if userDisabled {
			user.IsForbidden = true
			_, err = UpdateUser(user.GetId(), user, []string{"is_forbidden"}, false)
			if err != nil {
				return "", err
			}
			conn.Close()
			break
		}

		hit = true
		dn := searchResult.Entries[0].DN
		if err = conn.Conn.Bind(dn, password); err == nil {
			ldapLoginSuccess = true
			ldapServerId = ldapServer.Id
			conn.Close()
			break
		}

		conn.Close()
	}

	if userDisabled {
		return "", fmt.Errorf("user is disabled")
	}

	if !ldapLoginSuccess {
		if !hit {
			return "", fmt.Errorf("user not exist")
		}
		return "", fmt.Errorf(i18n.Translate(lang, "check:LDAP user name or password incorrect"))
	}
	return ldapServerId, resetUserSigninErrorTimes(user)
}

var ErrorUserNotFound = errors.New("user not found")
var ErrorUserDeleted = errors.New("user deleted")
var ErrorUserBlocked = errors.New("user blocked")
var ErrorWrongPassword = errors.New("wrong password")
var ErrorLDAPError = errors.New("LDAP error")
var ErrorLDAPUserNotFound = errors.New("LDAP user not found")

func NewCheckUserPasswordError(err error) *CheckUserPasswordError {
	return &CheckUserPasswordError{
		err: err,
	}
}

type CheckUserPasswordError struct {
	err      error
	username string
	message  string
}

func (err *CheckUserPasswordError) Err() error {
	return err.err
}

func (err *CheckUserPasswordError) Username() string {
	return err.username
}

func (err *CheckUserPasswordError) Message() string {
	return err.message
}

func (err *CheckUserPasswordError) WithUser(user string) *CheckUserPasswordError {
	err.username = user

	return err
}

func (err *CheckUserPasswordError) WithMessage(message string) *CheckUserPasswordError {
	err.message = message

	return err
}

func (err *CheckUserPasswordError) Error() string {
	return err.err.Error()
}

func (err *CheckUserPasswordError) RealError() error {
	return err.err
}

func CheckUserPassword(ctx context.Context, organization string, username string, password string, options CheckUserPasswordOptions) (*User, error) {
	enableCaptcha := false
	isSigninViaLdap := false
	isPasswordWithLdapEnabled := false

	enableCaptcha = options.EnableCaptcha
	isSigninViaLdap = options.IsSigninViaLdap
	isPasswordWithLdapEnabled = options.IsPasswordWithLdapEnabled

	user, err := GetUserByFields(organization, username)
	if err != nil {
		return nil, err
	}

	if user == nil || user.IsDeleted {
		return nil, fmt.Errorf(i18n.Translate(options.Lang, "general:The user: %s doesn't exist"), util.GetId(organization, username))
	}

	if user.IsForbidden {
		return nil, fmt.Errorf(i18n.Translate(options.Lang, "check:The user is forbidden to sign in, please contact the administrator"))
	}

	if isSigninViaLdap {
		if user.Ldap == "" {
			return nil, fmt.Errorf(i18n.Translate(options.Lang, "check:The user: %s doesn't exist in LDAP server"), username)
		}
	}

	if user.Ldap != "" && !isSigninViaLdap {
		return nil, fmt.Errorf(i18n.Translate(options.Lang, "check:Go to the LDAP tab and select the specific connection you have configured"))
	}

	if user.Ldap != "" {
		if !isSigninViaLdap && !isPasswordWithLdapEnabled {
			return nil, fmt.Errorf(i18n.Translate(options.Lang, "check:password or code is incorrect"))
		}

		// check the login error times
		if !enableCaptcha {
			err = checkSigninErrorTimes(ctx, user, options.Lang)
			if err != nil {
				return nil, err
			}
		}

		// only for LDAP users
		_, err = CheckLdapUserPassword(user, password, options.Lang, options.LdapId)
		if err != nil {
			if err.Error() == "user not exist" {
				return nil, fmt.Errorf(i18n.Translate(options.Lang, "check:The user: %s doesn't exist in LDAP server"), username)
			}

			if err.Error() == "user is disabled" {
				return nil, fmt.Errorf(i18n.Translate(options.Lang, "check:The user is forbidden to sign in, please contact the administrator"))
			}

			return nil, recordSigninErrorInfo(ctx, user, options.Lang, enableCaptcha)
		}
	} else {
		err = CheckPassword(ctx, user, password, options.Lang, enableCaptcha)
		if err != nil {
			return nil, err
		}
	}
	return user, nil
}

func CheckPassErrorToMessage(err error, lang string) string {
	if extendedErr, ok := err.(*CheckUserPasswordError); ok {
		switch extendedErr.Err() {
		case ErrorUserNotFound:
			return i18n.Translate(lang, "general:Invalid username or password/code")
		case ErrorUserDeleted:
			return i18n.Translate(lang, "general:Invalid username or password/code")
		case ErrorUserBlocked:
			return i18n.Translate(lang, "check:The user is forbidden to sign in, please contact the administrator")
		case ErrorWrongPassword:
			return extendedErr.Message()
		case ErrorLDAPUserNotFound:
			return i18n.Translate(lang, "general:Invalid username or password/code")
		case ErrorLDAPError:
			return extendedErr.Message()
		default:
			return extendedErr.Error()
		}
	}

	return err.Error()
}

func CheckUserPermission(ctx context.Context, requestUserId, userId string, strict bool, lang string) (bool, error) {
	if requestUserId == "" {
		return false, fmt.Errorf(i18n.Translate(lang, "general:Please login first"))
	}

	userOwner, err := util.GetOwnerFromId(userId)
	if err != nil {
		return false, err
	}

	if userId != "" {
		targetUser, err := GetUser(userId)
		if err != nil {
			return false, err
		}

		if targetUser == nil {
			if strings.HasPrefix(requestUserId, "built-in/") {
				return true, nil
			}

			return false, &NotFoundError{fmt.Sprintf(i18n.Translate(lang, "general:The user: %s doesn't exist"), userId)}
		}

		userOwner = targetUser.Owner
	}

	hasPermission := false
	if strings.HasPrefix(requestUserId, "app/") {
		requestApp, err := GetApplication(ctx, fmt.Sprintf("admin/%s", strings.Split(requestUserId, "/")[1]))
		if err != nil {
			return false, err
		}
		if requestApp == nil {
			return false, fmt.Errorf(i18n.Translate(lang, "check:Session outdated, please login again"))
		}

		if requestApp.Organization == builtInOrganization {
			hasPermission = true
		}

		if requestApp.Organization == userOwner {
			hasPermission = true
		}
	} else {
		requestUser, err := GetUser(requestUserId)
		if err != nil {
			return false, err
		}

		if requestUser == nil {
			return false, fmt.Errorf(i18n.Translate(lang, "check:Session outdated, please login again"))
		}
		if requestUser.IsGlobalAdmin() {
			hasPermission = true
		} else if requestUserId == userId {
			hasPermission = true
		} else if userOwner == requestUser.Owner {
			if strict {
				hasPermission = requestUser.IsAdmin
			} else {
				hasPermission = true
			}
		}
	}

	return hasPermission, fmt.Errorf(i18n.Translate(lang, "auth:Unauthorized operation"))
}

func CheckLoginPermission(userId string, application *Application) (bool, error) {
	var err error
	if userId == "built-in/admin" {
		return true, nil
	}

	permissions, err := GetPermissions(application.Organization)
	if err != nil {
		return false, err
	}

	allowCount := 0
	denyCount := 0
	for _, permission := range permissions {
		if !permission.IsEnabled || permission.ResourceType != "Application" || !permission.isResourceHit(application.Name) {
			continue
		}

		hit, err := permission.isUserHit(userId)
		if err != nil {
			return false, err
		}
		if hit {
			allowCount += 1
		}

		enforcer := getPermissionEnforcer(permission)

		var isAllowed bool
		isAllowed, err = enforcer.Enforce(userId, application.Name, "Read")
		if err != nil {
			return false, err
		}

		if isAllowed {
			if permission.Effect == "Allow" {
				allowCount += 1
			}
		} else {
			if permission.Effect == "Deny" {
				denyCount += 1
			}
		}
	}

	if denyCount > 0 {
		return false, nil
	}
	return true, nil
}

func CheckUsername(username string, lang string) string {
	if username == "" {
		return i18n.Translate(lang, "check:Empty username.")
	} else if len(username) > 255 {
		return i18n.Translate(lang, "check:Username is too long (maximum is 255 characters).")
	}

	// https://stackoverflow.com/questions/58726546/github-username-convention-using-regex

	if !util.ReUserName.MatchString(username) {
		return i18n.Translate(lang, "check:The username may only contain alphanumeric characters, underlines or hyphens, cannot have consecutive hyphens or underlines, and cannot begin or end with a hyphen or underline.")
	}

	return ""
}

func CheckUpdateUser(oldUser, user *User, lang string) string {
	if oldUser.Name != user.Name {
		if msg := CheckUsername(user.Name, lang); msg != "" {
			return msg
		}
		if HasUserByField(user.Owner, "name", user.Name) {
			return i18n.Translate(lang, "check:Username already exists")
		}
	}
	if strings.ToLower(oldUser.Email) != strings.ToLower(user.Email) {
		if HasUserByField(user.Owner, "email", user.Email) {
			return i18n.Translate(lang, "check:Email already exists")
		}
	}
	if oldUser.Phone != user.Phone {
		if HasUserByField(user.Owner, "phone", user.Phone) {
			return i18n.Translate(lang, "check:Phone already exists")
		}
	}

	return ""
}

func CheckToEnableCaptcha(application *Application, organization, username string) (bool, error) {
	if len(application.Providers) == 0 {
		return false, nil
	}

	for _, providerItem := range application.Providers {
		if providerItem.Provider == nil {
			continue
		}
		if providerItem.Provider.Category == "Captcha" {
			if providerItem.Rule == "Dynamic" {
				user, err := GetUserByFields(organization, username)
				if err != nil {
					return false, err
				}
				return user != nil && user.SigninWrongTimes >= SigninWrongTimesLimit, nil
			}
			return providerItem.Rule == "Always", nil
		}
	}

	return false, nil
}

func CheckUserIdProviderOrigin(userIdProvider UserIdProvider) bool {
	isProviderNameEmpty := userIdProvider.ProviderName == ""
	isLdapIdEmpty := userIdProvider.LdapId == ""

	return isProviderNameEmpty != isLdapIdEmpty
}

func CheckIsUserDisabled(userAttributes []*goldap.EntryAttribute) (bool, error) {
	isDisabled := false

	for _, attr := range userAttributes {
		if attr.Name == "userAccountControl" {
			intValue, err := strconv.Atoi(attr.Values[0])
			if err != nil {
				return false, err
			}

			accountContolFlags := ConvertUserAccountControl(intValue)
			if slices.Contains(accountContolFlags, "ACCOUNTDISABLE") {
				isDisabled = true
			}
		}
	}

	return isDisabled, nil
}
