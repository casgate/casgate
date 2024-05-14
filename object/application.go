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
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/util"
	"github.com/r3labs/diff/v3"
	"github.com/xorm-io/core"
)

type SigninMethod struct {
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Rule        string `json:"rule"`
}

type SignupItem struct {
	Name        string `json:"name"`
	Visible     bool   `json:"visible"`
	Required    bool   `json:"required"`
	Prompted    bool   `json:"prompted"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder"`
	Regex       string `json:"regex"`
	Rule        string `json:"rule"`
}

type SamlItem struct {
	Name       string `json:"name"`
	NameFormat string `json:"nameFormat"`
	Value      string `json:"value"`
}

type Application struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	DisplayName            string          `xorm:"varchar(100)" json:"displayName"`
	Logo                   string          `xorm:"varchar(200)" json:"logo"`
	HomepageUrl            string          `xorm:"varchar(100)" json:"homepageUrl"`
	Description            string          `xorm:"varchar(100)" json:"description"`
	Organization           string          `xorm:"varchar(100)" json:"organization"`
	Cert                   string          `xorm:"varchar(100)" json:"cert"`
	EnablePassword         bool            `json:"enablePassword"`
	EnablePasswordRecovery bool            `json:"enablePasswordRecovery"`
	EnableInternalSignUp   bool            `json:"enableInternalSignUp"`
	EnableIdpSignUp        bool            `json:"enableIdpSignUp"`
	EnableSigninSession    bool            `json:"enableSigninSession"`
	EnableAutoSignin       bool            `json:"enableAutoSignin"`
	EnableCodeSignin       bool            `json:"enableCodeSignin"`
	EnableSamlCompress     bool            `json:"enableSamlCompress"`
	EnableWebAuthn         bool            `json:"enableWebAuthn"`
	EnableLinkWithEmail    bool            `json:"enableLinkWithEmail"`
	OrgChoiceMode          string          `json:"orgChoiceMode"`
	SamlReplyUrl           string          `xorm:"varchar(100)" json:"samlReplyUrl"`
	Providers              []*ProviderItem `xorm:"mediumtext" json:"providers"`
	SigninMethods          []*SigninMethod `xorm:"varchar(2000)" json:"signinMethods"`
	SignupItems            []*SignupItem   `xorm:"varchar(1000)" json:"signupItems"`
	GrantTypes             []string        `xorm:"varchar(1000)" json:"grantTypes"`
	OrganizationObj        *Organization   `xorm:"-" json:"organizationObj"`
	CertPublicKey          string          `xorm:"-" json:"certPublicKey"`
	Tags                   []string        `xorm:"mediumtext" json:"tags"`
	InvitationCodes        []string        `xorm:"varchar(200)" json:"invitationCodes"`
	IsPublic               bool            `xorm:"bool" json:"isPublic"`
	SamlAttributes         []*SamlItem     `xorm:"varchar(1000)" json:"samlAttributes"`

	ClientId             string     `xorm:"varchar(100)" json:"clientId"`
	ClientSecret         string     `xorm:"varchar(100)" json:"clientSecret"`
	RedirectUris         []string   `xorm:"varchar(1000)" json:"redirectUris"`
	TokenFormat          string     `xorm:"varchar(100)" json:"tokenFormat"`
	TokenFields          []string   `xorm:"varchar(1000)" json:"tokenFields"`
	ExpireInHours        int        `json:"expireInHours"`
	RefreshExpireInHours int        `json:"refreshExpireInHours"`
	SignupUrl            string     `xorm:"varchar(200)" json:"signupUrl"`
	SigninUrl            string     `xorm:"varchar(200)" json:"signinUrl"`
	ForgetUrl            string     `xorm:"varchar(200)" json:"forgetUrl"`
	AffiliationUrl       string     `xorm:"varchar(100)" json:"affiliationUrl"`
	TermsOfUse           string     `xorm:"varchar(100)" json:"termsOfUse"`
	SignupHtml           string     `xorm:"mediumtext" json:"signupHtml"`
	SigninHtml           string     `xorm:"mediumtext" json:"signinHtml"`
	FooterText           string     `xorm:"mediumtext" json:"footerText"`
	ThemeData            *ThemeData `xorm:"json" json:"themeData"`
	FormCss              string     `xorm:"text" json:"formCss"`
	FormCssMobile        string     `xorm:"text" json:"formCssMobile"`
	FormOffset           int        `json:"formOffset"`
	FormSideHtml         string     `xorm:"mediumtext" json:"formSideHtml"`
	FormBackgroundUrl    string     `xorm:"varchar(200)" json:"formBackgroundUrl"`

	FailedSigninLimit      int `json:"failedSigninLimit"`
	FailedSigninFrozenTime int `json:"failedSigninFrozenTime"`
}

func GetApplicationCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Application{})
}

func GetOrganizationApplicationCount(owner, Organization, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Application{Organization: Organization})
}

func GetApplications(owner string) ([]*Application, error) {
	applications := []*Application{}
	err := ormer.Engine.Desc("created_time").Find(&applications, &Application{Owner: owner})
	if err != nil {
		return applications, err
	}

	return applications, nil
}

func CountApplicatoinsByProvider(providerName string) ([]*Application, error) {
	applications := []*Application{}
	err := ormer.Engine.Where("providers like ?", "%\"name\":\""+providerName+"\"%").Find(&applications, &Application{})
	if err != nil {
		return applications, err
	}

	return applications, nil
}

func GetOrganizationApplications(owner string, organization string) ([]*Application, error) {
	applications := []*Application{}
	err := ormer.Engine.Desc("created_time").Find(&applications, &Application{Organization: organization})
	if err != nil {
		return applications, err
	}

	return applications, nil
}

func GetPaginationApplications(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Application, error) {
	var applications []*Application
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&applications)
	if err != nil {
		return applications, err
	}

	return applications, nil
}

func GetPaginationOrganizationApplications(owner, organization string, offset, limit int, field, value, sortField, sortOrder string) ([]*Application, error) {
	applications := []*Application{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&applications, &Application{Organization: organization})
	if err != nil {
		return applications, err
	}

	return applications, nil
}

func getProviderMap(owner string) (m map[string]*Provider, err error) {
	providers, err := GetProviders(owner)
	if err != nil {
		return nil, err
	}

	m = map[string]*Provider{}
	for _, provider := range providers {
		// Get QRCode only once
		if provider.Type == "WeChat" && provider.DisableSsl && provider.Content == "" {
			provider.Content, err = idp.GetWechatOfficialAccountQRCode(provider.ClientId2, provider.ClientSecret2)
			if err != nil {
				return
			}
			UpdateProvider(provider.Owner+"/"+provider.Name, provider)
		}

		m[provider.Name] = GetMaskedProvider(provider, true)
	}

	return m, err
}

func extendApplicationWithProviders(ctx context.Context, application *Application) (err error) {
	m, err := getProviderMap(application.Organization)
	if err != nil {
		return err
	}

	record := GetRecord(ctx)

	for _, providerItem := range application.Providers {
		if provider, ok := m[providerItem.Name]; ok {
			if provider.Type == "OpenID" {
				err := updateOpenIDWithUrls(provider)
				if err != nil {
					record.AddReason(fmt.Sprintf("failed updateOpenIDWithUrls for provider %s: %s", provider.Name, err.Error()))

					logs.Error("failed updateOpenIDWithUrls for provider %s: %s", provider.Name, err.Error())
				}
			}
			providerItem.Provider = provider
		}
	}

	return
}

func updateOpenIDWithUrls(provider *Provider) error {
	idpInfo := FromProviderToIdpInfo(nil, provider)
	openIDProvider := idp.NewOpenIdProvider(idpInfo, idpInfo.RedirectUrl)

	client, err := GetProviderHttpClient(*idpInfo)
	if err != nil {
		return fmt.Errorf("failed to GetProviderHttpClient for provider %s", provider.Name)
	}
	openIDProvider.SetHttpClient(client)
	err = openIDProvider.EnrichOauthURLs()
	if err != nil {
		return fmt.Errorf("failed to EnrichOauthURLs for provider %s", provider.Name)
	}

	provider.CustomTokenUrl = openIDProvider.TokenURL
	provider.CustomAuthUrl = openIDProvider.AuthURL
	provider.CustomUserInfoUrl = openIDProvider.UserInfoURL

	return nil
}

func extendApplicationWithOrg(application *Application) (err error) {
	organization, err := getOrganization(application.Owner, application.Organization)
	application.OrganizationObj = organization
	return
}

func extendApplicationWithSigninMethods(application *Application) (err error) {
	if len(application.SigninMethods) == 0 {
		if application.EnablePassword {
			signinMethod := &SigninMethod{Name: "Password", DisplayName: "Password", Rule: "All"}
			application.SigninMethods = append(application.SigninMethods, signinMethod)
		}
		if application.EnableCodeSignin {
			signinMethod := &SigninMethod{Name: "Verification code", DisplayName: "Verification code", Rule: "All"}
			application.SigninMethods = append(application.SigninMethods, signinMethod)
		}
		if application.EnableWebAuthn {
			signinMethod := &SigninMethod{Name: "WebAuthn", DisplayName: "WebAuthn", Rule: "None"}
			application.SigninMethods = append(application.SigninMethods, signinMethod)
		}
	}

	if len(application.SigninMethods) == 0 {
		signinMethod := &SigninMethod{Name: "Password", DisplayName: "Password", Rule: "All"}
		application.SigninMethods = append(application.SigninMethods, signinMethod)
	}

	return
}

func getApplication(ctx context.Context, owner string, name string) (*Application, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	application := Application{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&application)
	if err != nil {
		return nil, err
	}

	if existed {
		err = extendApplicationWithProviders(ctx, &application)
		if err != nil {
			return nil, err
		}

		err = extendApplicationWithOrg(&application)
		if err != nil {
			return nil, err
		}

		err = extendApplicationWithSigninMethods(&application)
		if err != nil {
			return nil, err
		}

		return &application, nil
	} else {
		return nil, nil
	}
}

func GetApplicationByOrganizationName(ctx context.Context, organization string) (*Application, error) {
	application := Application{}
	existed, err := ormer.Engine.Where("organization=?", organization).Get(&application)
	if err != nil {
		return nil, nil
	}

	if existed {
		err = extendApplicationWithProviders(ctx, &application)
		if err != nil {
			return nil, err
		}

		err = extendApplicationWithOrg(&application)
		if err != nil {
			return nil, err
		}

		err = extendApplicationWithSigninMethods(&application)
		if err != nil {
			return nil, err
		}

		return &application, nil
	} else {
		return nil, nil
	}
}

func GetApplicationByUser(ctx context.Context, user *User) (*Application, error) {
	if user.SignupApplication != "" {
		return getApplication(ctx, "admin", user.SignupApplication)
	} else {
		return GetApplicationByOrganizationName(ctx, user.Owner)
	}
}

func GetApplicationByUserId(ctx context.Context, userId string) (application *Application, err error) {
	owner, name := util.GetOwnerAndNameFromId(userId)
	if owner == "app" {
		application, err = getApplication(ctx, "admin", name)
		return
	}

	user, err := GetUser(userId)
	if err != nil {
		return nil, err
	}
	application, err = GetApplicationByUser(ctx, user)
	return
}

func GetApplicationByClientId(ctx context.Context, clientId string) (*Application, error) {
	application := Application{}
	existed, err := ormer.Engine.Where("client_id=?", clientId).Get(&application)
	if err != nil {
		return nil, err
	}

	if existed {
		err = extendApplicationWithProviders(ctx, &application)
		if err != nil {
			return nil, err
		}

		err = extendApplicationWithOrg(&application)
		if err != nil {
			return nil, err
		}

		err = extendApplicationWithSigninMethods(&application)
		if err != nil {
			return nil, err
		}

		return &application, nil
	} else {
		return nil, nil
	}
}

func GetApplication(ctx context.Context, id string) (*Application, error) {
	owner, name := util.GetOwnerAndNameFromId(id)
	return getApplication(ctx, owner, name)
}

func GetMaskedApplication(application *Application, userId string) *Application {
	if application == nil {
		return nil
	}

	if application.TokenFields == nil {
		application.TokenFields = []string{}
	}

	if application.FailedSigninLimit == 0 {
		application.FailedSigninLimit = 5
	}
	if application.FailedSigninFrozenTime == 0 {
		application.FailedSigninFrozenTime = 15 // SigninWrongTimesLimit
	}

	if userId != "" {
		if isUserIdGlobalAdmin(userId) {
			return application
		}

		user, _ := GetUser(userId)
		if user != nil && user.IsApplicationAdmin(application) {
			return application
		}
	}

	if application.ClientSecret != "" {
		application.ClientSecret = "***"
	}

	if application.OrganizationObj != nil {
		if application.OrganizationObj.MasterPassword != "" {
			application.OrganizationObj.MasterPassword = "***"
		}
		if application.OrganizationObj.PasswordType != "" {
			application.OrganizationObj.PasswordType = "***"
		}
		if application.OrganizationObj.PasswordSalt != "" {
			application.OrganizationObj.PasswordSalt = "***"
		}
	}

	if application.InvitationCodes != nil {
		application.InvitationCodes = []string{"***"}
	}

	return application
}

func GetMaskedApplications(applications []*Application, userId string) []*Application {
	if isUserIdGlobalAdmin(userId) {
		return applications
	}

	for _, application := range applications {
		application = GetMaskedApplication(application, userId)
	}
	return applications
}

func UpdateApplication(ctx context.Context, id string, application *Application) (bool, error) {
	owner, name := util.GetOwnerAndNameFromId(id)
	oldApplication, err := getApplication(ctx, owner, name)
	if oldApplication == nil {
		return false, err
	}

	if name == "app-built-in" {
		application.Name = name
	}

	if name != application.Name {
		err = applicationChangeTrigger(name, application.Name)
		if err != nil {
			return false, err
		}
	}

	applicationByClientId, err := GetApplicationByClientId(ctx, application.ClientId)
	if err != nil {
		return false, err
	}

	if oldApplication.ClientId != application.ClientId && applicationByClientId != nil {
		return false, err
	}

	record := GetRecord(ctx)
	for _, providerItem := range application.Providers {
		providerItem.Provider = nil
	}

	recordProvidersDiff(record, oldApplication.Providers, application.Providers)

	session := ormer.Engine.ID(core.PK{owner, name}).AllCols()
	if application.ClientSecret == "***" {
		session.Omit("client_secret")
	}
	affected, err := session.Update(application)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func recordProvidersDiff(record *RecordBuilder, oldProviders, newProviders []*ProviderItem) {
	providersDiff, err := diff.Diff(mapProvidersToNames(oldProviders), mapProvidersToNames(newProviders))
	if err != nil {
		logs.Error("diff providers: %v", err.Error())

		return
	}

	if len(providersDiff) > 0 {
		if diff, err := json.Marshal(providersDiff); err == nil {
			record.AddReason(fmt.Sprintf("diff providers: %s", string(diff)))
		} else {
			logs.Error("marshall diff: %v", err.Error())
		}
	}
}

func AddApplication(ctx context.Context, application *Application) (bool, error) {
	if application.Owner == "" {
		application.Owner = "admin"
	}
	if application.Organization == "" {
		application.Organization = "built-in"
	}
	if application.ClientId == "" {
		application.ClientId = util.GenerateClientId()
	}
	if application.ClientSecret == "" {
		application.ClientSecret = util.GenerateClientSecret()
	}

	app, err := GetApplicationByClientId(ctx, application.ClientId)
	if err != nil {
		return false, err
	}

	if app != nil {
		return false, nil
	}

	for _, providerItem := range application.Providers {
		providerItem.Provider = nil
	}

	affected, err := ormer.Engine.Insert(application)
	if err != nil {
		return false, nil
	}

	return affected != 0, nil
}

func DeleteApplication(application *Application) (bool, error) {
	if application.Name == "app-built-in" {
		return false, nil
	}

	affected, err := ormer.Engine.ID(core.PK{application.Owner, application.Name}).Delete(&Application{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (application *Application) GetId() string {
	return fmt.Sprintf("%s/%s", application.Owner, application.Name)
}

func (application *Application) IsRedirectUriValid(redirectUri string) bool {
	redirectUris := append([]string{"http://localhost:", "https://localhost:", "http://127.0.0.1:", "http://casdoor-app"}, application.RedirectUris...)
	for _, targetUri := range redirectUris {
		targetUriRegex := regexp.MustCompile(targetUri)
		if targetUriRegex.MatchString(redirectUri) || strings.Contains(redirectUri, targetUri) {
			return true
		}
	}
	return false
}

func (application *Application) IsPasswordEnabled() bool {
	if len(application.SigninMethods) == 0 {
		return application.EnablePassword
	} else {
		for _, signinMethod := range application.SigninMethods {
			if signinMethod.Name == "Password" {
				return true
			}
		}
		return false
	}
}

func (application *Application) IsPasswordWithLdapEnabled() bool {
	if len(application.SigninMethods) == 0 {
		return application.EnablePassword
	} else {
		for _, signinMethod := range application.SigninMethods {
			if signinMethod.Name == "Password" && signinMethod.Rule == "All" {
				return true
			}
		}
		return false
	}
}

func (application *Application) IsCodeSigninViaEmailEnabled() bool {
	if len(application.SigninMethods) == 0 {
		return application.EnableCodeSignin
	} else {
		for _, signinMethod := range application.SigninMethods {
			if signinMethod.Name == "Verification code" && signinMethod.Rule != "Phone only" {
				return true
			}
		}
		return false
	}
}

func (application *Application) IsCodeSigninViaSmsEnabled() bool {
	if len(application.SigninMethods) == 0 {
		return application.EnableCodeSignin
	} else {
		for _, signinMethod := range application.SigninMethods {
			if signinMethod.Name == "Verification code" && signinMethod.Rule != "Email only" {
				return true
			}
		}
		return false
	}
}

func (application *Application) IsLdapEnabled() bool {
	if len(application.SigninMethods) > 0 {
		for _, signinMethod := range application.SigninMethods {
			if signinMethod.Name == "LDAP" {
				return true
			}
		}
	}
	return false
}

func IsOriginAllowed(origin string) (bool, error) {
	applications, err := GetApplications("")
	if err != nil {
		return false, err
	}

	for _, application := range applications {
		if application.IsRedirectUriValid(origin) {
			return true, nil
		}
	}
	return false, nil
}

func getApplicationMap(organization string) (map[string]*Application, error) {
	applicationMap := make(map[string]*Application)
	applications, err := GetOrganizationApplications("admin", organization)
	if err != nil {
		return applicationMap, err
	}

	for _, application := range applications {
		applicationMap[application.Name] = application
	}

	return applicationMap, nil
}

func ExtendManagedAccountsWithUser(user *User) (*User, error) {
	if user.ManagedAccounts == nil || len(user.ManagedAccounts) == 0 {
		return user, nil
	}

	applicationMap, err := getApplicationMap(user.Owner)
	if err != nil {
		return user, err
	}

	var managedAccounts []ManagedAccount
	for _, managedAccount := range user.ManagedAccounts {
		application := applicationMap[managedAccount.Application]
		if application != nil {
			managedAccount.SigninUrl = application.SigninUrl
			managedAccounts = append(managedAccounts, managedAccount)
		}
	}
	user.ManagedAccounts = managedAccounts

	return user, nil
}

func applicationChangeTrigger(oldName string, newName string) error {
	session := ormer.Engine.NewSession()
	defer session.Close()

	err := session.Begin()
	if err != nil {
		return err
	}

	organization := new(Organization)
	organization.DefaultApplication = newName
	_, err = session.Where("default_application=?", oldName).Update(organization)
	if err != nil {
		return err
	}

	user := new(User)
	user.SignupApplication = newName
	_, err = session.Where("signup_application=?", oldName).Update(user)
	if err != nil {
		return err
	}

	resource := new(Resource)
	resource.Application = newName
	_, err = session.Where("application=?", oldName).Update(resource)
	if err != nil {
		return err
	}

	var permissions []*Permission
	err = ormer.Engine.Find(&permissions)
	if err != nil {
		return err
	}
	for i := 0; i < len(permissions); i++ {
		permissionResources := permissions[i].Resources
		for j := 0; j < len(permissionResources); j++ {
			if permissionResources[j] == oldName {
				permissionResources[j] = newName
			}
		}
		permissions[i].Resources = permissionResources
		_, err = session.Where("owner=?", permissions[i].Owner).Where("name=?", permissions[i].Name).Update(permissions[i])
		if err != nil {
			return err
		}
	}

	return session.Commit()
}
