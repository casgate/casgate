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

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/casdoor/casdoor/util/logger"
	"github.com/pkg/errors"
)

const (
	ResponseTypeLogin   = "login"
	ResponseTypeCode    = "code"
	ResponseTypeToken   = "token"
	ResponseTypeIdToken = "id_token"
	ResponseTypeSaml    = "saml"
	ResponseTypeCas     = "cas"
)

type Response struct {
	Status string      `json:"status"`
	Msg    string      `json:"msg"`
	Sub    string      `json:"sub"`
	Name   string      `json:"name"`
	Data   interface{} `json:"data"`
	Data2  interface{} `json:"data2"`
}

type Captcha struct {
	Type          string `json:"type"`
	AppKey        string `json:"appKey"`
	Scene         string `json:"scene"`
	CaptchaId     string `json:"captchaId"`
	CaptchaImage  []byte `json:"captchaImage"`
	ClientId      string `json:"clientId"`
	ClientSecret  string `json:"clientSecret"`
	ClientId2     string `json:"clientId2"`
	ClientSecret2 string `json:"clientSecret2"`
	SubType       string `json:"subType"`
}

// Signup
// @Tag Login API
// @Title Signup
// @Description sign up a new user
// @Param type body         string false
// @Param signinMethod body string false
// @Param organization body   string true
// @Param id body             string false
// @Param username body       string true
// @Param password body       string false
// @Param name body           string false
// @Param firstName body      string false
// @Param lastName body       string false
// @Param email body          string false
// @Param phone body          string false
// @Param affiliation body    string false
// @Param idCard body         string false
// @Param region body         string false
// @Param invitationCode body string false
// @Param application body string true
// @Param clientId body    string false
// @Param provider body    string false
// @Param code body        string false
// @Param state body       string false
// @Param redirectUri body string false
// @Param method body      string false
// @Param emailCode body   string false
// @Param phoneCode body   string false
// @Param countryCode body string false
// @Param autoSignin body   bool false
// @Param relayState body   string false
// @Param samlRequest body  string false
// @Param samlResponse body string false
// @Param captchaType body  string false
// @Param captchaToken body string false
// @Param clientSecret body string false
// @Param mfaType body      string false
// @Param passcode body     string false
// @Param recoveryCode body string false
// @Param plan body    string false
// @Param pricing body string false
// @Param ldapId body string false
// @Success 200 {object} controllers.Response The Response object
// @router /signup [post]
func (c *ApiController) Signup() {
	if c.GetSessionUsername() != "" {
		c.ResponseError(c.T("account:Please sign out first"), c.GetSessionUsername())
		return
	}

	gCtx := c.getRequestCtx()
	record := object.GetRecordBuilderFromContext(gCtx)

	var authForm form.AuthForm
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &authForm)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	application, err := object.GetApplication(gCtx, fmt.Sprintf("admin/%s", authForm.Application))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if !application.EnableInternalSignUp {
		c.ResponseError(c.T("account:The application does not allow to sign up new account"))
		return
	}

	organization, err := object.GetOrganization(util.GetId("admin", authForm.Organization))
	if err != nil {
		c.ResponseError(c.T(err.Error()))
		return
	}

	if application.Organization != organization.Name {
		c.ResponseError(c.T("account:organization in request differs from application organization"))
		return
	}

	msg := object.CheckUserSignup(application, organization, &authForm, c.GetAcceptLanguage())
	if msg != "" {
		c.ResponseError(msg)
		return
	}

	if application.IsSignupItemVisible("Email") && application.GetSignupItemRule("Email") != "No verification" && authForm.Email != "" {
		checkResult := object.CheckVerificationCode(authForm.Email, authForm.EmailCode, c.GetAcceptLanguage())
		if checkResult.Code != object.VerificationSuccess {
			c.ResponseError(checkResult.Msg)
			return
		}
	}

	var checkPhone string
	if application.IsSignupItemVisible("Phone") && application.GetSignupItemRule("Phone") != "No verification" && authForm.Phone != "" {
		checkPhone, _ = util.GetE164Number(authForm.Phone, authForm.CountryCode)
		checkResult := object.CheckVerificationCode(checkPhone, authForm.PhoneCode, c.GetAcceptLanguage())
		if checkResult.Code != object.VerificationSuccess {
			c.ResponseError(checkResult.Msg)
			return
		}
	}

	id := util.GenerateId()

	username := authForm.Username
	if !application.IsSignupItemVisible("Username") {
		username = id
	}

	initScore, err := organization.GetInitScore()
	if err != nil {
		c.ResponseError(fmt.Errorf(c.T("account:Get init score failed, error: %w"), err).Error())
		return
	}

	userType := "normal-user"

	user := &object.User{
		Owner:             authForm.Organization,
		Name:              username,
		CreatedTime:       util.GetCurrentTime(),
		Id:                id,
		Type:              userType,
		Password:          authForm.Password,
		DisplayName:       authForm.Name,
		Avatar:            organization.DefaultAvatar,
		Email:             authForm.Email,
		Phone:             authForm.Phone,
		CountryCode:       authForm.CountryCode,
		Address:           []string{},
		Affiliation:       authForm.Affiliation,
		IdCard:            authForm.IdCard,
		Region:            authForm.Region,
		Score:             initScore,
		IsAdmin:           false,
		IsForbidden:       false,
		IsDeleted:         false,
		SignupApplication: application.Name,
		Properties:        map[string]string{},
		Karma:             0,
		MappingStrategy:   application.UserMappingStrategy,
	}

	if len(organization.Tags) > 0 {
		tokens := strings.Split(organization.Tags[0], "|")
		if len(tokens) > 0 {
			user.Tag = tokens[0]
		}
	}

	if application.GetSignupItemRule("Display name") == "First, last" {
		if authForm.FirstName != "" || authForm.LastName != "" {
			user.DisplayName = fmt.Sprintf("%s %s", authForm.FirstName, authForm.LastName)
			user.FirstName = authForm.FirstName
			user.LastName = authForm.LastName
		}
	}

	var affected bool

	if authForm.Id == "" {
		affected, err = object.AddUser(gCtx, user)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	} else {
		// signup invited user
		invitedUser, err := object.GetUserByField(organization.Name, "id", authForm.Id)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		if invitedUser.Type != "invited-user" {
			c.ResponseError(fmt.Errorf(c.T("account:User already registered")).Error())
			return
		}

		if application.IsSignupItemVisible("Username") && invitedUser.Name != authForm.Username {
			c.ResponseError(fmt.Errorf(c.T("account:Wrong username for invited user")).Error())
			return
		}

		if application.IsSignupItemVisible("Email") && invitedUser.Email != authForm.Email {
			c.ResponseError(fmt.Errorf(c.T("account:Wrong email for invited user")).Error())
			return
		}

		user.Id = invitedUser.Id
		user.Name = invitedUser.Name
		user.PasswordType = invitedUser.PasswordType

		columns := []string{"password", "type"}

		if application.IsSignupItemVisible("Display name") {
			columns = append(columns, "displayName")
		}

		if application.IsSignupItemVisible("Phone") {
			columns = append(columns, "phone", "countryCode")
		}

		if application.IsSignupItemVisible("Affiliation") {
			columns = append(columns, "affiliation")
		}

		if application.IsSignupItemVisible("ID card") {
			columns = append(columns, "idCard")
		}

		if application.IsSignupItemVisible("Country/Region") {
			columns = append(columns, "region")
		}

		if err := user.UpdateUserPassword(organization); err != nil {
			c.ResponseError(err.Error())
			return
		}

		affected, err = object.UpdateUser(invitedUser.GetOwnerAndName(), user, columns, false)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	if !affected {
		c.ResponseError(c.T("account:Failed to add user"), util.StructToJson(user))
		return
	}

	if application.HasPromptPage() && user.Type == "normal-user" {
		// The prompt page needs the user to be signed in
		c.SetSessionUsername(user.GetOwnerAndName())
	}

	err = object.DisableVerificationCode(authForm.Email)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	err = object.DisableVerificationCode(checkPhone)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	record.WithUsername(user.Name).WithOrganization(application.Organization).AddReason("User signed up")

	userId := user.GetOwnerAndName()
	util.LogInfo(c.Ctx, "API: [%s] is signed up as new user", userId)

	c.ResponseOk(userId)
}

// Logout
// @Title Logout
// @Tag Login API
// @Description logout the current user
// @Param   id_token_hint   query        string  false        "id_token_hint"
// @Param   post_logout_redirect_uri    query    string  false     "post_logout_redirect_uri"
// @Param   state     query    string  false     "state"
// @Success 200 {object} controllers.Response The Response object
// @router /logout [get,post]
func (c *ApiController) Logout() {
	// https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html
	accessToken := c.Input().Get("id_token_hint")
	redirectUri := c.Input().Get("post_logout_redirect_uri")
	state := c.Input().Get("state")

	userNameWithOrg := c.GetSessionUsername()
	c.Ctx.Input.SetData("user", userNameWithOrg)

	goCtx := c.getRequestCtx()
	record := object.GetRecordBuilderFromContext(goCtx).WithUsername(userNameWithOrg)

	logger.SetItem(goCtx, "obj-type", "application")
	logger.SetItem(goCtx, "usr", userNameWithOrg)

	if accessToken == "" && redirectUri == "" {
		// TODO https://github.com/casdoor/casdoor/pull/1494#discussion_r1095675265
		if userNameWithOrg == "" {
			c.ResponseOk()
			return
		}
		owner, username, err := util.SplitIdIntoOrgAndName(userNameWithOrg)
		if err != nil {
			record.AddReason(fmt.Sprintf("Logout error: %s", err.Error()))

			c.ResponseError(err.Error())
			return
		}
		record.WithUsername(username).WithOrganization(owner)
		application, err := object.GetApplicationByUserId(goCtx, userNameWithOrg)
		if err != nil {
			err = errors.Wrap(err, "Logout error: failed to get application for user")
			logLogoutErr(goCtx, err.Error())
			c.ResponseError(err.Error())
			return
		}
		logger.SetItem(goCtx, "obj", object.CasdoorApplication)
		if application != nil {
			logger.SetItem(goCtx, "obj", application.GetId())
		}

		c.ClearUserSession()
		_, err = object.DeleteSessionId(
			goCtx,
			util.GetSessionId(owner, username, object.CasdoorApplication),
			c.Ctx.Input.CruSession.SessionID(),
		)
		if err != nil {
			logLogoutErr(goCtx, fmt.Sprintf("Logout error: %s", err.Error()))
			c.ResponseError(err.Error())
			return
		}

		logger.Info(goCtx,
			"",
			"act", "logout",
			"r", "success",
		)

		if application == nil || application.Name == object.CasdoorApplication || application.HomepageUrl == "" {
			record.AddReason("Logout error: application mismatch")

			c.ResponseOk(userNameWithOrg)
			return
		}
		c.ResponseOk(userNameWithOrg, application.HomepageUrl)
		return
	} else {
		if accessToken == "" {
			logLogoutErr(goCtx, "Logout error: missing id_token_hint")
			c.ResponseError(c.T("general:Missing parameter") + ": id_token_hint")
			return
		}

		affected, application, token, err := object.ExpireTokenByAccessToken(goCtx, accessToken)
		if err != nil {
			logLogoutErr(goCtx, fmt.Sprintf("Logout error: %s", err.Error()))
			c.ResponseError(err.Error())
			return
		}

		if !affected {
			logLogoutErr(goCtx, "Logout error: token not found, invalid access token")
			c.ResponseError(c.T("token:Token not found, invalid accessToken"))
			return
		}

		if application == nil {
			logger.SetItem(goCtx, "obj", util.GetId(token.Organization, token.Application))
			logLogoutErr(goCtx, fmt.Sprintf("Logout error: application does not exist %s", token.Application))
			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist")), token.Application)
			return
		}

		logger.SetItem(goCtx, "obj", application.GetId())

		if userNameWithOrg == "" {
			userNameWithOrg = util.GetId(token.Organization, token.User)
			logger.SetItem(goCtx, "usr", userNameWithOrg)
		}

		c.ClearUserSession()
		// TODO https://github.com/casdoor/casdoor/pull/1494#discussion_r1095675265
		owner, username, err := util.SplitIdIntoOrgAndName(userNameWithOrg)
		if err != nil {
			record.AddReason(fmt.Sprintf("Logout error: %s", err.Error()))

			c.ResponseError(err.Error())
			return
		}
		record.WithUsername(username).WithOrganization(owner)

		_, err = object.DeleteSessionId(goCtx, util.GetSessionId(owner, username, object.CasdoorApplication), c.Ctx.Input.CruSession.SessionID())
		if err != nil {
			logger.SetItem(goCtx, "obj", object.CasdoorApplication)
			logLogoutErr(goCtx, fmt.Sprintf("Logout error: %s", err.Error()))
			c.ResponseError(err.Error())
			return
		}

		util.LogInfo(c.Ctx, "API: [%s] logged out", userNameWithOrg)

		if redirectUri == "" {
			logger.Info(goCtx,
				"",
				"obj-type", "application",
				"usr", userNameWithOrg,
				"obj", application.GetId(),
				"act", "logout",
				"r", "success",
			)
			c.ResponseOk()
			return
		} else {
			if application.IsRedirectUriValid(redirectUri) {
				logger.Info(goCtx,
					"",
					"obj-type", "application",
					"usr", userNameWithOrg,
					"obj", application.GetId(),
					"act", "logout",
					"r", "success",
				)
				c.Ctx.Redirect(http.StatusFound, fmt.Sprintf("%s?state=%s", strings.TrimRight(redirectUri, "/"), state))
			} else {
				logLogoutErr(goCtx, fmt.Sprintf("Logout error: wrong redirect URI: %s", redirectUri))
				c.ResponseError(fmt.Sprintf(c.T("token:Redirect URI: %s doesn't exist in the allowed Redirect URI list"), redirectUri))
				return
			}
		}
	}
}

func logLogoutErr(ctx context.Context, errText string) {
	record := object.GetRecordBuilderFromContext(ctx)
	record.AddReason(errText)

	logMsg := map[string]string{
		"error": errText,
	}

	logMsgStr, err := json.Marshal(logMsg)
	if err != nil {
		return
	}
	logger.Error(ctx,
		string(logMsgStr),
		"act", "logout",
		"r", "failure",
	)
}

// GetAccount
// @Title GetAccount
// @Tag Account API
// @Description get the details of the current account
// @Success 200 {object} controllers.Response The Response object
// @router /get-account [get]
func (c *ApiController) GetAccount() {
	var err error
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	managedAccounts := c.Input().Get("managedAccounts")
	if managedAccounts == "1" {
		user, err = object.ExtendManagedAccountsWithUser(user)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
	}

	err = object.ExtendUserWithRolesAndPermissions(user)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if user != nil {
		user.Permissions = object.GetMaskedPermissions(user.Permissions)
		user.Roles = object.GetMaskedRoles(user.Roles)
		user.MultiFactorAuths = object.GetAllMfaProps(user, true)
	}

	organization, err := object.GetMaskedOrganization(object.GetOrganizationByUser(user))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	isAdminOrSelf := c.IsAdminOrSelf(user)
	u, err := object.GetMaskedUser(user, isAdminOrSelf)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	resp := Response{
		Status: "ok",
		Sub:    user.Id,
		Name:   user.Name,
		Data:   u,
		Data2:  organization,
	}
	c.Data["json"] = resp
	c.ServeJSON()
}

// GetUserinfo
// UserInfo
// @Title UserInfo
// @Tag Account API
// @Description return user information according to OIDC standards
// @Success 200 {object} object.Userinfo The Response object
// @router /userinfo [get]
func (c *ApiController) GetUserinfo() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	scope, aud := c.GetSessionOidc()
	host := c.Ctx.Request.Host
	userInfo := object.GetUserInfo(user, scope, aud, host)

	c.Data["json"] = userInfo
	c.ServeJSON()
}

// GetUserinfo2
// LaravelResponse
// @Title UserInfo2
// @Tag Account API
// @Description return Laravel compatible user information according to OAuth 2.0
// @Success 200 {object} LaravelResponse The Response object
// @router /user [get]
func (c *ApiController) GetUserinfo2() {
	user, ok := c.RequireSignedInUser()
	if !ok {
		return
	}

	// this API is used by "Api URL" of Flarum's FoF Passport plugin
	// https://github.com/FriendsOfFlarum/passport
	type LaravelResponse struct {
		Id              string `json:"id"`
		Name            string `json:"name"`
		Email           string `json:"email"`
		EmailVerifiedAt string `json:"email_verified_at"`
		CreatedAt       string `json:"created_at"`
		UpdatedAt       string `json:"updated_at"`
	}

	response := LaravelResponse{
		Id:              user.Id,
		Name:            user.Name,
		Email:           user.Email,
		EmailVerifiedAt: user.CreatedTime,
		CreatedAt:       user.CreatedTime,
		UpdatedAt:       user.UpdatedTime,
	}

	c.Data["json"] = response
	c.ServeJSON()
}

// GetCaptcha ...
// @Tag Login API
// @Title GetCaptcha
// @Success 200 {object} controllers.Response "The Response object"
// @router /get-captcha [get]
func (c *ApiController) GetCaptcha() {
	applicationId := c.Input().Get("applicationId")
	isCurrentProvider := c.Input().Get("isCurrentProvider")
	goCtx := c.getRequestCtx()

	captchaProvider, err := object.GetCaptchaProviderByApplication(goCtx, applicationId, isCurrentProvider, c.GetAcceptLanguage())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if captchaProvider != nil {
		if captchaProvider.Type == "Default" {
			id, img, err := object.GetCaptcha()
			if err != nil {
				c.ResponseError(err.Error())
				return
			}

			c.ResponseOk(Captcha{Type: captchaProvider.Type, CaptchaId: id, CaptchaImage: img})
			return
		} else if captchaProvider.Type != "" {
			c.ResponseOk(Captcha{
				Type:          captchaProvider.Type,
				SubType:       captchaProvider.SubType,
				ClientId:      captchaProvider.ClientId,
				ClientSecret:  captchaProvider.ClientSecret,
				ClientId2:     captchaProvider.ClientId2,
				ClientSecret2: captchaProvider.ClientSecret2,
			})
			return
		}
	}

	c.ResponseOk(Captcha{Type: "none"})
}
