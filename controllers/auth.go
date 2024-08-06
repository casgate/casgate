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
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/captcha"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/idp"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/proxy"
	"github.com/casdoor/casdoor/role_mapper"
	"github.com/casdoor/casdoor/util"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	wechatScanType string
	lock           sync.RWMutex
)

type GetAuthURLResp struct {
	IsShortState bool   `json:"isShortState"`
	AuthQuery    string `json:"authQuery"`
	URL          string `json:"url"`
}

func codeToResponse(code *object.Code) *Response {
	if code.Code == "" {
		return &Response{Status: "error", Msg: code.Message, Data: code.Code}
	}

	return &Response{Status: "ok", Msg: "", Data: code.Code}
}

func tokenToResponse(token *object.Token) *Response {
	if token.AccessToken == "" {
		return &Response{Status: "error", Msg: "fail to get accessToken", Data: token.AccessToken}
	}
	return &Response{Status: "ok", Msg: "", Data: token.AccessToken, Data2: token.RefreshToken}
}

// HandleLoggedIn ...
func (c *ApiController) HandleLoggedIn(application *object.Application, user *object.User, form *form.AuthForm) (resp *Response) {
	userId := user.GetId()
	sid := c.getSid(userId)

	if user.Type == "invited-user" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	allowed, err := object.CheckLoginPermission(userId, application)
	if err != nil {
		c.ResponseError(err.Error(), nil)
		return
	}
	if !allowed {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	// check user's tag
	if !user.IsGlobalAdmin() && !user.IsAdmin && len(application.Tags) > 0 {
		// only users with the tag that is listed in the application tags can login
		if !util.InSlice(application.Tags, user.Tag) {
			c.ResponseError(fmt.Sprintf(c.T("auth:User's tag: %s is not listed in the application's tags"), user.Tag))
			return
		}
	}

	if form.Type == ResponseTypeLogin {
		c.SetSessionUsername(userId)
		util.LogInfo(c.Ctx, "API: [%s] signed in", userId)
		resp = &Response{Status: "ok", Msg: "", Data: userId}
	} else if form.Type == ResponseTypeCode {
		clientId := c.Input().Get("clientId")
		responseType := c.Input().Get("responseType")
		redirectUri := c.Input().Get("redirectUri")
		scope := c.Input().Get("scope")
		state := c.Input().Get("state")
		nonce := c.Input().Get("nonce")
		challengeMethod := c.Input().Get("code_challenge_method")
		codeChallenge := c.Input().Get("code_challenge")

		if challengeMethod != "S256" && challengeMethod != "null" && challengeMethod != "" {
			c.ResponseError(c.T("auth:Challenge method should be S256"))
			return
		}
		code, err := object.GetOAuthCode(userId, clientId, responseType, redirectUri, scope, state, nonce, codeChallenge, c.Ctx.Request.Host, sid, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseError(err.Error(), nil)
			return
		}

		resp = codeToResponse(code)

		if application.EnableSigninSession || application.HasPromptPage() {
			// The prompt page needs the user to be signed in
			c.SetSessionUsername(userId)
		}
	} else if form.Type == ResponseTypeToken || form.Type == ResponseTypeIdToken { // implicit flow
		if !object.IsGrantTypeValid(form.Type, application.GrantTypes) {
			resp = &Response{Status: "error", Msg: fmt.Sprintf("error: grant_type: %s is not supported in this application", form.Type), Data: ""}
		} else {
			scope := c.Input().Get("scope")
			token, _ := object.GetTokenByUser(application, user, scope, c.Ctx.Request.Host, sid)
			resp = tokenToResponse(token)
		}
	} else if form.Type == ResponseTypeSaml { // saml flow
		res, redirectUrl, method, err := object.GetSamlResponse(application, user, form.SamlRequest, c.Ctx.Request.Host)
		if err != nil {
			c.ResponseError(err.Error(), nil)
			return
		}
		resp = &Response{Status: "ok", Msg: "", Data: res, Data2: map[string]string{"redirectUrl": redirectUrl, "method": method}}

		if application.EnableSigninSession || application.HasPromptPage() {
			// The prompt page needs the user to be signed in
			c.SetSessionUsername(userId)
		}
	} else if form.Type == ResponseTypeCas {
		// not oauth but CAS SSO protocol
		service := c.Input().Get("service")
		resp = wrapErrorResponse(nil)
		if service != "" {
			st, err := object.GenerateCasToken(userId, service)
			if err != nil {
				resp = wrapErrorResponse(err)
			} else {
				resp.Data = st
			}
		}

		if application.EnableSigninSession || application.HasPromptPage() {
			// The prompt page needs the user to be signed in
			c.SetSessionUsername(userId)
		}
	} else {
		resp = wrapErrorResponse(fmt.Errorf("unknown response type: %s", form.Type))
	}

	// if user did not check auto signin
	if resp.Status == "ok" && !form.AutoSignin {
		c.setExpireForSession()
	}

	if resp.Status == "ok" {
		_, err = object.AddSession(&object.Session{
			Owner:       user.Owner,
			Name:        user.Name,
			Application: application.Name,
			SessionId:   []string{c.Ctx.Input.CruSession.SessionID()},
		})
		if err != nil {
			c.ResponseError(err.Error(), nil)
			return
		}
	}

	return resp
}

// GetApplicationLogin ...
// @Title GetApplicationLogin
// @Tag Login API
// @Description get application login
// @Param   clientId    query    string  true        "client id"
// @Param   responseType    query    string  true        "response type"
// @Param   redirectUri    query    string  true        "redirect uri"
// @Param   scope    query    string  true        "scope"
// @Param   state    query    string  true        "state"
// @Success 200 {object}  Response The Response object
// @router /get-app-login [get]
func (c *ApiController) GetApplicationLogin() {
	clientId := c.Input().Get("clientId")
	responseType := c.Input().Get("responseType")
	redirectUri := c.Input().Get("redirectUri")
	scope := c.Input().Get("scope")
	state := c.Input().Get("state")
	id := c.Input().Get("id")
	loginType := c.Input().Get("type")
	ctx := c.Ctx.Request.Context()

	var application *object.Application
	var msg string
	var err error
	if loginType == "code" {
		msg, application, err = object.CheckOAuthLogin(ctx, clientId, responseType, redirectUri, scope, state, c.GetAcceptLanguage())
		if err != nil {
			c.ResponseInternalServerError("internal server error")
			return
		}
	} else if loginType == "cas" {
		application, err = object.GetApplication(ctx, id)
		if err != nil {
			c.ResponseInternalServerError("internal server error")
			return
		}
		if application == nil {
			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), id))
			return
		}

		err = object.CheckCasLogin(application, c.GetAcceptLanguage(), redirectUri)
		if err != nil {
			c.ResponseInternalServerError("internal server error")
			return
		}
	}

	application = object.GetMaskedApplication(application, "")
	if msg != "" {
		c.ResponseError(msg, application)
	} else {
		c.ResponseOk(application)
	}
}

func setHttpClient(idProvider idp.IdProvider, providerInfo idp.ProviderInfo) error {
	if isProxyProviderType(providerInfo.Type) {
		idProvider.SetHttpClient(proxy.ProxyHttpClient)
	} else {
		client, err := object.GetProviderHttpClient(providerInfo)
		if err != nil {
			return err
		}
		idProvider.SetHttpClient(client)
	}

	return nil
}

func isProxyProviderType(providerType string) bool {
	providerTypes := []string{
		"GitHub",
		"Google",
		"Facebook",
		"LinkedIn",
		"Steam",
		"Line",
		"Amazon",
		"Instagram",
		"TikTok",
		"Twitter",
		"Uber",
		"Yahoo",
	}
	for _, v := range providerTypes {
		if strings.EqualFold(v, providerType) {
			return true
		}
	}
	return false
}

// Login ...
// @Title Login
// @Tag Login API
// @Description login
// @Param clientId        query    string  false clientId
// @Param responseType    query    string  false responseType
// @Param redirectUri     query    string  false redirectUri
// @Param scope     query    string  false  scope
// @Param state     query    string  false  state
// @Param nonce     query    string  false nonce
// @Param code_challenge_method   query    string  false code_challenge_method
// @Param code_challenge          query    string  false code_challenge
// @Param   form   body   controllers.AuthForm  true        "Login information"
// @Success 200 {object} controllers.Response The Response object
// @router /login [post]
func (c *ApiController) Login() {
	resp := &Response{}

	var authForm form.AuthForm
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &authForm)
	if err != nil {
		c.ResponseBadRequest("read request body error")
		return
	}

	goCtx := c.getRequestCtx()
	record := object.GetRecord(goCtx)
	
	if authForm.Username != "" {
		if authForm.Type == ResponseTypeLogin {
			if c.GetSessionUsername() != "" {
				record.AddReason("Login error: please sign out first")

				c.ResponseError(c.T("account:Please sign out first"), c.GetSessionUsername())
				return
			}
		}

		record.WithUsername(authForm.Username)

		var user *object.User
		var msg string

		if authForm.Password == "" {
			record.AddReason("Empty password")

			if user, err = object.GetUserByFields(authForm.Organization, authForm.Username); err != nil {
				record.AddReason("Login error: please sign out first")

				c.ResponseError(err.Error(), nil)
				return
			} else if user == nil {
				record.AddReason("Login error: User not found")

				c.ResponseError(fmt.Sprintf(c.T("general:Invalid username or password/code"), util.GetId(authForm.Organization, authForm.Username)))
				return
			}

			verificationCodeType := object.GetVerifyType(authForm.Username)
			var checkDest string
			if verificationCodeType == object.VerifyTypePhone {
				authForm.CountryCode = user.GetCountryCode(authForm.CountryCode)
				var ok bool
				if checkDest, ok = util.GetE164Number(authForm.Username, authForm.CountryCode); !ok {
					record.AddReason("Login error: invalid country code")

					c.ResponseError(fmt.Sprintf(c.T("verification:Phone number is invalid in your region %s"), authForm.CountryCode))
					return
				}
			}

			// check result through Email or Phone
			err := object.CheckSigninCode(goCtx, user, checkDest, authForm.Code, c.GetAcceptLanguage())
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s - %s", verificationCodeType, err.Error()))

				c.ResponseError(fmt.Sprintf("%s - %s", verificationCodeType, err.Error()))
				return
			}

			// disable the verification code
			err = object.DisableVerificationCode(checkDest)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseError(err.Error(), nil)
				return
			}
		} else {
			application, err := object.GetApplication(goCtx, fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseError(err.Error(), nil)
				return
			}

			if application == nil {
				record.AddReason(fmt.Sprintf("Login error: application does not exists: %s", authForm.Application))

				c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
				return
			}
			if authForm.SigninMethod == "Password" && !application.EnablePassword {
				record.AddReason("Login error: login with password is not enabled for the application")

				c.ResponseError(c.T("auth:The login method: login with password is not enabled for the application"))
				return
			}
			if authForm.SigninMethod == "LDAP" && !application.IsLdapEnabled() {
				c.ResponseError(c.T("auth:The login method: login with LDAP is not enabled for the application"))
				return
			}
			var enableCaptcha bool
			if enableCaptcha, err = object.CheckToEnableCaptcha(application, authForm.Organization, authForm.Username); err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			} else if enableCaptcha {
				isHuman, err := captcha.VerifyCaptchaByCaptchaType(authForm.CaptchaType, authForm.CaptchaToken, authForm.ClientSecret)
				if err != nil {
					record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

					c.ResponseInternalServerError("internal server error")
					return
				}

				if !isHuman {
					record.AddReason("Login error: turing test filed")

					c.ResponseError(c.T("verification:Turing test failed."))
					return
				}
			}

			isSigninViaLdap := authForm.SigninMethod == "LDAP"
			var isPasswordWithLdapEnabled bool
			if authForm.SigninMethod == "Password" {
				isPasswordWithLdapEnabled = application.IsPasswordWithLdapEnabled()
			} else {
				isPasswordWithLdapEnabled = false
			}

			if isSigninViaLdap {
				ldap, err := object.GetLdap(authForm.LdapId)
				if err != nil {
					record.AddReason(fmt.Sprintf("Get Ldap error: %s", err.Error()))

					c.ResponseError(c.T(fmt.Sprintf("auth:Failed to login in: %s", err.Error())))
				}
				if ldap == nil {
					record.AddReason(fmt.Sprintf("Cannot get Ldap \"%s\"", authForm.LdapId))

					c.ResponseError(c.T(fmt.Sprintf("auth:Failed to login in: %s", "Failed to get Ldap")))
				}

				if ldap != nil {
					if ldap.EnableCaseInsensitivity {
						user, err = object.GetUserByFieldsCaseInsensitively(authForm.Organization, authForm.Username)
					} else {
						user, err = object.GetUserByFields(authForm.Organization, authForm.Username)
					}
				}
				
				if err != nil {
					record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))
				}

				if user == nil {
					_, err = object.SyncUserFromLdap(goCtx, authForm.Organization, authForm.LdapId, authForm.Username, authForm.Password, c.GetAcceptLanguage(), record)
					if err != nil {
						record.AddReason(fmt.Sprintf("Ldap sync error: %s", err.Error()))
					}
				}
			}

			var userName = authForm.Username

			if user != nil && isSigninViaLdap {
				userName = user.Name
			}

	
			options := object.CheckUserPasswordOptions{
				Lang: c.GetAcceptLanguage(),
				LdapId:         authForm.LdapId,
				EnableCaptcha:  enableCaptcha,
				IsSigninViaLdap: isSigninViaLdap,
				IsPasswordWithLdapEnabled: isPasswordWithLdapEnabled,
			}

			user, err = object.CheckUserPassword(
				goCtx, 
				authForm.Organization, 
				userName, 
				authForm.Password,
				options)

			if err != nil {
				msg = object.CheckPassErrorToMessage(err, c.GetAcceptLanguage())
				record.AddReason(fmt.Sprintf("Error: %s", err.Error()))
			}

			if user != nil && user.Ldap != "" && (isSigninViaLdap || isPasswordWithLdapEnabled) {
				authForm.LdapId, err = object.CheckLdapUserPassword(user, authForm.Password, c.GetAcceptLanguage(), authForm.LdapId)
			}

			if err != nil {
				msg = object.CheckPassErrorToMessage(err, c.GetAcceptLanguage())
				record.AddReason(fmt.Sprintf("Error: %s", err.Error()))
			}
		}

		if msg != "" {
			resp = &Response{Status: "error", Msg: msg}
		} else {
			application, err := object.GetApplication(goCtx, fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}

			if application == nil {
				record.AddReason(fmt.Sprintf("Login error: application does not exists: %s", authForm.Application))

				c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
				return
			}

			organization, err := object.GetOrganizationByUser(user)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}

			if organization == nil {
				record.AddReason(fmt.Sprintf("Login error: Organization does not exist"))

				c.ResponseInternalServerError(c.T("check:Organization does not exist"))
				return
			}

			if object.IsNeedPromptMfa(organization, user) {
				// The prompt page needs the user to be signed in
				c.SetSessionUsername(user.GetId())
				c.ResponseOk(object.RequiredMfa)
				return
			}

			if user.IsMfaEnabled() {
				c.setMfaUserSession(user.GetId())
				c.ResponseOk(object.NextMfa, user.GetPreferredMfaProps(true))
				return
			}

			if user.IsPasswordChangeRequired() {
				c.setChangePasswordUserSession(user.GetId())
				c.ResponseOk(object.NextChangePasswordForm)
				return
			}

			resp = c.HandleLoggedIn(application, user, &authForm)

			if user.Ldap != "" {
				userIdProvider := &object.UserIdProvider{
					Owner:           organization.Name,
					LdapId:          authForm.LdapId,
					UsernameFromIdp: user.Name,
					LastSignInTime:  util.GetCurrentTime(),
				}

				err = object.UpdateUserIdProvider(c.Ctx.Request.Context(), userIdProvider, "ldap_id")

				if err != nil {
					record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

					c.ResponseInternalServerError("internal server error")
					return
				}
			}

			record.WithUsername(user.Name).WithOrganization(application.Organization).AddReason("User logged in")
		}
	} else if authForm.Provider != "" {
		var application *object.Application
		if authForm.ClientId != "" {
			application, err = object.GetApplicationByClientId(goCtx, authForm.ClientId)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}
		} else {
			application, err = object.GetApplicationWithOpts(
				goCtx, fmt.Sprintf("admin/%s", authForm.Application), &object.GetApplicationOptions{InitOpenIDProvider: true},
			)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}
		}

		if application == nil {
			record.AddReason(fmt.Sprintf("Login error: the application does not exists: %s", err.Error()))

			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
			return
		}
		organization, err := object.GetOrganization(util.GetId("admin", application.Organization))
		if err != nil {
			record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

			c.ResponseError(c.T(err.Error()))
		}

		providerID := util.GetId(application.Organization, authForm.Provider)
		provider, err := object.GetProvider(providerID)
		if err != nil {
			record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

			c.ResponseInternalServerError("internal server error")
			return
		}
		if provider == nil {
			record.AddReason(fmt.Sprintf("Could not find provider with id: %s", providerID))

			c.ResponseInternalServerError("internal server error")
			return
		}

		providerItem := application.GetProviderItem(provider.Name)
		if !providerItem.IsProviderVisible() {
			record.AddReason(fmt.Sprintf("Login error: provider is not enabled for the application: %s", provider.Name))

			c.ResponseError(fmt.Sprintf(c.T("auth:The provider: %s is not enabled for the application"), provider.Name))
			return
		}

		userInfo := &idp.UserInfo{}
		var authData map[string]interface{}
		if provider.Category == "SAML" {
			// SAML
			userInfo, authData, err = object.ParseSamlResponse(authForm.SamlResponse, provider, c.Ctx.Request.Host)
			if err != nil {
				record.AddReason(fmt.Sprintf("SAML login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}
		} else if provider.Category == "OAuth" || provider.Category == "Web3" {
			// OAuth
			idpInfo := object.FromProviderToIdpInfo(c.Ctx, provider)
			idProvider := idp.GetIdProvider(idpInfo, authForm.RedirectUri)
			if idProvider == nil {
				record.AddReason(fmt.Sprintf("Login error: provider type is not supported: %s", provider.Type))

				c.ResponseError(fmt.Sprintf(c.T("storage:The provider type: %s is not supported"), provider.Type))
				return
			}

			err = setHttpClient(idProvider, *idpInfo)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}

			if authForm.State != conf.GetConfigString("authState") && authForm.State != application.Name {
				record.AddReason(fmt.Sprintf("Login error: mismatch state: %s got: %s", conf.GetConfigString("authState"), authForm.State))

				c.ResponseError(fmt.Sprintf(c.T("auth:State expected: %s, but got: %s"), conf.GetConfigString("authState"), authForm.State))
				return
			}

			// https://github.com/golang/oauth2/issues/123#issuecomment-103715338
			token, err := idProvider.GetToken(authForm.Code)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseUnauthorized("wrong client id")
				return
			}

			if !token.Valid() {
				record.AddReason("Login error: invalid token")

				c.ResponseError(c.T("auth:Invalid token"))
				return
			}

			userInfo, err = idProvider.GetUserInfo(token)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseError(fmt.Sprintf(c.T("auth:Failed to login in: %s"), err.Error()))
				return
			}

			if provider.Category == "OAuth" {
				// decode JWT token without verifying the signature to fill authData
				jwtToken, _ := jwt.ParseSigned(token.AccessToken)
				if jwtToken != nil {
					err = jwtToken.UnsafeClaimsWithoutVerification(&authData)
					if err != nil {
						record.AddReason("Login error: invalid token")

						c.ResponseError(c.T("auth:Invalid token"))
						return
					}
				}

				if provider.Type == "OpenID" && len(userInfo.AdditionalInfo) != 0 {
					//add userInfo and tokenId to authData

					maps.Copy(authData, userInfo.AdditionalInfo)

					idToken, _ := token.Extra("id_token").(string)
					jwtIdToken, _ := jwt.ParseSigned(idToken)

					err = jwtIdToken.UnsafeClaimsWithoutVerification(&authData)
					if err != nil {
						record.AddReason("Login error: invalid id token")

						c.ResponseError(c.T("auth:Invalid id token"))
						return
					}
				}
			}
		}

		if authForm.Method == "signup" {
			user := &object.User{}
			if provider.Category == "OAuth" || provider.Category == "Web3" || provider.Category == "SAML" {
				user, err = object.GetUserByField(application.Organization, provider.Type, userInfo.Id)
				if err != nil {
					record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))
					c.ResponseInternalServerError("internal server error")
					return
				}
			}

			if user != nil && !user.IsDeleted {
				// Sign in via OAuth (want to sign up but already have account)

				if user.IsForbidden {
					record.AddReason("Login error: user forbidden to sign in")

					c.ResponseError(c.T("check:The user is forbidden to sign in, please contact the administrator"))
					return
				}

				resp = c.HandleLoggedIn(application, user, &authForm)
				record.WithUsername(user.Name).WithOrganization(application.Organization).AddReason("User logged in")

				if jsonProvider, err := json.Marshal(provider); err == nil {
					record.AddReason(fmt.Sprintf("provider: %s", jsonProvider))
				}

				err = object.UpdateUserIdProvider(c.Ctx.Request.Context(), &object.UserIdProvider{
					Owner:           organization.Name,
					ProviderName:    provider.Name,
					UsernameFromIdp: userInfo.Username,
					LastSignInTime:  util.GetCurrentTime(),
				}, "provider_name")
				if err != nil {
					record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

					c.ResponseInternalServerError(err.Error())
					return
				}
			} else if provider.Category == "OAuth" || provider.Category == "Web3" || provider.Category == "SAML" {
				// Sign up via OAuth/Web3/SAML
				if application.EnableLinkWithEmail {
					if userInfo.Email != "" {
						// Find existing user with Email
						user, err = object.GetUserByField(application.Organization, "email", userInfo.Email)
						if err != nil {
							record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

							c.ResponseInternalServerError("internal server error")
							return
						}
					}

					if user == nil && userInfo.Phone != "" {
						// Find existing user with phone number
						user, err = object.GetUserByField(application.Organization, "phone", userInfo.Phone)
						if err != nil {
							record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

							c.ResponseInternalServerError("internal server error")
							return
						}
					}
				}

				if user == nil || user.IsDeleted {
					if !application.EnableInternalSignUp && !application.EnableIdpSignUp {
						record.AddReason(fmt.Sprintf("Login error: provider: %s, username: %s, (%s) does not allowed to sign up as new account", provider.Type, userInfo.Username, userInfo.DisplayName))

						c.ResponseError(fmt.Sprintf(c.T("auth:The account for provider: %s and username: %s (%s) does not exist and is not allowed to sign up as new account, please contact your IT support"), provider.Type, userInfo.Username, userInfo.DisplayName))
						return
					}

					if !providerItem.CanSignUp {
						record.AddReason(fmt.Sprintf("Login error: provider: %s, username: %s, (%s) does not allowed to sign up as new account via %s", provider.Type, userInfo.Username, userInfo.DisplayName, provider.Type))

						c.ResponseError(fmt.Sprintf(c.T("auth:The account for provider: %s and username: %s (%s) does not exist and is not allowed to sign up as new account via %%s, please use another way to sign up"), provider.Type, userInfo.Username, userInfo.DisplayName, provider.Type))
						return
					}

					// Handle username conflicts
					tmpUser, err := object.GetUser(util.GetId(application.Organization, userInfo.Username))
					if err != nil {
						record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

						c.ResponseInternalServerError("internal server error")
						return
					}

					if tmpUser != nil {
						uid, err := uuid.NewRandom()
						if err != nil {
							record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

							c.ResponseInternalServerError("internal server error")
							return
						}

						uidStr := strings.Split(uid.String(), "-")
						userInfo.Username = fmt.Sprintf("%s_%s", userInfo.Username, uidStr[1])
					}

					properties := map[string]string{}
					count, err := object.GetUserCount(application.Organization, "", "", "")
					if err != nil {
						record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

						c.ResponseInternalServerError("internal server error")
						return
					}

					properties["no"] = strconv.Itoa(int(count + 2))
					initScore, err := organization.GetInitScore()
					if err != nil {
						record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

						c.ResponseError(fmt.Errorf(c.T("account:Get init score failed, error: %w"), err).Error())
						return
					}

					var userId string
					if provider.Category != "SAML" {
						userId = userInfo.Id
					}
					if userId == "" {
						userId = util.GenerateId()
					}

					user = &object.User{
						Owner:             application.Organization,
						Name:              userInfo.Username,
						CreatedTime:       util.GetCurrentTime(),
						Id:                userId,
						Type:              "normal-user",
						DisplayName:       userInfo.DisplayName,
						Avatar:            userInfo.AvatarUrl,
						Address:           []string{},
						Email:             userInfo.Email,
						Phone:             userInfo.Phone,
						CountryCode:       userInfo.CountryCode,
						Region:            userInfo.CountryCode,
						Score:             initScore,
						IsAdmin:           false,
						IsForbidden:       false,
						IsDeleted:         false,
						SignupApplication: application.Name,
						Properties:        properties,
						MappingStrategy:   application.UserMappingStrategy,
					}

					affected, err := object.AddUser(goCtx, user)
					if err != nil {
						record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

						c.ResponseInternalServerError("internal server error")
						return
					}

					if !affected {
						record.AddReason(fmt.Sprintf("Login error: user information is invalid: %s", util.StructToJson(user)))

						c.ResponseError(fmt.Sprintf(c.T("auth:Failed to create user, user information is invalid")))
						return
					}
				}

				if provider.Category != "SAML" {
					// sync info from 3rd-party if possible
					_, err := object.SetUserOAuthProperties(organization, user, provider.Type, userInfo)
					if err != nil {
						record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

						c.ResponseInternalServerError("internal server error")
						return
					}
				}

				_, err = object.LinkUserAccount(user, provider.Type, userInfo.Id)
				if err != nil {
					record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

					c.ResponseInternalServerError("internal server error")
					return
				}

				_, err = object.AddUserIdProvider(c.Ctx.Request.Context(), &object.UserIdProvider{
					ProviderName:    provider.Name,
					UserId:          user.Id,
					UsernameFromIdp: userInfo.Username,
					Owner:           organization.Name,
					LastSignInTime:  util.GetCurrentTime(),
					CreatedTime:     util.GetCurrentTime(),
				})
				if err != nil {
					record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

					c.ResponseInternalServerError("internal server error")
					return
				}

				resp = c.HandleLoggedIn(application, user, &authForm)

				record.WithAction("signup").WithUsername(user.Name).WithOrganization(application.Organization).AddReason("User logged in")
			}

			if resp.Status == "ok" {
				if len(provider.UserMapping) > 0 {
					record.AddReason("Start attribute mapping")
					err = object.SyncAttributesToUser(user, userInfo.DisplayName, userInfo.Email, userInfo.Phone, userInfo.AvatarUrl, user.Address)
					if err != nil {
						record.AddReason(fmt.Sprintf("Attribute mapping error: %s", err.Error()))

						c.ResponseInternalServerError("internal server error")
						return
					}
					record.AddReason("Finish attribute mapping")
				}

				if provider.EnableRoleMapping {
					record.AddReason("Start role mapping")
					mapper, err := role_mapper.NewRoleMapper(provider.Category, provider.RoleMappingItems, authData)
					if err != nil {
						record.AddReason(fmt.Sprintf("Role mapping error: %s", err.Error()))

						c.ResponseInternalServerError("internal server error")
						return
					}

					userRoles := mapper.GetRoles()
					err = object.SyncRolesToUser(user, userRoles)
					if err != nil {
						record.AddReason(fmt.Sprintf("Role mapping error: %s", err.Error()))

						c.ResponseInternalServerError("internal server error")
						return
					}
					record.AddReason("Finish role mapping")
				}
			}
		} else { // authForm.Method != "signup"
			userId := c.GetSessionUsername()
			if userId == "" {
				record.AddReason("Login error: invalid username or password")

				c.ResponseError(fmt.Sprintf(c.T("general:Invalid username or password/code"), util.GetId(application.Organization, userInfo.Id)), userInfo)
				return
			}

			oldUser, err := object.GetUserByField(application.Organization, provider.Type, userInfo.Id)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}

			if oldUser != nil {
				record.AddReason(fmt.Sprintf("Login error: provider: %s and username: %s (%s) is already linked to another account %s (%s)", provider.Type, userInfo.Username, userInfo.DisplayName, oldUser.Name, oldUser.DisplayName))

				c.ResponseError(fmt.Sprintf(c.T("auth:The account for provider: %s and username: %s (%s) is already linked to another account: %s (%s)"), provider.Type, userInfo.Username, userInfo.DisplayName, oldUser.Name, oldUser.DisplayName))
				return
			}

			user, err := object.GetUser(userId)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}

			// sync info from 3rd-party if possible
			_, err = object.SetUserOAuthProperties(organization, user, provider.Type, userInfo)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}

			isLinked, err := object.LinkUserAccount(user, provider.Type, userInfo.Id)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}

			if isLinked {
				resp = &Response{Status: "ok", Msg: "", Data: isLinked}
			} else {
				resp = &Response{Status: "error", Msg: "Failed to link user account", Data: isLinked}
			}
		}
	} else if c.getMfaUserSession() != "" {
		user, err := object.GetUser(c.getMfaUserSession())
		if err != nil {
			record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

			c.ResponseInternalServerError("internal server error")
			return
		}
		if user == nil {
			record.AddReason("Login error: expired user session")

			c.ResponseError("expired user session")
			return
		}

		if authForm.Passcode != "" {
			mfaUtil := object.GetMfaUtil(authForm.MfaType, user.GetPreferredMfaProps(false))
			if mfaUtil == nil {
				record.AddReason("Login error: invalid multi-factor authentication type")

				c.ResponseError("Invalid multi-factor authentication type")
				return
			}

			err = mfaUtil.Verify(authForm.Passcode)
			if err != nil {
				record.AddReason("OTP was wrong")

				c.ResponseUnprocessableEntity("OTP was wrong")
				return
			}
		} else if authForm.RecoveryCode != "" {
			err = object.MfaRecover(user, authForm.RecoveryCode)
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}
		} else {
			record.AddReason("missing passcode or recovery code")

			c.ResponseError("missing passcode or recovery code")
			return
		}

		application, err := object.GetApplication(goCtx, fmt.Sprintf("admin/%s", authForm.Application))
		if err != nil {
			record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

			c.ResponseInternalServerError("internal server error")
			return
		}

		if application == nil {
			record.AddReason(fmt.Sprintf("Login error: application: %s doens not exists", authForm.Application))

			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
			return
		}

		if user.IsPasswordChangeRequired() {
			c.setChangePasswordUserSession(user.GetId())
			c.setMfaUserSession("")
			c.ResponseOk(object.NextChangePasswordForm)
			return
		}

		resp = c.HandleLoggedIn(application, user, &authForm)
		c.setMfaUserSession("")

		record.WithOrganization(application.Organization).WithUsername(user.Name).AddReason("MFA success")
	} else if c.getChangePasswordUserSession() != "" {
		user, err := object.GetUser(c.getChangePasswordUserSession())
		if err != nil {
			record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

			c.ResponseInternalServerError("internal server error")
			return
		}
		if user == nil {
			record.AddReason("expired user session")

			c.ResponseError("expired user session")
			return
		}

		if user.IsPasswordChangeRequired() {
			c.ResponseOk(object.NextChangePasswordForm)
			return
		}

		application, err := object.GetApplication(goCtx, fmt.Sprintf("admin/%s", authForm.Application))
		if err != nil {
			record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

			c.ResponseInternalServerError("internal server error")
			return
		}

		if application == nil {
			record.AddReason(fmt.Sprintf("Login error: application %s does not exist", authForm.Application))

			c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
			return
		}

		resp = c.HandleLoggedIn(application, user, &authForm)
		c.setChangePasswordUserSession("")

		record.WithOrganization(application.Organization).WithUsername(user.Name).AddReason("Changed password")
	} else {
		if c.GetSessionUsername() != "" {
			// user already signed in to Casdoor, so let the user click the avatar button to do the quick sign-in
			application, err := object.GetApplication(goCtx, fmt.Sprintf("admin/%s", authForm.Application))
			if err != nil {
				record.AddReason(fmt.Sprintf("Login error: %s", err.Error()))

				c.ResponseInternalServerError("internal server error")
				return
			}

			if application == nil {
				record.AddReason(fmt.Sprintf("Login error: application %s does not exist", authForm.Application))

				c.ResponseError(fmt.Sprintf(c.T("auth:The application: %s does not exist"), authForm.Application))
				return
			}

			user := c.getCurrentUser()
			resp = c.HandleLoggedIn(application, user, &authForm)

			record.WithOrganization(application.Organization).WithUsername(user.Name).AddReason("Quick sign in")
		} else {
			record.AddReason("Login error: Unknown authentication type (not password or provider)")

			c.ResponseError(fmt.Sprintf(c.T("auth:Unknown authentication type (not password or provider), form = %s"), util.StructToJson(authForm)))
			return
		}
	}

	c.Data["json"] = resp
	c.ServeJSON()
}

func (c *ApiController) GetSamlLogin() {
	providerId := c.Input().Get("id")
	relayState := c.Input().Get("relayState")
	authURL, method, err := object.GenerateSamlRequest(providerId, relayState, c.Ctx.Request.Host, c.GetAcceptLanguage())
	if err != nil {
		logs.Error("generate SAML request: %s", err.Error())

		c.ResponseInternalServerError("Create SAML request error")
		return
	}

	c.ResponseOk(authURL, method)
}

func (c *ApiController) HandleSamlLogin() {
	relayState := c.Input().Get("RelayState")
	samlResponse := c.Input().Get("SAMLResponse")
	decode, err := base64.StdEncoding.DecodeString(relayState)
	if err != nil {
		c.ResponseBadRequest("decoding relay state error")
		return
	}
	slice := strings.Split(string(decode), "&")
	relayState = url.QueryEscape(relayState)
	samlResponse = url.QueryEscape(samlResponse)
	targetUrl := fmt.Sprintf("%s?relayState=%s&samlResponse=%s",
		slice[4], relayState, samlResponse)
	c.Redirect(targetUrl, 303)
}

// HandleOfficialAccountEvent ...
// @Tag HandleOfficialAccountEvent API
// @Title HandleOfficialAccountEvent
// @Success 200 {object} controllers.Response "The Response object"
// @router /webhook [POST]
func (c *ApiController) HandleOfficialAccountEvent() {
	respBytes, err := ioutil.ReadAll(c.Ctx.Request.Body)
	if err != nil {
		c.ResponseBadRequest("read body error")
		return
	}

	var data struct {
		MsgType  string `xml:"MsgType"`
		Event    string `xml:"Event"`
		EventKey string `xml:"EventKey"`
	}
	err = xml.Unmarshal(respBytes, &data)
	if err != nil {
		c.ResponseBadRequest("unmarshall body error")
		return
	}

	lock.Lock()
	defer lock.Unlock()
	if data.EventKey != "" {
		wechatScanType = data.Event
		c.Ctx.WriteString("")
	}
}

// GetWebhookEventType ...
// @Tag GetWebhookEventType API
// @Title GetWebhookEventType
// @Success 200 {object} controllers.Response "The Response object"
// @router /get-webhook-event [GET]
func (c *ApiController) GetWebhookEventType() {
	lock.Lock()
	defer lock.Unlock()
	resp := &Response{
		Status: "ok",
		Msg:    "",
		Data:   wechatScanType,
	}
	c.Data["json"] = resp
	wechatScanType = ""
	c.ServeJSON()
}

// GetCaptchaStatus
// @Title GetCaptchaStatus
// @Tag Token API
// @Description Get Login Error Counts
// @Param   id     query    string  true        "The id ( owner/name ) of user"
// @Success 200 {object} controllers.Response The Response object
// @router /get-captcha-status [get]
func (c *ApiController) GetCaptchaStatus() {
	organization := c.Input().Get("organization")
	userId := c.Input().Get("user_id")
	user, err := object.GetUserByFields(organization, userId)
	if err != nil {
		c.ResponseInternalServerError("internal server error")
		return
	}

	var captchaEnabled bool
	if user != nil && user.SigninWrongTimes >= object.SigninWrongTimesLimit {
		captchaEnabled = true
	}
	c.ResponseOk(captchaEnabled)
}

// Callback
// @Title Callback
// @Tag Callback API
// @Description Get Login Error Counts
// @Success 200 {object} controllers.Response "The Response object"
// @router /callback [post]
func (c *ApiController) Callback() {
	code := c.GetString("code")
	state := c.GetString("state")

	frontendCallbackUrl := fmt.Sprintf("/callback?code=%s&state=%s", code, state)
	c.Ctx.Redirect(http.StatusFound, frontendCallbackUrl)
}

// GetAuthURL ...
// @Title GetAuthURL
// @Tag Login API
// @Description get auth url
// @Param   providerID        query    string  true        "The id ( owner/name ) of the provider"
// @Param   applicationID     query    string  true        "The id ( owner/name ) of the application"
// @Param   method            query    string  true        "Query method"
// @Success 200 {object}  Response The Response object
// @Failure 400 Bad Request
// @Failure 404 Not Found
// @Failure 500 Internal Server Error
// @router /get-auth-url [get]
func (c *ApiController) GetAuthURL() {
	goCtx := c.getRequestCtx()

	applicationID := c.Input().Get("applicationID")
	providerID := c.Input().Get("providerID")
	method := c.Input().Get("method")

	if applicationID == "" || providerID == "" {
		c.ResponseNotFound("Missing required parameters")
		return
	}

	redirectURI := fmt.Sprintf("%s://%s/callback", getScheme(c.Ctx.Request), c.Ctx.Request.Host)
	userAgent := c.Ctx.Request.UserAgent()

	application, err := object.GetApplicationWithOpts(goCtx, applicationID, &object.GetApplicationOptions{InitOpenIDProvider: true})
	if err != nil {
		c.ResponseInternalServerError(fmt.Sprintf("Get application: %s", applicationID))
		return
	}
	var provider *object.Provider
	for _, p := range application.Providers {
		if providerID == p.Provider.GetId() {
			provider = p.Provider
			break
		}
	}
	if provider == nil {
		c.ResponseNotFound(fmt.Sprintf("Could not find provider: %s in application: %s", providerID, applicationID))
		return
	}

	isShortState := provider.Type == "WeChat" && strings.Contains(userAgent, "MicroMessenger")

	authQuery, err := getAuthQuery(application.Name, provider.Name, method, redirectURI, c.Ctx.Request.URL.RawQuery)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}
	state := getStateFromQueryParams(authQuery, provider.Name, isShortState)
	authInfo, err := object.GetAuthInfo(provider.Type)
	if err != nil {
		c.ResponseBadRequest(err.Error())
		return
	}

	endpoint := authInfo.Endpoint()
	if provider.Type == "AzureAD" && provider.Domain != "" {
		endpoint = strings.Replace(endpoint, "common", provider.Domain, -1)
	} else if provider.Type == "Apple" {
		redirectURI = fmt.Sprintf("%s/api/callback", redirectURI)
	}
	url, err := buildAuthURL(provider, authInfo, endpoint, redirectURI, state, userAgent, c.Ctx.Request.Host)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}
	resp := GetAuthURLResp{
		IsShortState: isShortState,
		AuthQuery:    authQuery,
		URL:          url,
	}
	c.ResponseOk(resp)
}

func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func getAuthQuery(applicationName, providerName, method, currentURL, currentPath string) (string, error) {
	queryParams, err := url.ParseQuery(currentURL)
	if err != nil {
		return "", err
	}
	queryParams.Add("application", applicationName)
	queryParams.Add("provider", providerName)
	queryParams.Add("method", method)

	if method == "link" {
		queryParams.Add("from", currentPath)
	}

	return queryParams.Encode(), nil
}

func getStateFromQueryParams(authQuery, providerName string, isShortState bool) string {
	if !isShortState {
		result := base64.StdEncoding.EncodeToString([]byte(authQuery))
		return string(result)
	}
	return providerName
}

func buildAuthURL(provider *object.Provider, authInfo *object.AuthInfo, endpoint, redirectURI, state, userAgent, host string) (string, error) {
	const codeChallenge = "P3S-a7dr8bgM4bF6vOyiKkKETDl16rcAzao9F8UIL1Y" // SHA256(Base64-URL-encode("casdoor-verifier"))

	switch provider.Type {
	case "Google", "GitHub", "QQ", "Facebook", "Weibo", "Gitee", "LinkedIn", "GitLab", "AzureAD",
		"Slack", "Line", "Amazon", "Auth0", "BattleNet", "Bitbucket", "Box", "CloudFoundry",
		"Dailymotion", "DigitalOcean", "Discord", "Dropbox", "EveOnline", "Gitea", "Heroku",
		"InfluxCloud", "Instagram", "Intercom", "Kakao", "MailRu", "Meetup", "MicrosoftOnline",
		"Naver", "Nextcloud", "OneDrive", "Oura", "Patreon", "PayPal", "SalesForce", "SoundCloud",
		"Spotify", "Strava", "Stripe", "Tumblr", "Twitch", "Typetalk", "Uber", "VK", "Wepay", "Xero",
		"Yahoo", "Yammer", "Yandex", "Zoom":
		return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&state=%s",
			endpoint, provider.ClientId, redirectURI, authInfo.Scope(), state), nil
	case "DingTalk":
		return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&prompt=consent&state=%s",
			endpoint, provider.ClientId, redirectURI, authInfo.Scope(), state), nil
	case "WeChat":
		if strings.Contains(userAgent, "MicroMessenger") {
			mpEndpoint, err := authInfo.MPEndpoint()
			if err != nil {
				return "", err
			}
			mpScope, err := authInfo.MPScope()
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s?appid=%s&redirect_uri=%s&state=%s&scope=%s&response_type=code#wechat_redirect",
				mpEndpoint, provider.ClientId2, redirectURI, state, mpScope), nil
		}
		return fmt.Sprintf("%s?appid=%s&redirect_uri=%s&scope=%s&response_type=code&state=%s#wechat_redirect",
			endpoint, provider.ClientId, redirectURI, authInfo.Scope(), state), nil
	case "WeCom":
		switch provider.SubType {
		case "Internal":
			if provider.Method == "Silent" {
				endpoint, err := authInfo.SilentEndpoint()
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%s?appid=%s&redirect_uri=%s&state=%s&scope=%s&response_type=code#wechat_redirect",
					endpoint, provider.ClientId, redirectURI, state, authInfo.Scope()), nil
			} else if provider.Method == "Normal" {
				endpoint, err := authInfo.InternalEndpoint()
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%s?appid=%s&agentid=%s&redirect_uri=%s&state=%s&usertype=member",
					endpoint, provider.ClientId, provider.AppId, redirectURI, state), nil
			} else {
				return fmt.Sprintf("https://error:not-supported-provider-method:%s", provider.Method), nil
			}
		case "Third-party":
			if provider.Method == "Silent" {
				endpoint, err := authInfo.SilentEndpoint()
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%s?appid=%s&redirect_uri=%s&state=%s&scope=%s&response_type=code#wechat_redirect",
					endpoint, provider.ClientId, redirectURI, state, authInfo.Scope()), nil
			} else if provider.Method == "Normal" {
				return fmt.Sprintf("%s?appid=%s&redirect_uri=%s&state=%s&usertype=member",
					endpoint, provider.ClientId, redirectURI, state), nil
			} else {
				return fmt.Sprintf("https://error:not-supported-provider-method:%s", provider.Method), nil
			}
		default:
			return fmt.Sprintf("https://error:not-supported-provider-sub-type:%s", provider.SubType), nil
		}
	case "Lark":
		return fmt.Sprintf("%s?app_id=%s&redirect_uri=%s&state=%s", endpoint, provider.ClientId, redirectURI, state), nil
	case "ADFS":
		return fmt.Sprintf("%s/adfs/oauth2/authorize?client_id=%s&redirect_uri=%s&state=%s&response_type=code&nonce=casdoor&scope=openid",
			provider.Domain, provider.ClientId, redirectURI, state), nil
	case "Baidu":
		return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s&response_type=code&scope=%s&display=popup",
			endpoint, provider.ClientId, redirectURI, state, authInfo.Scope()), nil
	case "Alipay":
		return fmt.Sprintf("%s?app_id=%s&scope=auth_user&redirect_uri=%s&state=%s&response_type=code&scope=%s&display=popup",
			endpoint, provider.ClientId, redirectURI, state, authInfo.Scope()), nil
	case "Casdoor":
		return fmt.Sprintf("%s/login/oauth/authorize?client_id=%s&redirect_uri=%s&state=%s&response_type=code&scope=%s",
			provider.Domain, provider.ClientId, redirectURI, state, authInfo.Scope()), nil
	case "Infoflow":
		return fmt.Sprintf("%s?appid=%s&redirect_uri=%s?state=%s", endpoint, provider.ClientId, redirectURI, state), nil
	case "Apple":
		return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s&response_type=code%%20id_token&scope=%s&response_mode=form_post",
			endpoint, provider.ClientId, redirectURI, state, authInfo.Scope()), nil
	case "Steam":
		return fmt.Sprintf("%s?openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select&openid.identity=http://specs.openid.net/auth/2.0/identifier_select&openid.mode=checkid_setup&openid.ns=http://specs.openid.net/auth/2.0&openid.realm=%s&openid.return_to=%s?state=%s",
			endpoint, host, redirectURI, state), nil
	case "Okta":
		return fmt.Sprintf("%s/v1/authorize?client_id=%s&redirect_uri=%s&state=%s&response_type=code&scope=%s",
			provider.Domain, provider.ClientId, redirectURI, state, authInfo.Scope()), nil
	case "Douyin", "TikTok":
		return fmt.Sprintf("%s?client_key=%s&redirect_uri=%s&state=%s&response_type=code&scope=%s",
			endpoint, provider.ClientId, redirectURI, state, authInfo.Scope()), nil
	case "Custom", "OpenID":
		return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&state=%s",
			provider.CustomAuthUrl, provider.ClientId, redirectURI, provider.Scopes, state), nil
	case "Bilibili":
		return fmt.Sprintf("%s#/?client_id=%s&return_url=%s&state=%s&response_type=code",
			endpoint, provider.ClientId, redirectURI, state), nil
	case "Deezer":
		return fmt.Sprintf("%s?app_id=%s&redirect_uri=%s&perms=%s", endpoint, provider.ClientId, redirectURI, authInfo.Scope()), nil
	case "Lastfm":
		return fmt.Sprintf("%s?api_key=%s&cb=%s", endpoint, provider.ClientId, redirectURI), nil
	case "Shopify":
		return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&state=%s&grant_options[]=per-user",
			endpoint, provider.ClientId, redirectURI, authInfo.Scope(), state), nil
	case "Twitter", "Fitbit":
		return fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&state=%s&response_type=code&scope=%s&code_challenge=%s&code_challenge_method=S256",
			endpoint, provider.ClientId, redirectURI, state, authInfo.Scope(), codeChallenge), nil
	case "MetaMask", "Web3Onboard":
		return fmt.Sprintf("%s?state=%s", redirectURI, state), nil
	default:
		return "https://error:unsupported-provider-type", nil
	}
}
