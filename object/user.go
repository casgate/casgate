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
	"slices"
	"strings"
	"time"

	"github.com/casdoor/casdoor/orm"

	"github.com/beego/beego/logs"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/xorm-io/builder"
	"github.com/xorm-io/core"

	"github.com/casdoor/casdoor/util"
)

const (
	UserPropertiesWechatUnionId = "wechatUnionId"
	UserPropertiesWechatOpenId  = "wechatOpenId"
	NextChangePasswordForm      = "NextChangePasswordForm"
	ChangePasswordSessionId     = "ChangePasswordSessionId"
)

const UserEnforcerId = "built-in/user-enforcer-built-in"

var userEnforcer *UserGroupEnforcer
var userMaxPasswordLength int

func InitUserManager() {
	enforcer, err := GetInitializedEnforcer(UserEnforcerId)
	if err != nil {
		panic(err)
	}

	userEnforcer = NewUserGroupEnforcer(enforcer.Enforcer)
}

type User struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(255) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100) index" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`

	Id                     string    `xorm:"varchar(100) index unique" json:"id"`
	Type                   string    `xorm:"varchar(100)" json:"type"`
	Password               string    `xorm:"varchar(100)" json:"password"`
	PasswordChangeRequired bool      `xorm:"-" json:"passwordChangeRequired"`
	PasswordChangeTime     time.Time `json:"-"`
	PasswordSalt           string    `xorm:"varchar(100)" json:"passwordSalt"`
	PasswordType           string    `xorm:"varchar(100)" json:"passwordType"`
	DisplayName            string    `xorm:"varchar(255)" json:"displayName"`
	FirstName              string    `xorm:"varchar(100)" json:"firstName"`
	LastName               string    `xorm:"varchar(100)" json:"lastName"`
	Avatar                 string    `xorm:"varchar(500)" json:"avatar"`
	AvatarType             string    `xorm:"varchar(100)" json:"avatarType"`
	PermanentAvatar        string    `xorm:"varchar(500)" json:"permanentAvatar"`
	Email                  string    `xorm:"varchar(255) index" json:"email"`
	EmailVerified          bool      `json:"emailVerified"`
	Phone                  string    `xorm:"varchar(20) index" json:"phone"`
	CountryCode            string    `xorm:"varchar(6)" json:"countryCode"`
	Region                 string    `xorm:"varchar(100)" json:"region"`
	Location               string    `xorm:"varchar(100)" json:"location"`
	Address                []string  `json:"address"`
	Affiliation            string    `xorm:"varchar(100)" json:"affiliation"`
	Title                  string    `xorm:"varchar(100)" json:"title"`
	IdCardType             string    `xorm:"varchar(100)" json:"idCardType"`
	IdCard                 string    `xorm:"varchar(100) index" json:"idCard"`
	Homepage               string    `xorm:"varchar(100)" json:"homepage"`
	Bio                    string    `xorm:"varchar(100)" json:"bio"`
	Tag                    string    `xorm:"varchar(100)" json:"tag"`
	Language               string    `xorm:"varchar(100)" json:"language"`
	Gender                 string    `xorm:"varchar(100)" json:"gender"`
	Birthday               string    `xorm:"varchar(100)" json:"birthday"`
	Education              string    `xorm:"varchar(100)" json:"education"`
	Score                  int       `json:"score"`
	Karma                  int       `json:"karma"`
	Ranking                int       `json:"ranking"`
	IsDefaultAvatar        bool      `json:"isDefaultAvatar"`
	IsOnline               bool      `json:"isOnline"`
	IsAdmin                bool      `json:"isAdmin"`

	IsForbidden       bool   `json:"isForbidden"`
	IsDeleted         bool   `json:"isDeleted"`
	SignupApplication string `xorm:"varchar(100)" json:"signupApplication"`
	Hash              string `xorm:"varchar(100)" json:"hash"`
	PreHash           string `xorm:"varchar(100)" json:"preHash"`
	AccessKey         string `xorm:"varchar(100)" json:"accessKey"`
	AccessSecret      string `xorm:"varchar(100)" json:"accessSecret"`

	CreatedIp      string `xorm:"varchar(100)" json:"createdIp"`
	LastSigninTime string `xorm:"varchar(100)" json:"lastSigninTime"`
	LastSigninIp   string `xorm:"varchar(100)" json:"lastSigninIp"`

	GitHub          string `xorm:"github varchar(100)" json:"github"`
	Google          string `xorm:"varchar(100)" json:"google"`
	QQ              string `xorm:"qq varchar(100)" json:"qq"`
	WeChat          string `xorm:"wechat varchar(100)" json:"wechat"`
	Facebook        string `xorm:"facebook varchar(100)" json:"facebook"`
	DingTalk        string `xorm:"dingtalk varchar(100)" json:"dingtalk"`
	Weibo           string `xorm:"weibo varchar(100)" json:"weibo"`
	Gitee           string `xorm:"gitee varchar(100)" json:"gitee"`
	LinkedIn        string `xorm:"linkedin varchar(100)" json:"linkedin"`
	Wecom           string `xorm:"wecom varchar(100)" json:"wecom"`
	Lark            string `xorm:"lark varchar(100)" json:"lark"`
	Gitlab          string `xorm:"gitlab varchar(100)" json:"gitlab"`
	Adfs            string `xorm:"adfs varchar(100)" json:"adfs"`
	Baidu           string `xorm:"baidu varchar(100)" json:"baidu"`
	Alipay          string `xorm:"alipay varchar(100)" json:"alipay"`
	Casdoor         string `xorm:"casdoor varchar(100)" json:"casdoor"`
	Infoflow        string `xorm:"infoflow varchar(100)" json:"infoflow"`
	Apple           string `xorm:"apple varchar(100)" json:"apple"`
	AzureAD         string `xorm:"azuread varchar(100)" json:"azuread"`
	Slack           string `xorm:"slack varchar(100)" json:"slack"`
	Steam           string `xorm:"steam varchar(100)" json:"steam"`
	Bilibili        string `xorm:"bilibili varchar(100)" json:"bilibili"`
	Okta            string `xorm:"okta varchar(100)" json:"okta"`
	Douyin          string `xorm:"douyin varchar(100)" json:"douyin"`
	Line            string `xorm:"line varchar(100)" json:"line"`
	Amazon          string `xorm:"amazon varchar(100)" json:"amazon"`
	Auth0           string `xorm:"auth0 varchar(100)" json:"auth0"`
	BattleNet       string `xorm:"battlenet varchar(100)" json:"battlenet"`
	Bitbucket       string `xorm:"bitbucket varchar(100)" json:"bitbucket"`
	Box             string `xorm:"box varchar(100)" json:"box"`
	CloudFoundry    string `xorm:"cloudfoundry varchar(100)" json:"cloudfoundry"`
	Dailymotion     string `xorm:"dailymotion varchar(100)" json:"dailymotion"`
	Deezer          string `xorm:"deezer varchar(100)" json:"deezer"`
	DigitalOcean    string `xorm:"digitalocean varchar(100)" json:"digitalocean"`
	Discord         string `xorm:"discord varchar(100)" json:"discord"`
	Dropbox         string `xorm:"dropbox varchar(100)" json:"dropbox"`
	EveOnline       string `xorm:"eveonline varchar(100)" json:"eveonline"`
	Fitbit          string `xorm:"fitbit varchar(100)" json:"fitbit"`
	Gitea           string `xorm:"gitea varchar(100)" json:"gitea"`
	Heroku          string `xorm:"heroku varchar(100)" json:"heroku"`
	InfluxCloud     string `xorm:"influxcloud varchar(100)" json:"influxcloud"`
	Instagram       string `xorm:"instagram varchar(100)" json:"instagram"`
	Intercom        string `xorm:"intercom varchar(100)" json:"intercom"`
	Kakao           string `xorm:"kakao varchar(100)" json:"kakao"`
	Lastfm          string `xorm:"lastfm varchar(100)" json:"lastfm"`
	Mailru          string `xorm:"mailru varchar(100)" json:"mailru"`
	Meetup          string `xorm:"meetup varchar(100)" json:"meetup"`
	MicrosoftOnline string `xorm:"microsoftonline varchar(100)" json:"microsoftonline"`
	Naver           string `xorm:"naver varchar(100)" json:"naver"`
	Nextcloud       string `xorm:"nextcloud varchar(100)" json:"nextcloud"`
	OneDrive        string `xorm:"onedrive varchar(100)" json:"onedrive"`
	Oura            string `xorm:"oura varchar(100)" json:"oura"`
	Patreon         string `xorm:"patreon varchar(100)" json:"patreon"`
	Paypal          string `xorm:"paypal varchar(100)" json:"paypal"`
	SalesForce      string `xorm:"salesforce varchar(100)" json:"salesforce"`
	Shopify         string `xorm:"shopify varchar(100)" json:"shopify"`
	Soundcloud      string `xorm:"soundcloud varchar(100)" json:"soundcloud"`
	Spotify         string `xorm:"spotify varchar(100)" json:"spotify"`
	Strava          string `xorm:"strava varchar(100)" json:"strava"`
	Stripe          string `xorm:"stripe varchar(100)" json:"stripe"`
	TikTok          string `xorm:"tiktok varchar(100)" json:"tiktok"`
	Tumblr          string `xorm:"tumblr varchar(100)" json:"tumblr"`
	Twitch          string `xorm:"twitch varchar(100)" json:"twitch"`
	Twitter         string `xorm:"twitter varchar(100)" json:"twitter"`
	Typetalk        string `xorm:"typetalk varchar(100)" json:"typetalk"`
	Uber            string `xorm:"uber varchar(100)" json:"uber"`
	VK              string `xorm:"vk varchar(100)" json:"vk"`
	Wepay           string `xorm:"wepay varchar(100)" json:"wepay"`
	Xero            string `xorm:"xero varchar(100)" json:"xero"`
	Yahoo           string `xorm:"yahoo varchar(100)" json:"yahoo"`
	Yammer          string `xorm:"yammer varchar(100)" json:"yammer"`
	Yandex          string `xorm:"yandex varchar(100)" json:"yandex"`
	Zoom            string `xorm:"zoom varchar(100)" json:"zoom"`
	MetaMask        string `xorm:"metamask varchar(100)" json:"metamask"`
	Web3Onboard     string `xorm:"web3onboard varchar(100)" json:"web3onboard"`
	Custom          string `xorm:"custom varchar(100)" json:"custom"`
	OpenID          string `xorm:"openid varchar(100)" json:"openid"`

	// SAML Types
	Keycloak    string `xorm:"keycloak varchar(100)" json:"keycloak"`
	AliyunIDaaS string `xorm:"aliyunidaas varchar(100)" json:"aliyunidaas"`
	GenericSAML string `xorm:"genericsaml varchar(100)" json:"genericsaml"`

	WebauthnCredentials []webauthn.Credential `xorm:"webauthnCredentials blob" json:"webauthnCredentials"`
	PreferredMfaType    string                `xorm:"varchar(100)" json:"preferredMfaType"`
	RecoveryCodes       []string              `xorm:"varchar(1000)" json:"recoveryCodes"`
	TotpSecret          string                `xorm:"varchar(100)" json:"totpSecret"`
	MfaPhoneEnabled     bool                  `json:"mfaPhoneEnabled"`
	MfaEmailEnabled     bool                  `json:"mfaEmailEnabled"`
	MultiFactorAuths    []*MfaProps           `xorm:"-" json:"multiFactorAuths,omitempty"`

	MappingStrategy string `xorm:"varchar(50)" json:"mappingStrategy"`

	Ldap       string            `xorm:"ldap varchar(100)" json:"ldap"`
	Properties map[string]string `json:"properties"`

	Roles       []*Role       `json:"roles"`
	Permissions []*Permission `json:"permissions"`
	Groups      []string      `xorm:"groups varchar(1000)" json:"groups"`

	LastSigninWrongTime string `xorm:"varchar(100)" json:"lastSigninWrongTime"`
	SigninWrongTimes    int    `json:"signinWrongTimes"`

	ManagedAccounts []ManagedAccount `xorm:"managedAccounts blob" json:"managedAccounts"`
	UserIdProvider  *UserIdProvider  `xorm:"-" json:"userIdProvider"`
}

type Userinfo struct {
	Sub           string   `json:"sub"`
	Iss           string   `json:"iss"`
	Aud           string   `json:"aud"`
	Name          string   `json:"preferred_username,omitempty"`
	DisplayName   string   `json:"name,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Avatar        string   `json:"picture,omitempty"`
	Address       string   `json:"address,omitempty"`
	Phone         string   `json:"phone,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

type ManagedAccount struct {
	Application string `xorm:"varchar(100)" json:"application"`
	Username    string `xorm:"varchar(100)" json:"username"`
	Password    string `xorm:"varchar(100)" json:"password"`
	SigninUrl   string `xorm:"varchar(200)" json:"signinUrl"`
}

func (user *User) IsPasswordChangeRequired() bool {
	return !user.PasswordChangeTime.IsZero() && user.PasswordChangeTime.Before(time.Now())
}

func (user *User) checkPasswordChangeRequestAllowed() error {
	if !user.isPasswordChangeRequestAllowed() && !user.PasswordChangeTime.IsZero() {
		return fmt.Errorf("IsPasswordChangeRequired is not supported to be enabled for users from LDAP or Keycloak")
	}
	return nil
}

func (user *User) isPasswordChangeRequestAllowed() bool {
	return user.Type != "" || user.Ldap == ""
}

func GetGlobalUserCount(field, value string) (int64, error) {
	session := orm.GetSession("", -1, -1, field, value, "", "")

	notUserAccesToken := builder.Not{builder.Like{"tag", "<access-token>"}}
	session = session.And(notUserAccesToken)

	return session.Count(&User{})
}

func GetGlobalUsers() ([]*User, error) {
	users := []*User{}
	err := orm.AppOrmer.Engine.Desc("created_time").Find(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetPaginationGlobalUsers(offset, limit int, field, value, sortField, sortOrder string) ([]*User, error) {
	users := []*User{}
	session := orm.GetSessionForUser("", offset, limit, field, value, sortField, sortOrder)

	err := session.Find(&users)
	if err != nil {
		logs.Error(err.Error())

		return nil, err
	}

	for i := range users {
		users[i].PasswordChangeRequired = users[i].IsPasswordChangeRequired()
	}
	return users, nil
}

func GetUserCount(owner, field, value string, groupName string) (int64, error) {
	session := orm.GetSession(owner, -1, -1, field, value, "", "")

	notUserAccesToken := builder.Not{builder.Like{"tag", "<access-token>"}}
	session = session.And(notUserAccesToken)

	if groupName != "" {
		return GetGroupUserCount(util.GetId(owner, groupName), field, value)
	}

	return session.Count(&User{})
}

func GetOnlineUserCount(owner string, isOnline int) (int64, error) {
	notUserAccesToken := builder.Not{builder.Like{"tag", "<access-token>"}}

	return orm.AppOrmer.Engine.Where("is_online = ?", isOnline).And(notUserAccesToken).Count(&User{Owner: owner})
}

func GetUsers(owner string) ([]*User, error) {
	users := []*User{}
	err := orm.AppOrmer.Engine.Desc("created_time").Find(&users, &User{Owner: owner})
	if err != nil {
		return nil, err
	}

	for i := range users {
		users[i].PasswordChangeRequired = users[i].IsPasswordChangeRequired()
	}

	return users, nil
}

func GetSortedUsers(owner string, sorter string, limit int) ([]*User, error) {
	users := []*User{}

	notUserAccesToken := builder.Not{builder.Like{"tag", "<access-token>"}}
	sorter = strings.ReplaceAll(strings.ReplaceAll(sorter, "\"", ""), "'", "")
	_, errExist := orm.AppOrmer.Engine.SQL("SELECT ? from USER", sorter).Exist()
	if errExist != nil {
		return nil, nil
	}

	err := orm.AppOrmer.Engine.Desc(sorter).And(notUserAccesToken).Limit(limit, 0).Find(&users, &User{Owner: owner})
	if err != nil {
		return nil, err
	}

	for i := range users {
		users[i].PasswordChangeRequired = users[i].IsPasswordChangeRequired()
	}

	return users, nil
}

func GetPaginationUsers(owner string, offset, limit int, field, value, sortField, sortOrder string, groupName string) ([]*User, error) {
	users := []*User{}

	if groupName != "" {
		return GetPaginationGroupUsers(util.GetId(owner, groupName), offset, limit, field, value, sortField, sortOrder)
	}

	session := orm.GetSessionForUser(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&users)
	if err != nil {
		return nil, err
	}

	for i := range users {
		users[i].PasswordChangeRequired = users[i].IsPasswordChangeRequired()
	}

	return users, nil
}

func getUser(owner string, name string) (*User, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	user := User{Owner: owner, Name: name}
	existed, err := orm.AppOrmer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		user.PasswordChangeRequired = user.IsPasswordChangeRequired()
		return &user, nil
	} else {
		return nil, nil
	}
}

func getUserByWechatId(owner string, wechatOpenId string, wechatUnionId string) (*User, error) {
	if wechatUnionId == "" {
		wechatUnionId = wechatOpenId
	}
	user := &User{}
	existed, err := orm.AppOrmer.Engine.Where("owner = ?", owner).Where("wechat = ? OR wechat = ?", wechatOpenId, wechatUnionId).Get(user)
	if err != nil {
		return nil, err
	}

	if existed {
		return user, nil
	} else {
		return nil, nil
	}
}

func GetUserByEmail(owner string, email string) (*User, error) {
	if owner == "" || email == "" {
		return nil, nil
	}

	email = strings.ToLower(email)

	user := User{Owner: owner, Email: email}
	existed, err := orm.AppOrmer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		user.PasswordChangeRequired = user.IsPasswordChangeRequired()
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUserByPhone(owner string, phone string) (*User, error) {
	if owner == "" || phone == "" {
		return nil, nil
	}

	user := User{Owner: owner, Phone: phone}
	existed, err := orm.AppOrmer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		user.PasswordChangeRequired = user.IsPasswordChangeRequired()
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUserByUserId(owner string, userId string) (*User, error) {
	if owner == "" || userId == "" {
		return nil, nil
	}

	user := User{Owner: owner, Id: userId}
	existed, err := orm.AppOrmer.Engine.Get(&user)
	if err != nil {
		return nil, err
	}

	if existed {
		user.PasswordChangeRequired = user.IsPasswordChangeRequired()
		return &user, nil
	} else {
		return nil, nil
	}
}

func GetUser(id string) (*User, error) {
	owner, name, err := util.GetOwnerAndNameFromId(id)
	if err != nil {
		return nil, err
	}
	return getUser(owner, name)
}

func GetMaskedUser(user *User, isAdminOrSelf bool, errs ...error) (*User, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	if user == nil {
		return nil, nil
	}

	if user.Password != "" {
		user.Password = "***"
	}

	if !isAdminOrSelf {
		if user.AccessSecret != "" {
			user.AccessSecret = "***"
		}
	}

	if user.ManagedAccounts != nil {
		for _, manageAccount := range user.ManagedAccounts {
			manageAccount.Password = "***"
		}
	}

	if user.TotpSecret != "" {
		user.TotpSecret = ""
	}
	if user.RecoveryCodes != nil {
		user.RecoveryCodes = nil
	}

	return user, nil
}

func GetMaskedUsers(users []*User, errs ...error) ([]*User, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	var err error
	for _, user := range users {
		user, err = GetMaskedUser(user, false)
		if err != nil {
			return nil, err
		}
	}
	return users, nil
}

func UpdateUser(id string, user *User, columns []string, isAdmin bool) (bool, error) {
	var err error
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	oldUser, err := getUser(owner, name)
	if err != nil {
		return false, err
	}
	if oldUser == nil {
		return false, nil
	}

	if name != user.Name {
		err := userChangeTrigger(name, user.Name)
		if err != nil {
			return false, err
		}
	}

	if user.Password == "***" {
		user.Password = oldUser.Password
	}

	user.Email = strings.ToLower(user.Email)

	if len(columns) == 0 {
		columns = []string{
			"owner", "display_name", "avatar",
			"location", "address", "country_code", "region", "language", "affiliation", "title", "homepage", "bio", "tag", "language", "gender", "birthday", "education", "score", "karma", "ranking", "signup_application",
			"is_admin", "is_forbidden", "is_deleted", "password_change_time", "hash", "is_default_avatar", "properties", "webauthnCredentials", "managedAccounts",
			"signin_wrong_times", "last_signin_wrong_time", "groups", "access_key", "access_secret",
			"github", "google", "qq", "wechat", "facebook", "dingtalk", "weibo", "gitee", "linkedin", "wecom", "lark", "gitlab", "adfs",
			"baidu", "alipay", "casdoor", "infoflow", "apple", "azuread", "slack", "steam", "bilibili", "okta", "douyin", "line", "amazon",
			"auth0", "battlenet", "bitbucket", "box", "cloudfoundry", "dailymotion", "deezer", "digitalocean", "discord", "dropbox",
			"eveonline", "fitbit", "gitea", "heroku", "influxcloud", "instagram", "intercom", "kakao", "lastfm", "mailru", "meetup",
			"microsoftonline", "naver", "nextcloud", "onedrive", "oura", "patreon", "paypal", "salesforce", "shopify", "soundcloud",
			"spotify", "strava", "stripe", "type", "tiktok", "tumblr", "twitch", "twitter", "typetalk", "uber", "vk", "wepay", "xero", "yahoo",
			"yammer", "yandex", "zoom", "custom", "keycloak", "aliyunidaas", "mapping_strategy",
		}
	}
	if isAdmin {
		columns = append(columns, "name", "email", "phone", "country_code", "type")
	}

	if util.ContainsString(columns, "password_change_time") {
		user.PasswordChangeTime = oldUser.PasswordChangeTime
		if oldUser.PasswordChangeRequired != user.PasswordChangeRequired {
			user.PasswordChangeTime = time.Time{}
			if user.PasswordChangeRequired {
				user.PasswordChangeTime = time.Now()
			}
		}

		organization, err := GetOrganization(util.GetId("admin", user.Owner))
		if err != nil {
			return false, err
		}

		if organization.PasswordChangeInterval != 0 && user.PasswordChangeTime.IsZero() {
			user.PasswordChangeTime = getNextPasswordChangeTime(organization.PasswordChangeInterval)
		}
	}

	if util.ContainsString(columns, "groups") {
		_, err := userEnforcer.UpdateGroupsForUser(user.GetId(), user.Groups)
		if err != nil {
			return false, err
		}
	}

	affected, err := updateUser(id, user, columns)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func updateUser(id string, user *User, columns []string) (int64, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	err := user.UpdateUserHash()
	if err != nil {
		return 0, err
	}

	err = user.checkPasswordChangeRequestAllowed()
	if err != nil {
		return 0, err
	}

	oldUser, err := getUser(owner, name)
	if err != nil {
		return 0, err
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{owner, name}).Cols(columns...).Update(user)
	if err != nil {
		return 0, err
	}

	hasImpactOnPolicy :=
		(util.InSlice(columns, "groups") && !slices.Equal(oldUser.Groups, user.Groups)) ||
			(util.InSlice(columns, "name") && oldUser.Name != user.Name) ||
			(util.InSlice(columns, "owner") && oldUser.Owner != user.Owner)

	if affected != 0 && hasImpactOnPolicy {
		oldReachablePermissions, err := reachablePermissionsByUser(oldUser)
		if err != nil {
			return 0, fmt.Errorf("reachablePermissionsByUser: %w", err)
		}

		reachablePermissions, err := reachablePermissionsByUser(user)
		if err != nil {
			return 0, fmt.Errorf("reachablePermissionsByUser: %w", err)
		}

		reachablePermissions = append(reachablePermissions, oldReachablePermissions...)

		err = ProcessPolicyDifference(reachablePermissions)
		if err != nil {
			return 0, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected, nil
}

func UpdateUserForAllFields(id string, user *User) (bool, error) {
	var err error
	owner, name, err := util.GetOwnerAndNameFromId(id)
	if err != nil {
		return false, err
	}
	oldUser, err := getUser(owner, name)
	if err != nil {
		return false, err
	}

	if oldUser == nil {
		return false, nil
	}

	if name != user.Name {
		err := userChangeTrigger(name, user.Name)
		if err != nil {
			return false, err
		}
	}

	err = user.UpdateUserHash()
	if err != nil {
		return false, err
	}

	organization, err := GetOrganization(util.GetId("admin", owner))
	if err != nil {
		return false, err
	}
	if organization.PasswordChangeInterval != 0 && user.PasswordChangeTime.IsZero() {
		user.PasswordChangeTime = getNextPasswordChangeTime(organization.PasswordChangeInterval)
	}

	err = user.checkPasswordChangeRequestAllowed()
	if err != nil {
		return false, err
	}

	user.PasswordChangeTime = oldUser.PasswordChangeTime
	if oldUser.PasswordChangeRequired != user.PasswordChangeRequired {
		user.PasswordChangeTime = time.Time{}
		if user.PasswordChangeRequired {
			user.PasswordChangeTime = time.Now()
		}
	}

	if organization.PasswordChangeInterval != 0 && user.PasswordChangeTime.IsZero() {
		user.PasswordChangeTime = getNextPasswordChangeTime(organization.PasswordChangeInterval)
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{owner, name}).AllCols().Update(user)
	if err != nil {
		return false, err
	}

	if affected != 0 &&
		(!slices.Equal(oldUser.Groups, user.Groups) || oldUser.Owner != user.Owner || oldUser.Name != user.Name) {
		oldReachablePermissions, err := reachablePermissionsByUser(oldUser)
		if err != nil {
			return false, fmt.Errorf("reachablePermissionsByUser: %w", err)
		}

		reachablePermissions, err := reachablePermissionsByUser(user)
		if err != nil {
			return false, fmt.Errorf("reachablePermissionsByUser: %w", err)
		}
		reachablePermissions = append(reachablePermissions, oldReachablePermissions...)

		err = ProcessPolicyDifference(reachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func AddUser(ctx context.Context, user *User) (bool, error) {
	user.Id = util.GenerateId()

	if user.MappingStrategy == "" {
		user.MappingStrategy = "all"
	}

	if user.Owner == "" || user.Name == "" {
		return false, nil
	}

	user.Email = strings.ToLower(user.Email)

	organization, _ := GetOrganizationByUser(user)
	if organization == nil {
		return false, nil
	}

	if err := user.UpdateUserPassword(organization); err != nil {
		return false, err
	}

	err := user.UpdateUserHash()
	if err != nil {
		return false, err
	}

	user.PreHash = user.Hash

	if user.PasswordChangeTime.IsZero() && organization.PasswordChangeInterval != 0 {
		user.PasswordChangeTime = getNextPasswordChangeTime(organization.PasswordChangeInterval)
	}

	if user.PasswordChangeRequired {
		user.PasswordChangeTime = time.Now()
	}

	count, err := GetUserCount(user.Owner, "", "", "")
	if err != nil {
		return false, err
	}
	user.Ranking = int(count + 1)

	affected, err := orm.AppOrmer.Engine.Insert(user)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		reachablePermissions, err := reachablePermissionsByUser(user)
		if err != nil {
			return false, fmt.Errorf("reachablePermissionsByUser: %w", err)
		}

		err = ProcessPolicyDifference(reachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func DeleteUser(ctx context.Context, user *User) (bool, error) {
	// Forced offline the user first
	_, err := DeleteSession(ctx, util.GetSessionId(user.Owner, user.Name, CasdoorApplication))
	if err != nil {
		return false, err
	}

	oldReachablePermissions, err := reachablePermissionsByUser(user)
	if err != nil {
		return false, fmt.Errorf("reachablePermissionsByUser: %w", err)
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{user.Owner, user.Name}).Delete(&User{})
	if err != nil {
		return false, err
	}

	if affected != 0 {
		err = ProcessPolicyDifference(oldReachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func GetUserInfo(user *User, scope string, aud string, host string) *Userinfo {
	_, originBackend := getOriginFromHost(host)

	resp := Userinfo{
		Sub: user.Id,
		Iss: originBackend,
		Aud: aud,
	}
	if strings.Contains(scope, "profile") {
		resp.Name = user.Name
		resp.DisplayName = user.DisplayName
		resp.Avatar = user.Avatar
		resp.Groups = user.Groups
	}
	if strings.Contains(scope, "email") {
		resp.Email = user.Email
		resp.EmailVerified = user.EmailVerified
	}
	if strings.Contains(scope, "address") {
		resp.Address = user.Location
	}
	if strings.Contains(scope, "phone") {
		resp.Phone = user.Phone
	}
	return &resp
}

func LinkUserAccount(user *User, field string, value string) (bool, error) {
	return SetUserField(user, field, value)
}

func (user *User) GetId() string {
	return fmt.Sprintf("%s/%s", user.Owner, user.Name)
}

func isUserIdGlobalAdmin(userId string) bool {
	return strings.HasPrefix(userId, "built-in/")
}

func ExtendUserWithRolesAndPermissions(user *User) (err error) {
	if user == nil {
		return
	}

	user.Permissions, user.Roles, err = getPermissionsAndRolesByUser(user.GetId())
	if err != nil {
		return err
	}

	if user.Groups == nil {
		user.Groups = []string{}
	}

	return
}

func DeleteGroupForUser(user string, group string) (bool, error) {
	return userEnforcer.DeleteGroupForUser(user, group)
}

func userChangeTrigger(oldName string, newName string) error {
	session := orm.AppOrmer.Engine.NewSession()
	defer session.Close()

	err := session.Begin()
	if err != nil {
		return err
	}

	var roles []*Role
	err = orm.AppOrmer.Engine.Find(&roles)
	if err != nil {
		return err
	}

	for _, role := range roles {
		for j, u := range role.Users {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(u)
			if err != nil {
				return err
			}
			if name == oldName {
				role.Users[j] = util.GetId(owner, newName)
			}
		}
		_, err = session.Where("name=?", role.Name).And("owner=?", role.Owner).Update(role)
		if err != nil {
			return err
		}
	}

	var permissions []*Permission
	err = orm.AppOrmer.Engine.Find(&permissions)
	if err != nil {
		return err
	}
	for _, permission := range permissions {
		for j, u := range permission.Users {
			// u = organization/username
			owner, name, err := util.GetOwnerAndNameFromId(u)
			if err != nil {
				return err
			}
			if name == oldName {
				permission.Users[j] = util.GetId(owner, newName)
			}
		}
		_, err = session.Where("name=?", permission.Name).And("owner=?", permission.Owner).Update(permission)
		if err != nil {
			return err
		}
	}

	resource := new(Resource)
	resource.User = newName
	_, err = session.Where("user=?", oldName).Update(resource)
	if err != nil {
		return err
	}

	return session.Commit()
}

func (user *User) IsMfaEnabled() bool {
	if user == nil {
		return false
	}
	return user.PreferredMfaType != ""
}

func (user *User) GetPreferredMfaProps(masked bool) *MfaProps {
	if user == nil || user.PreferredMfaType == "" {
		return nil
	}
	return user.GetMfaProps(user.PreferredMfaType, masked)
}

func AddUserkeys(user *User, isAdmin bool) (bool, error) {
	if user == nil {
		return false, nil
	}

	user.AccessKey = util.GenerateId()
	user.AccessSecret = util.GenerateId()

	return UpdateUser(user.GetId(), user, []string{}, isAdmin)
}

func (user *User) IsApplicationAdmin(application *Application) bool {
	if user == nil {
		return false
	}

	return (user.Owner == application.Organization && user.IsAdmin) || user.IsGlobalAdmin()
}

func (user *User) IsGlobalAdmin() bool {
	if user == nil {
		return false
	}

	return user.Owner == "built-in"
}

func reachablePermissionsByUser(user *User) ([]*Permission, error) {
	result := make([]*Permission, 0)

	userPermissions, userRoles, err := getPermissionsAndRolesByUser(user.GetId())
	if err != nil {
		return nil, fmt.Errorf("GetPermissionsAndRolesByUser: %w", err)
	}

	result = append(result, userPermissions...)

	for _, role := range userRoles {
		rolePermissions, err := subRolePermissions(role)
		if err != nil {
			return nil, fmt.Errorf("subRolePermissions: %w", err)
		}
		if len(rolePermissions) > 0 {
			result = append(result, rolePermissions...)
		}
	}

	for _, groupId := range user.Groups {
		subGroup, err := GetGroup(groupId)
		if err != nil {
			return nil, fmt.Errorf("GetGroup: %w", err)
		}

		permissions, err := subGroupPermissions(subGroup)
		if err != nil {
			return nil, fmt.Errorf("GetPermissionsByGroup: %w", err)
		}
		if len(permissions) > 0 {
			result = append(result, permissions...)
		}

	}

	return result, nil
}

func groupUsersByGroups(users []*User) map[string][]*User {
	result := make(map[string][]*User, 0)
	for _, user := range users {
		for _, group := range user.Groups {
			result[group] = append(result[group], user)
		}
	}

	return result
}
func GetUsersWithFilter(owner string, cond builder.Cond) ([]*User, error) {
	users := []*User{}
	session := orm.AppOrmer.Engine.Desc("created_time")
	if cond != nil {
		session = session.Where(cond)
	}
	err := session.Find(&users, &User{Owner: owner})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetGlobalUsersWithFilter(cond builder.Cond) ([]*User, error) {
	users := []*User{}
	session := orm.AppOrmer.Engine.Desc("created_time")
	if cond != nil {
		session = session.Where(cond)
	}
	err := session.Find(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetUsersByTagWithFilter(owner string, tag string, cond builder.Cond) ([]*User, error) {
	users := []*User{}
	session := orm.AppOrmer.Engine.Desc("created_time")
	if cond != nil {
		session = session.Where(cond)
	}
	err := session.Find(&users, &User{Owner: owner, Tag: tag})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetUserTablePasswordMaxLength() (int, error) {
	if userMaxPasswordLength != 0 {
		return userMaxPasswordLength, nil
	}
	user := User{}
	table, err := orm.AppOrmer.Engine.TableInfo(&user)
	if err != nil {
		return 0, err
	}
	for _, col := range table.Columns() {
		if col.Name == "password" {
			userMaxPasswordLength = col.Length
			return userMaxPasswordLength, nil
		}
	}
	return 0, fmt.Errorf("could not found column 'password' in table 'user'")
}

func SyncAttributesToUser(user *User, displayName, email, mobile, avatar string, address []string) error {
	if user.MappingStrategy != "all" && user.MappingStrategy != "attribute" {
		return nil
	}

	user.DisplayName = displayName
	user.Email = email
	user.Phone = mobile
	user.Avatar = avatar
	user.Address = address

	_, err := UpdateUser(user.GetId(), user, []string{"display_name", "email", "phone", "avatar", "address"}, true)
	if err != nil {
		return err
	}

	return nil
}
