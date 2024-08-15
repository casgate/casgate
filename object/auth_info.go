package object

import (
	"errors"
	"fmt"
)

type AuthInfo struct {
	scope            string
	endpoint         string
	silentEndpoint   *string
	internalEndpoint *string
	mpScope          *string
	mpEndpoint       *string
}

func (a *AuthInfo) Scope() string {
	return a.scope
}

func (a *AuthInfo) Endpoint() string {
	return a.endpoint
}

func (a *AuthInfo) SilentEndpoint() (string, error) {
	if a.silentEndpoint == nil {
		return "", errors.New("authinfo silentEndpoint is nil")
	}
	return *a.silentEndpoint, nil
}

func (a *AuthInfo) InternalEndpoint() (string, error) {
	if a.internalEndpoint == nil {
		return "", errors.New("authinfo internalEndpoint is nil")
	}
	return *a.internalEndpoint, nil
}

func (a *AuthInfo) MPScope() (string, error) {
	if a.mpScope == nil {
		return "", errors.New("authinfo mpScope is nil")
	}
	return *a.mpScope, nil
}

func (a *AuthInfo) MPEndpoint() (string, error) {
	if a.mpEndpoint == nil {
		return "", errors.New("authinfo mpEndpoint is nil")
	}
	return *a.mpEndpoint, nil
}

func newAuthInfoDefault(scope, endpoint string) *AuthInfo {
	return &AuthInfo{
		scope: scope, endpoint: endpoint,
	}
}

func newAuthInfoWeCom(scope, endpoint, silentEndpoint, internalEndpoint string) *AuthInfo {
	return &AuthInfo{
		scope: scope, endpoint: endpoint, silentEndpoint: &silentEndpoint, internalEndpoint: &internalEndpoint,
	}
}

func newAuthInfoWeChat(scope, endpoint, mpScope, mpEndpoint string) *AuthInfo {
	return &AuthInfo{
		scope: scope, endpoint: endpoint, mpScope: &mpScope, mpEndpoint: &mpEndpoint,
	}
}

func GetAuthInfo(providerType string) (*AuthInfo, error) {
	authInfo := map[string]*AuthInfo{
		"Google":            newAuthInfoDefault("profile+email", "https://accounts.google.com/signin/oauth"),
		"GitHub":            newAuthInfoDefault("user:email+read:user", "https://github.com/login/oauth/authorize"),
		"QQ":                newAuthInfoDefault("get_user_info", "https://graph.qq.com/oauth2.0/authorize"),
		"WeChat":            newAuthInfoWeChat("snsapi_login", "https://open.weixin.qq.com/connect/qrconnect", "snsapi_userinfo", "https://open.weixin.qq.com/connect/oauth2/authorize"),
		"WeChatMiniProgram": newAuthInfoDefault("", "https://mp.weixin.qq.com/"),
		"Facebook":          newAuthInfoDefault("email,public_profile", "https://www.facebook.com/dialog/oauth"),
		"DingTalk":          newAuthInfoDefault("openid", "https://login.dingtalk.com/oauth2/auth"),
		"Weibo":             newAuthInfoDefault("email", "https://api.weibo.com/oauth2/authorize"),
		"Gitee":             newAuthInfoDefault("user_info%20emails", "https://gitee.com/oauth/authorize"),
		"LinkedIn":          newAuthInfoDefault("r_liteprofile%20r_emailaddress", "https://www.linkedin.com/oauth/v2/authorization"),
		"WeCom":             newAuthInfoWeCom("snsapi_userinfo", "https://open.work.weixin.qq.com/wwopen/sso/3rd_qrConnect", "https://open.weixin.qq.com/connect/oauth2/authorize", "https://open.work.weixin.qq.com/wwopen/sso/qrConnect"),
		"Lark":              newAuthInfoDefault("", "https://open.feishu.cn/open-apis/authen/v1/index"),
		"GitLab":            newAuthInfoDefault("read_user+profile", "https://gitlab.com/oauth/authorize"),
		"ADFS":              newAuthInfoDefault("openid", "http://example.com"),
		"Baidu":             newAuthInfoDefault("basic", "http://openapi.baidu.com/oauth/2.0/authorize"),
		"Alipay":            newAuthInfoDefault("basic", "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm"),
		"Casdoor":           newAuthInfoDefault("openid%20profile%20email", "http://example.com"),
		"Infoflow":          newAuthInfoDefault("", "https://xpc.im.baidu.com/oauth2/authorize"),
		"Apple":             newAuthInfoDefault("name%20email", "https://appleid.apple.com/auth/authorize"),
		"AzureAD":           newAuthInfoDefault("user.read", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
		"Slack":             newAuthInfoDefault("users:read", "https://slack.com/oauth/authorize"),
		"Steam":             newAuthInfoDefault("", "https://steamcommunity.com/openid/login"),
		"Okta":              newAuthInfoDefault("openid%20profile%20email", "http://example.com"),
		"Douyin":            newAuthInfoDefault("user_info", "https://open.douyin.com/platform/oauth/connect"),
		"Custom":            newAuthInfoDefault("", "https://example.com/"),
		"OpenID":            newAuthInfoDefault("", "https://example.com/"),
		"Bilibili":          newAuthInfoDefault("", "https://passport.bilibili.com/register/pc_oauth2.html"),
		"Line":              newAuthInfoDefault("profile%20openid%20email", "https://access.line.me/oauth2/v2.1/authorize"),
		"Amazon":            newAuthInfoDefault("profile", "https://www.amazon.com/ap/oa"),
		"Auth0":             newAuthInfoDefault("openid%20profile%20email", "http://auth0.com/authorize"),
		"BattleNet":         newAuthInfoDefault("openid", "https://oauth.battlenet.com.cn/authorize"),
		"Bitbucket":         newAuthInfoDefault("account", "https://bitbucket.org/site/oauth2/authorize"),
		"Box":               newAuthInfoDefault("root_readwrite", "https://account.box.com/api/oauth2/authorize"),
		"CloudFoundry":      newAuthInfoDefault("cloud_controller.read", "https://login.cloudfoundry.org/oauth/authorize"),
		"Dailymotion":       newAuthInfoDefault("userinfo", "https://api.dailymotion.com/oauth/authorize"),
		"Deezer":            newAuthInfoDefault("basic_access", "https://connect.deezer.com/oauth/auth.php"),
		"DigitalOcean":      newAuthInfoDefault("read", "https://cloud.digitalocean.com/v1/oauth/authorize"),
		"Discord":           newAuthInfoDefault("identify%20email", "https://discord.com/api/oauth2/authorize"),
		"Dropbox":           newAuthInfoDefault("account_info.read", "https://www.dropbox.com/oauth2/authorize"),
		"EveOnline":         newAuthInfoDefault("publicData", "https://login.eveonline.com/oauth/authorize"),
		"Fitbit":            newAuthInfoDefault("activity%20heartrate%20location%20nutrition%20profile%20settings%20sleep%20social%20weight", "https://www.fitbit.com/oauth2/authorize"),
		"Gitea":             newAuthInfoDefault("user:email", "https://gitea.com/login/oauth/authorize"),
		"Heroku":            newAuthInfoDefault("global", "https://id.heroku.com/oauth/authorize"),
		"InfluxCloud":       newAuthInfoDefault("read:org", "https://cloud2.influxdata.com/oauth/authorize"),
		"Instagram":         newAuthInfoDefault("user_profile", "https://api.instagram.com/oauth/authorize"),
		"Intercom":          newAuthInfoDefault("user.read", "https://app.intercom.com/oauth"),
		"Kakao":             newAuthInfoDefault("account_email", "https://kauth.kakao.com/oauth/authorize"),
		"Lastfm":            newAuthInfoDefault("user_read", "https://www.last.fm/api/auth"),
		"Mailru":            newAuthInfoDefault("userinfo", "https://oauth.mail.ru/login"),
		"Meetup":            newAuthInfoDefault("basic", "https://secure.meetup.com/oauth2/authorize"),
		"MicrosoftOnline":   newAuthInfoDefault("openid%20profile%20email", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"),
		"Naver":             newAuthInfoDefault("profile", "https://nid.naver.com/oauth2.0/authorize"),
		"Nextcloud":         newAuthInfoDefault("openid%20profile%20email", "https://cloud.example.org/apps/oauth2/authorize"),
		"OneDrive":          newAuthInfoDefault("offline_access%20onedrive.readonly", "https://login.live.com/oauth20_authorize.srf"),
		"Oura":              newAuthInfoDefault("personal", "https://cloud.ouraring.com/oauth/authorize"),
		"Patreon":           newAuthInfoDefault("identity", "https://www.patreon.com/oauth2/authorize"),
		"PayPal":            newAuthInfoDefault("openid%20profile%20email", "https://www.sandbox.paypal.com/connect"),
		"SalesForce":        newAuthInfoDefault("openid%20profile%20email", "https://login.salesforce.com/services/oauth2/authorize"),
		"Shopify":           newAuthInfoDefault("read_products", "https://myshopify.com/admin/oauth/authorize"),
		"Soundcloud":        newAuthInfoDefault("non-expiring", "https://api.soundcloud.com/connect"),
		"Spotify":           newAuthInfoDefault("user-read-email", "https://accounts.spotify.com/authorize"),
		"Strava":            newAuthInfoDefault("read", "https://www.strava.com/oauth/authorize"),
		"Stripe":            newAuthInfoDefault("read_only", "https://connect.stripe.com/oauth/authorize"),
		"TikTok":            newAuthInfoDefault("user.info.basic", "https://www.tiktok.com/auth/authorize/"),
		"Tumblr":            newAuthInfoDefault("email", "https://www.tumblr.com/oauth2/authorize"),
		"Twitch":            newAuthInfoDefault("user_read", "https://id.twitch.tv/oauth2/authorize"),
		"Twitter":           newAuthInfoDefault("users.read", "https://twitter.com/i/oauth2/authorize"),
		"Typetalk":          newAuthInfoDefault("my", "https://typetalk.com/oauth2/authorize"),
		"Uber":              newAuthInfoDefault("profile", "https://login.uber.com/oauth/v2/authorize"),
		"VK":                newAuthInfoDefault("email", "https://oauth.vk.com/authorize"),
		"Wepay":             newAuthInfoDefault("manage_accounts%20view_user", "https://www.wepay.com/v2/oauth2/authorize"),
		"Xero":              newAuthInfoDefault("openid%20profile%20email", "https://login.xero.com/identity/connect/authorize"),
		"Yahoo":             newAuthInfoDefault("openid%20profile%20email", "https://api.login.yahoo.com/oauth2/request_auth"),
		"Yammer":            newAuthInfoDefault("user", "https://www.yammer.com/oauth2/authorize"),
		"Yandex":            newAuthInfoDefault("login:email", "https://oauth.yandex.com/authorize"),
		"Zoom":              newAuthInfoDefault("user:read", "https://zoom.us/oauth/authorize"),
		"MetaMask":          newAuthInfoDefault("", ""),
		"Web3Onboard":       newAuthInfoDefault("", ""),
	}

	if auth, found := authInfo[providerType]; found {
		return auth, nil
	}
	return nil, &NotFoundError{fmt.Sprintf("not found auth info for provider with type: %s", providerType)}
}
