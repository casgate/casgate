package object

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	xormadapter "github.com/casbin/xorm-adapter/v2"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
)

const (
	adminRole     = "admin"
	userRole      = "user"
	AnonymousRole = "*"

	adminOwner = "admin"
	existGroup = "exist"

	subjectGroupingPolicy = "g"
	objectGroupingPolicy  = "g2"

	methodGet  = "GET"
	methodPost = "POST"

	oidcEntity                       = "oidc"
	accountEntity                    = "account"
	adapterEntity                    = "adapter"
	apiTokenEntity                   = "apiToken"
	applicationEntity                = "application"
	syncerEntity                     = "syncer"
	certEntity                       = "cert"
	domainEntity                     = "domain"
	enforcerEntity                   = "enforcer"
	groupEntity                      = "group"
	ldapEntity                       = "ldap"
	modelEntity                      = "model"
	organizationEntity               = "organization"
	paymentEntity                    = "payment"
	permissionEntity                 = "permission"
	planEntity                       = "plan"
	pricingEntity                    = "pricing"
	productEntity                    = "product"
	providerEntity                   = "provider"
	recordEntity                     = "record"
	resourceEntity                   = "resource"
	roleEntity                       = "role"
	sessionEntity                    = "session"
	subscriptionEntity               = "subscription"
	tokenEntity                      = "token"
	webhookEntity                    = "webhook"
	userEntity                       = "user"
	callbackEntity                   = "callback"
	metricsEntity                    = "metrics"
	mfaEntity                        = "mfa"
	loginEntity                      = "login"
	dashboardEntity                  = "dashboard"
	prometheusEntity                 = "prometheus"
	systemEntity                     = "system"
	getWebhookEventTypeEntity        = "getWebhookEventType"
	verificationEntity               = "verification"
	handleOfficialAccountEventEntity = "handleOfficialAccountEvent"
)

type Endpoint struct {
	role    string
	method  string
	urlPath string
	entity  string
}

func getManyMethodsRegex(methods []string) string {
	return fmt.Sprintf("(%s)", strings.Join(methods, "|"))
}

var methodGetAndPost = getManyMethodsRegex([]string{methodGet, methodPost})

var endpoints = []Endpoint{
	// oidc
	{role: AnonymousRole, method: methodGetAndPost, urlPath: "/.well-known*", entity: oidcEntity},
	// adapter
	{role: adminRole, method: methodPost, urlPath: "/api/add-adapter", entity: adapterEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-adapter", entity: adapterEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-adapters", entity: adapterEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-adapter", entity: adapterEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-adapter", entity: adapterEntity},
	// apiToken
	{role: adminRole, method: methodPost, urlPath: "/api/get-user-by-api-token", entity: apiTokenEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/add-api-token", entity: apiTokenEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-api-token", entity: apiTokenEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/recreate-api-token", entity: apiTokenEntity},
	// application
	{role: userRole, method: methodPost, urlPath: "/api/add-application", entity: applicationEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-application", entity: applicationEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-application", entity: applicationEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-default-application", entity: applicationEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-applications", entity: applicationEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-organization-applications", entity: applicationEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-user-application", entity: applicationEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-application", entity: applicationEntity},
	// cert
	{role: adminRole, method: methodPost, urlPath: "/api/add-cert", entity: certEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-cert", entity: certEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-cert", entity: certEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-certs", entity: certEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-globle-certs", entity: certEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-cert", entity: certEntity},
	// domain
	{role: adminRole, method: methodPost, urlPath: "/api/add-domain", entity: domainEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-domain", entity: domainEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-domain", entity: domainEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-domains", entity: domainEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-domain", entity: domainEntity},
	// enforcer
	{role: adminRole, method: methodPost, urlPath: "/api/add-enforcer", entity: enforcerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-enforcer", entity: enforcerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-enforcer", entity: enforcerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-enforcers", entity: enforcerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-enforcer", entity: enforcerEntity},
	// group
	{role: adminRole, method: methodPost, urlPath: "/api/add-group", entity: groupEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-group", entity: groupEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-group", entity: groupEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-groups", entity: groupEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-group", entity: groupEntity},
	// account
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-account", entity: accountEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/user", entity: accountEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/userinfo", entity: accountEntity},
	{role: AnonymousRole, method: methodPost, urlPath: "/api/set-password", entity: accountEntity},
	{role: AnonymousRole, method: methodPost, urlPath: "/api/reset-email-or-phone", entity: accountEntity},
	// ldap
	{role: adminRole, method: methodPost, urlPath: "/api/add-ldap", entity: ldapEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-ldap", entity: ldapEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-ldap", entity: ldapEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-ldap-server-names", entity: ldapEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-ldap-users", entity: ldapEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-ldaps", entity: ldapEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/sync-ldap-users", entity: ldapEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/test-ldap", entity: ldapEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-ldap", entity: ldapEntity},
	// model
	{role: adminRole, method: methodPost, urlPath: "/api/add-model", entity: modelEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-model", entity: modelEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-model", entity: modelEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-models", entity: modelEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-model", entity: modelEntity},
	// organization
	{role: adminRole, method: methodPost, urlPath: "/api/delete-organization", entity: organizationEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-organization", entity: organizationEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-organization-names", entity: organizationEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-organizations", entity: organizationEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-organization", entity: organizationEntity},
	// payment
	{role: adminRole, method: methodPost, urlPath: "/api/add-payment", entity: paymentEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-payment", entity: paymentEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-payment", entity: paymentEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-payments", entity: paymentEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-user-payments", entity: paymentEntity},
	{role: userRole, method: methodPost, urlPath: "/api/invoice-payment", entity: paymentEntity},
	{role: userRole, method: methodPost, urlPath: "/api/notify-payment", entity: paymentEntity},
	{role: userRole, method: methodPost, urlPath: "/api/update-payment", entity: paymentEntity},
	// permission
	{role: adminRole, method: methodPost, urlPath: "/api/add-permission", entity: permissionEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-permission", entity: permissionEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-permission", entity: permissionEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-permissions", entity: permissionEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-permissions-by-role", entity: permissionEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-permissions-by-submitter", entity: permissionEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-permission", entity: permissionEntity},
	// plan
	{role: adminRole, method: methodPost, urlPath: "/api/add-plan", entity: planEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-plan", entity: planEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-plan", entity: planEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-plans", entity: planEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-plan", entity: planEntity},
	// pricing
	{role: adminRole, method: methodPost, urlPath: "/api/add-pricing", entity: pricingEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-pricing", entity: pricingEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-pricing", entity: pricingEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-pricings", entity: pricingEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-pricing", entity: pricingEntity},
	// product
	{role: adminRole, method: methodPost, urlPath: "/api/add-product", entity: productEntity},
	{role: userRole, method: methodPost, urlPath: "/api/buy-product", entity: productEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-product", entity: productEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-product", entity: productEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-products", entity: productEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-product", entity: productEntity},
	// provider
	{role: adminRole, method: methodPost, urlPath: "/api/add-provider", entity: providerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-provider", entity: providerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-global-providers", entity: providerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-provider-saml-metadata", entity: providerEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-provider", entity: providerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-providers", entity: providerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/test-provider", entity: providerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-provider", entity: providerEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-saml-login", entity: providerEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/saml/metadata", entity: providerEntity},
	{role: AnonymousRole, method: methodPost, urlPath: "/api/acs", entity: providerEntity},
	{role: AnonymousRole, method: methodGetAndPost, urlPath: "/cas*", entity: providerEntity},
	// record
	{role: adminRole, method: methodPost, urlPath: "/api/add-record", entity: recordEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-records", entity: recordEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/get-records-filter", entity: recordEntity},
	// resource
	{role: adminRole, method: methodPost, urlPath: "/api/add-resource", entity: resourceEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-resource", entity: resourceEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-resource", entity: resourceEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-resources", entity: resourceEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-resource", entity: resourceEntity},
	{role: userRole, method: methodPost, urlPath: "/api/upload-resource", entity: resourceEntity},
	// role
	{role: adminRole, method: methodPost, urlPath: "/api/add-role", entity: roleEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-role", entity: roleEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-role", entity: roleEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-roles", entity: roleEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-role", entity: roleEntity},
	// session
	{role: adminRole, method: methodPost, urlPath: "/api/add-session", entity: sessionEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-session", entity: sessionEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-session", entity: sessionEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-sessions", entity: sessionEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/is-session-duplicated", entity: sessionEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-session", entity: sessionEntity},
	// subscription
	{role: adminRole, method: methodPost, urlPath: "/api/add-subscription", entity: subscriptionEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-subscription", entity: subscriptionEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-subscription", entity: subscriptionEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-subscriptions", entity: subscriptionEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-subscription", entity: subscriptionEntity},
	// syncer
	{role: adminRole, method: methodPost, urlPath: "/api/add-syncer", entity: syncerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-syncer", entity: syncerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-syncers", entity: syncerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/run-syncer", entity: syncerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-syncer", entity: syncerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-syncer", entity: syncerEntity},
	// token
	{role: adminRole, method: methodPost, urlPath: "/api/add-token", entity: tokenEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-token", entity: tokenEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-captcha-status", entity: tokenEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-token", entity: tokenEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-tokens", entity: tokenEntity},
	{role: AnonymousRole, method: methodGetAndPost, urlPath: "/api/login/oauth*", entity: tokenEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-token", entity: tokenEntity},
	// user
	{role: adminRole, method: methodPost, urlPath: "/api/add-user", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/add-user-keys", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/check-user-password", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-user", entity: userEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-email-and-phone", entity: userEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-global-users", entity: userEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-sorted-users", entity: userEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-user", entity: userEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-user-count", entity: userEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-users", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/remove-user-from-group", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/send-invite", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-user", entity: userEntity},
	// webhook
	{role: adminRole, method: methodPost, urlPath: "/api/add-webhook", entity: webhookEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-webhook", entity: webhookEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-webhook", entity: webhookEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-webhooks", entity: webhookEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-webhook", entity: webhookEntity},
	// metrics
	{role: AnonymousRole, method: methodGetAndPost, urlPath: "/api/metrics", entity: metricsEntity},
	// mfa
	{role: adminRole, method: methodPost, urlPath: "/api/delete-mfa", entity: mfaEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/mfa/setup/enable", entity: mfaEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/mfa/setup/initiate", entity: mfaEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/mfa/setup/verify", entity: mfaEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/set-prefered-mfa", entity: mfaEntity},
	// callback
	{role: AnonymousRole, method: methodPost, urlPath: "/api/callback", entity: callbackEntity},
	// login
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-app-login", entity: loginEntity},
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-captcha", entity: loginEntity},
	{role: AnonymousRole, method: methodPost, urlPath: "/api/login", entity: loginEntity},
	{role: AnonymousRole, method: methodGetAndPost, urlPath: "/api/logout", entity: loginEntity},
	{role: AnonymousRole, method: methodPost, urlPath: "/api/signup", entity: loginEntity},
	{role: AnonymousRole, method: methodPost, urlPath: "/api/unlink", entity: loginEntity},
	{role: AnonymousRole, method: methodGetAndPost, urlPath: "/api/webauthn*", entity: loginEntity},
	// dashboard
	{role: adminRole, method: methodGet, urlPath: "/api/get-dashboard", entity: dashboardEntity},
	// prometheus
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-prometheus-info", entity: prometheusEntity},
	// system
	{role: AnonymousRole, method: methodGet, urlPath: "/api/health", entity: systemEntity},
	// getWebhookEventType
	{role: AnonymousRole, method: methodGet, urlPath: "/api/get-webhook-event", entity: getWebhookEventTypeEntity},
	// verification
	{role: AnonymousRole, method: methodPost, urlPath: "/api/send-verification-code", entity: verificationEntity},
	{role: AnonymousRole, method: methodPost, urlPath: "/api/verify-captcha", entity: verificationEntity},
	{role: AnonymousRole, method: methodPost, urlPath: "/api/verify-code", entity: verificationEntity},
	// HandleOfficialAccountEvent
	{role: userRole, method: methodPost, urlPath: "/api/webhook", entity: handleOfficialAccountEventEntity},
}

var casbinEnforcer *casbin.SyncedEnforcer
var casbinEnforcerErr = "Error init casbin: %s"

func initCasbinModel() (casbinmodel.Model, error) {
	model, err := casbinmodel.NewModelFromString(
		`[request_definition]
r = subOwner, subName, method, urlPath, objOwner, objName

[policy_definition]
p = subOwner, subName, method, urlPath, objOwner, objName

[role_definition]
g = _,_,_
g2 = _,_

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.subName, p.subName, r.subOwner) && r.subOwner == p.subOwner && \
((r.objOwner == p.objOwner || r.objOwner == "admin") && \
(g2(r.objName, p.objName) || g2(r.objName, "exist") == false)) || \ 
(p.subName == "*" && p.subOwner == "*" && p.objOwner == "*" && p.objName == "*")) && \
regexMatch(r.method, p.method) && keyMatch(r.urlPath, p.urlPath) || \
r.subOwner == "built-in"
`)
	if err != nil {
		return nil, err
	}
	return model, nil
}

func initCasbinAdapter() (*xormadapter.Adapter, error) {
	driverName := conf.GetConfigString("driverName")
	dataSourceName := conf.GetConfigDataSourceName() +
		conf.GetConfigString("dbName")
	adapter, err := xormadapter.NewAdapter(driverName, dataSourceName, true)
	if err != nil {
		return &xormadapter.Adapter{}, err
	}
	return adapter, nil
}

func InitCasbinEnforcer() (*casbin.SyncedEnforcer, error) {
	model, err := initCasbinModel()
	if err != nil {
		return nil, fmt.Errorf(casbinEnforcerErr, err)
	}

	adapter, err := initCasbinAdapter()
	if err != nil {
		return nil, fmt.Errorf(casbinEnforcerErr, err)
	}

	casbinEnforcer, err = casbin.NewSyncedEnforcer(model, adapter)
	if err != nil {
		return nil, fmt.Errorf(casbinEnforcerErr, err)
	}
	return casbinEnforcer, nil
}

func addCasbinObjectGroupingPolicy(name, owner, entity string) (bool, error) {
	ok, err := casbinEnforcer.AddNamedGroupingPolicy(objectGroupingPolicy,
		name, fmt.Sprintf("%s-%ss", owner, entity))
	if !ok || err != nil {
		return ok, err
	}
	return true, nil
}

func updateCasbinObjectGroupingPolicy(oldName, oldOwner, newName, newOwner, entity string) (bool, error) {
	if oldName == newName && oldOwner == newOwner {
		return true, nil
	}
	ok, err := casbinEnforcer.UpdateNamedGroupingPolicy(objectGroupingPolicy,
		[]string{oldName, fmt.Sprintf("%s-%ss", oldOwner, entity)},
		[]string{newName, fmt.Sprintf("%s-%ss", newOwner, entity)})
	if !ok || err != nil {
		return ok, err
	}
	return true, nil
}

func removeCasbinObjectGroupingPolicy(name, owner, entity string) (bool, error) {
	ok, err := casbinEnforcer.RemoveNamedGroupingPolicy(objectGroupingPolicy,
		name, fmt.Sprintf("%s-%ss", owner, entity))
	if !ok || err != nil {
		return ok, err
	}
	return true, nil
}

func addOrganizationPolicies(organization *Organization) (bool, error) {
	var newPolicies [][]string
	uniqEntities := make(map[string]bool)
	for _, endpoint := range endpoints {
		_, ok := uniqEntities[endpoint.entity]
		if !ok {
			uniqEntities[endpoint.entity] = true
		}

		if endpoint.role == AnonymousRole {
			continue
		}

		newPolicies = append(newPolicies, []string{organization.Name, endpoint.role,
			endpoint.method, endpoint.urlPath, organization.Name,
			fmt.Sprintf("%s-%ss", organization.Name, endpoint.entity)})
	}
	ok, err := casbinEnforcer.AddPoliciesEx(newPolicies)
	if !ok || err != nil {
		return ok, err
	}

	var sharedEntityGroupingPolicies [][]string
	var existEntityGroups [][]string
	for entity := range uniqEntities {
		sharedEntityGroup := fmt.Sprintf("%s-%ss", adminOwner, entity)
		organizationEntityGroup := fmt.Sprintf("%s-%ss", organization.Name, entity)
		sharedEntityGroupingPolicies = append(sharedEntityGroupingPolicies,
			[]string{sharedEntityGroup, organizationEntityGroup})
		existEntityGroups = append(existEntityGroups, []string{organizationEntityGroup, existGroup})
	}
	newGroupingPolicies := util.ConcatSlices(sharedEntityGroupingPolicies, existEntityGroups)
	ok, err = casbinEnforcer.AddNamedGroupingPoliciesEx(objectGroupingPolicy, newGroupingPolicies)
	if !ok || err != nil {
		return ok, err
	}

	return true, nil
}

func removeOrganizationPolicies(organization *Organization) (bool, error) {
	var policies [][]string
	uniqEntities := make(map[string]bool)
	for _, endpoint := range endpoints {
		_, ok := uniqEntities[endpoint.entity]
		if !ok {
			uniqEntities[endpoint.entity] = true
		}

		if endpoint.role == AnonymousRole {
			continue
		}

		policies = append(policies, []string{organization.Name, endpoint.role,
			endpoint.method, endpoint.urlPath, organization.Name,
			fmt.Sprintf("%s-%ss", organization.Name, endpoint.entity)})
	}
	ok, err := casbinEnforcer.RemovePolicies(policies)
	if !ok || err != nil {
		return ok, err
	}

	var sharedEntityGroupingPolicies [][]string
	var existEntityGroups [][]string
	for entity := range uniqEntities {
		sharedEntityGroup := fmt.Sprintf("%s-%ss", adminOwner, entity)
		organizationEntityGroup := fmt.Sprintf("%s-%ss", organization.Name, entity)
		sharedEntityGroupingPolicies = append(sharedEntityGroupingPolicies,
			[]string{sharedEntityGroup, organizationEntityGroup})
		existEntityGroups = append(existEntityGroups, []string{organizationEntityGroup, existGroup})
	}
	groupingPolicies := util.ConcatSlices(sharedEntityGroupingPolicies, existEntityGroups)
	ok, err = casbinEnforcer.RemoveNamedGroupingPolicies(objectGroupingPolicy, groupingPolicies)
	if !ok || err != nil {
		return ok, err
	}

	return true, nil
}

func updateOrganizationPolicies(oldOrganization, newOrganization *Organization) (bool, error) {
	if oldOrganization.Name != newOrganization.Name {
		var oldPolicies [][]string
		var newPolicies [][]string
		for _, endpoint := range endpoints {
			if endpoint.role == AnonymousRole {
				continue
			}

			oldPolicies = append(oldPolicies, []string{oldOrganization.Name, endpoint.role,
				endpoint.method, endpoint.urlPath, oldOrganization.Name,
				fmt.Sprintf("%s-%ss", oldOrganization.Name, endpoint.entity)})

			newPolicies = append(newPolicies, []string{newOrganization.Name,
				endpoint.role, endpoint.method, endpoint.urlPath, newOrganization.Name,
				fmt.Sprintf("%s-%ss", newOrganization.Name, endpoint.entity)})
		}
		ok, err := casbinEnforcer.UpdatePolicies(oldPolicies, newPolicies)
		if !ok || err != nil {
			return ok, fmt.Errorf("error updating organization policies: %s", err)
		}

		orgRoles := casbinEnforcer.GetFilteredNamedGroupingPolicy(
			subjectGroupingPolicy, 2, oldOrganization.Name)
		var organizationRoles [][]string
		for _, orgRole := range orgRoles {
			organizationRole := []string{orgRole[0], orgRole[1], newOrganization.Name}
			organizationRoles = append(organizationRoles, organizationRole)
		}
		ok, err = casbinEnforcer.UpdateNamedGroupingPolicies(
			subjectGroupingPolicy, orgRoles, organizationRoles)
		if !ok || err != nil {
			return ok, fmt.Errorf("error updating organization roles policies: %s", err)
		}

		var orgGroups [][]string
		var orgExistGroups [][]string
		updatedEntities := make(map[string]bool)
		for _, endpoint := range endpoints {
			entity := endpoint.entity
			_, ok := updatedEntities[entity]
			if !ok {
				entityOrgGroups :=
					casbinEnforcer.GetFilteredNamedGroupingPolicy(objectGroupingPolicy,
						1, fmt.Sprintf("%s-%ss", oldOrganization.Name, entity))
				existedOrgGroups :=
					casbinEnforcer.GetFilteredNamedGroupingPolicy(objectGroupingPolicy,
						0, fmt.Sprintf("%s-%ss", oldOrganization.Name, entity))
				orgGroups = append(orgGroups, entityOrgGroups...)
				orgExistGroups = append(orgExistGroups, existedOrgGroups...)
				updatedEntities[entity] = true
			}
		}

		groupNameRegex := regexp.MustCompile(".*(-[^-]+$)")
		var organizationGroups [][]string
		var organizationExistGroups [][]string
		for _, orgGroup := range orgGroups {
			entityName := orgGroup[0]
			newGroupName := groupNameRegex.ReplaceAllStringFunc(orgGroup[1],
				func(match string) string {
					matches := groupNameRegex.FindStringSubmatch(match)
					entityName := matches[1]
					return newOrganization.Name + entityName
				})
			organizationGroup := []string{entityName, newGroupName}
			organizationGroups = append(organizationGroups, organizationGroup)
		}
		for _, orgExistGroup := range orgExistGroups {
			newExistGroupName := groupNameRegex.ReplaceAllStringFunc(orgExistGroup[0],
				func(match string) string {
					matches := groupNameRegex.FindStringSubmatch(match)
					entityName := matches[1]
					return newOrganization.Name + entityName
				})
			organizationExistGroup := []string{newExistGroupName, existGroup}
			organizationExistGroups = append(organizationExistGroups, organizationExistGroup)
		}
		oldGroupingPolicies := util.ConcatSlices(orgGroups, orgExistGroups)
		newGroupingPolicies := util.ConcatSlices(organizationGroups, organizationExistGroups)
		ok, err = casbinEnforcer.UpdateNamedGroupingPolicies(
			objectGroupingPolicy, oldGroupingPolicies, newGroupingPolicies)
		if !ok || err != nil {
			return ok, fmt.Errorf("error updating organization grouping policies: %s", err)
		}
	}

	return true, nil
}

func addRoleForUserInDomain(username string, isAdmin bool, userOwner string) (bool, error) {
	role := userRole
	if isAdmin {
		role = adminRole
	}
	ok, err := casbinEnforcer.AddRoleForUserInDomain(username, role, userOwner)
	if !ok || err != nil {
		return ok, err
	}

	return ok, nil
}

func deleteRoleForUserInDomain(username string, isAdmin bool, userOwner string) (bool, error) {
	role := userRole
	if isAdmin {
		role = adminRole
	}
	ok, err := casbinEnforcer.DeleteRoleForUserInDomain(username, role, userOwner)
	if !ok || err != nil {
		return ok, err
	}

	return true, nil
}

func updateRoleForUserInDomain(oldUsername string, isOldAdmin bool, oldUserOwner string, newUsername string, isNewAdmin bool, newUserOwner string) (bool, error) {
	if oldUsername != newUsername || oldUserOwner != newUserOwner || isOldAdmin != isNewAdmin {
		oldRole := userRole
		if isOldAdmin {
			oldRole = adminRole
		}
		newRole := userRole
		if isNewAdmin {
			newRole = adminRole
		}
		ok, err := casbinEnforcer.UpdateNamedGroupingPolicy(subjectGroupingPolicy,
			[]string{oldUsername, oldRole, oldUserOwner},
			[]string{newUsername, newRole, newUserOwner})
		if !ok || err != nil {
			return ok, err
		}
	}

	return true, nil
}

func InitCasbinPolicy() error {
	var anonymousPolicies [][]string
	anonymous := AnonymousRole
	for _, endpoint := range endpoints {
		if endpoint.role == anonymous {
			anonymousPolicies = append(anonymousPolicies,
				[]string{anonymous, anonymous, endpoint.method,
					endpoint.urlPath, anonymous, anonymous},
			)
		}
	}
	ok, err := casbinEnforcer.AddPoliciesEx(anonymousPolicies)
	if !ok || err != nil {
		return fmt.Errorf("error adding base policies: %s", err)
	}

	return nil
}
