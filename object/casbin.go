package object

import (
	"fmt"

	"github.com/casbin/casbin/v2"
	casbinmodel "github.com/casbin/casbin/v2/model"
	xormadapter "github.com/casbin/xorm-adapter/v2"
	"github.com/casdoor/casdoor/conf"
)

const (
	adminRole = "admin"
	userRole  = "user"

	subjectGroupingPolicy = "g"
	objectGroupingPolicy  = "g2"

	methodGet  = "GET"
	methodPost = "POST"

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
	mfaEntity                        = "mfa"
	dashboardEntity                  = "dashboard"
	handleOfficialAccountEventEntity = "handleOfficialAccountEvent"
)

type Endpoint struct {
	role    string
	method  string
	urlPath string
	entity  string
}

var endpoints = []Endpoint{
	// adapter
	{role: adminRole, method: methodPost, urlPath: "/api/add-adapter", entity: adapterEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-adapter", entity: adapterEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-adapters", entity: adapterEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-adapter", entity: adapterEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-adapter", entity: adapterEntity},
	// apiToken
	{role: adminRole, method: methodPost, urlPath: "/api/get-user-by-api-token", entity: apiTokenEntity},
	// application
	{role: adminRole, method: methodPost, urlPath: "/api/add-application", entity: applicationEntity},
	{role: userRole, method: methodPost, urlPath: "/api/add-application", entity: applicationEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-application", entity: applicationEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-applications", entity: applicationEntity},
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
	// ldap
	{role: adminRole, method: methodPost, urlPath: "/api/add-ldap", entity: ldapEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-ldap", entity: ldapEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-ldap", entity: ldapEntity},
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
	{role: adminRole, method: methodPost, urlPath: "/api/add-organization", entity: organizationEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-organization", entity: organizationEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-organization", entity: organizationEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-organizations", entity: organizationEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-organization", entity: organizationEntity},
	// payment
	{role: adminRole, method: methodPost, urlPath: "/api/add-payment", entity: paymentEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-payment", entity: paymentEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-payment", entity: paymentEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-payment", entity: paymentEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-payments", entity: paymentEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-user-payments", entity: paymentEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/invoice-payment", entity: paymentEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/notify-payment", entity: paymentEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-payment", entity: paymentEntity},
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
	{role: adminRole, method: methodGet, urlPath: "/api/get-plans", entity: planEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-plan", entity: planEntity},
	// pricing
	{role: adminRole, method: methodPost, urlPath: "/api/add-pricing", entity: pricingEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-pricing", entity: pricingEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-pricings", entity: pricingEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-pricing", entity: pricingEntity},
	// product
	{role: adminRole, method: methodPost, urlPath: "/api/add-product", entity: productEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/buy-product", entity: productEntity},
	{role: userRole, method: methodPost, urlPath: "/api/buy-product", entity: productEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-product", entity: productEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-product", entity: productEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-product", entity: productEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-products", entity: productEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-product", entity: productEntity},
	// provider
	{role: adminRole, method: methodPost, urlPath: "/api/add-provider", entity: providerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-provider", entity: providerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-global-providers", entity: providerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-provider-saml-metadata", entity: providerEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-providers", entity: providerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/test-provider", entity: providerEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-provider", entity: providerEntity},
	// record
	{role: adminRole, method: methodPost, urlPath: "/api/add-record", entity: recordEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-records", entity: recordEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/get-records-filter", entity: recordEntity},
	// resource
	{role: adminRole, method: methodPost, urlPath: "/api/add-resource", entity: resourceEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-resource", entity: resourceEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-resource", entity: resourceEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-resources", entity: resourceEntity},
	{role: userRole, method: methodGet, urlPath: "/api/get-resources", entity: resourceEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-resource", entity: resourceEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/upload-resource", entity: resourceEntity},
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
	{role: adminRole, method: methodGet, urlPath: "/api/get-subscription", entity: subscriptionEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-subscriptions", entity: subscriptionEntity},
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
	{role: adminRole, method: methodGet, urlPath: "/api/get-token", entity: tokenEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-tokens", entity: tokenEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/login/oauth/access_token", entity: tokenEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/login/oauth/refresh_token", entity: tokenEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/update-token", entity: tokenEntity},
	// user
	{role: adminRole, method: methodPost, urlPath: "/api/add-user", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/add-user-keys", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/check-user-password", entity: userEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/delete-user", entity: userEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-global-users", entity: userEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-sorted-users", entity: userEntity},
	{role: adminRole, method: methodGet, urlPath: "/api/get-user", entity: userEntity},
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
	// mfa
	{role: adminRole, method: methodPost, urlPath: "/api/delete-mfa", entity: mfaEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/mfa/setup/enable", entity: mfaEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/mfa/setup/initiate", entity: mfaEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/mfa/setup/verify", entity: mfaEntity},
	{role: adminRole, method: methodPost, urlPath: "/api/set-prefered-mfa", entity: mfaEntity},
	// dashboard
	{role: adminRole, method: methodGet, urlPath: "/api/get-dashboard", entity: dashboardEntity},
	// HandleOfficialAccountEvent
	{role: adminRole, method: methodPost, urlPath: "/api/webhook", entity: handleOfficialAccountEventEntity},
	{role: userRole, method: methodPost, urlPath: "/api/webhook", entity: handleOfficialAccountEventEntity},
}

var casbinEnforcer *casbin.Enforcer
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
(g2(r.objName, p.objName) || r.objOwner == p.objOwner) || \
(p.subName == "*" && p.subOwner == "*" && p.objOwner == "*" && p.objName == "*")) && \
regexMatch(r.method, p.method) && \
keyMatch(r.urlPath, p.urlPath) || \
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

func InitCasbinEnforcer() (*casbin.Enforcer, error) {
	model, err := initCasbinModel()
	if err != nil {
		return nil, fmt.Errorf(casbinEnforcerErr, err)
	}

	adapter, err := initCasbinAdapter()
	if err != nil {
		return nil, fmt.Errorf(casbinEnforcerErr, err)
	}

	casbinEnforcer, err = casbin.NewEnforcer(model, adapter)
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
