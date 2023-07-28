package tenant

import (
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	"github.com/casdoor/casdoor/pt_af_logic/pwd_generator"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
	af_client "github.com/casdoor/casdoor/pt_af_sdk"
	"github.com/casdoor/casdoor/util"
)

const defaultPasswordLength = 12

func CreateOrEnableTenant(subscription *object.Subscription) error {
	afHost := conf.GetConfigString("PT_AF_URL")
	afLogin := conf.GetConfigString("PT_AF_LOGIN")
	afPwd := conf.GetConfigString("PT_AF_PASSWORD")
	afFingerPrint := conf.GetConfigString("PT_AF_FINGERPRINT")
	af := af_client.NewPtAF(afHost)

	allRoles := af.GetRoles()
	if allRoles == nil {
		return fmt.Errorf("no roles found")
	}

	customer, err := object.GetUser(subscription.User)
	if err != nil {
		return fmt.Errorf("object.GetUser: %w", err)
	}
	customerOrganization, err := object.GetOrganization(util.GetId("admin", customer.Owner))
	if err != nil {
		return fmt.Errorf("object.GetOrganization: %w", err)
	}

	adminLoginResp, err := af.Login(af_client.LoginRequest{
		Username:    afLogin,
		Password:    afPwd,
		Fingerprint: afFingerPrint,
	})
	if err != nil {
		return fmt.Errorf("af.Login: %w", err)
	}

	af.Token = adminLoginResp.AccessToken

	tenantName := fmt.Sprintf("%s - %s", customer.Owner, customer.Name)

	// if tenant already exists - no action required
	if tenantID, found := customer.Properties[af_client.PtPropPref+"Tenant ID"]; found {
		existingTenant, err := af.GetTenant(tenantID)
		if err != nil {
			return fmt.Errorf("af.GetTenant: %w", err)
		}

		if existingTenant != nil {
			// tenant already exist - enable existing tenant.
			err = af.SetTenantStatus(tenantID, true)
			if err != nil {
				return fmt.Errorf("af.SetTenantStatus: %w", err)
			}
			return nil
		}
	}

	tenantAdminPassword, err := pwd_generator.GeneratePassword(defaultPasswordLength)
	if err != nil {
		return fmt.Errorf("generatePassword for admin: %w", err)
	}

	tenantAdminName := fmt.Sprintf("%s_%s_admin", customer.Owner, customer.Name)

	portalAdmin, err := object.GetUser(util.GetId(PTAFLTypes.BuiltInOrgCode, "admin"))
	if err != nil {
		return fmt.Errorf("object.GetUser for portal admin: %w", err)
	}

	request := af_client.Tenant{
		Name:     tenantName,
		IsActive: true,
		TrafficProcessing: af_client.TrafficProcessing{
			TrafficProcessingType: "agent",
		},
		Administrator: af_client.Administrator{
			Email:                  portalAdmin.Email,
			Username:               tenantAdminName,
			Password:               tenantAdminPassword,
			IsActive:               true,
			PasswordChangeRequired: false,
		},
	}

	tenant, err := af.CreateTenant(request)
	if err != nil {
		return fmt.Errorf("af.CreateTenant: %w", err)
	}

	if tenant != nil {
		// login from tenant admin
		token, err := af.Login(af_client.LoginRequest{
			Username:    tenantAdminName,
			Password:    tenantAdminPassword,
			Fingerprint: afFingerPrint,
		})
		if err != nil {
			return fmt.Errorf("af.Login: %w", err)
		}
		af.Token = token.AccessToken

		tenant, err = af.GetTenant(tenant.ID)
		if err != nil {
			return fmt.Errorf("af.GetTenant: %w", err)
		}
		connectionString := tenant.BorderConnectionString

		// create proper roles
		var serviceRole, userRORole, userRole af_client.Role
		var serviceRoleFound, userRORoleFound, userRoleFound bool
		for _, role := range allRoles {
			if strings.EqualFold(role.Name, "Service") {
				serviceRole = role
				serviceRoleFound = true
			}

			if strings.EqualFold(role.Name, "User RO") {
				userRORole = role
				userRORoleFound = true
			}

			if strings.EqualFold(role.Name, "User") {
				userRole = role
				userRoleFound = true
			}
		}

		if !serviceRoleFound {
			return fmt.Errorf("no service role found")
		}

		if !userRORoleFound {
			return fmt.Errorf("no user RO role found")
		}

		if !userRoleFound {
			return fmt.Errorf("no user role found")
		}

		userRORoleID, err := af.CreateRole(userRORole)
		if err != nil {
			return fmt.Errorf("af.CreateRole(userRORole): %w", err)
		}

		serviceRoleID, err := af.CreateRole(serviceRole)
		if err != nil {
			return fmt.Errorf("af.CreateRole(serviceRole): %w", err)
		}

		userRoleID, err := af.CreateRole(userRole)
		if err != nil {
			return fmt.Errorf("af.CreateRole(userRole): %w", err)
		}

		// create users
		userROName := fmt.Sprintf("%s_%s", customer.Name, customer.Owner)
		userROPwd, err := pwd_generator.GeneratePassword(defaultPasswordLength)
		if err != nil {
			return fmt.Errorf("generatePassword: %w", err)
		}
		createUserRORequest := af_client.CreateUserRequest{
			Username:               userROName,
			Password:               userROPwd,
			Email:                  customer.Email,
			Role:                   userRORoleID,
			PasswordChangeRequired: true,
			IsActive:               true,
		}

		err = af.CreateUser(createUserRORequest)
		if err != nil {
			return fmt.Errorf("af.CreateUser with user RO role: %w", err)
		}

		userName := fmt.Sprintf("%s_%s_ctrl", customer.Name, customer.Owner)
		userPwd, err := pwd_generator.GeneratePassword(defaultPasswordLength)
		if err != nil {
			return fmt.Errorf("generatePassword: %w", err)
		}
		createUserRequest := af_client.CreateUserRequest{
			Username:               userName,
			Password:               userPwd,
			Email:                  fmt.Sprintf("%s_%s_ctrl@example.com", customer.Name, customer.Owner),
			Role:                   userRoleID,
			PasswordChangeRequired: true,
			IsActive:               true,
		}

		err = af.CreateUser(createUserRequest)
		if err != nil {
			return fmt.Errorf("af.CreateUser with user role: %w", err)
		}

		serviceUserName := fmt.Sprintf("%s_%s_service", customer.Name, customer.Owner)
		serviceUserPwd, err := pwd_generator.GeneratePassword(defaultPasswordLength)
		if err != nil {
			return fmt.Errorf("generatePassword: %w", err)
		}
		createServiceUserRequest := af_client.CreateUserRequest{
			Username:               serviceUserName,
			Password:               serviceUserPwd,
			Email:                  customerOrganization.Email,
			Role:                   serviceRoleID,
			PasswordChangeRequired: true,
			IsActive:               true,
		}

		err = af.CreateUser(createServiceUserRequest)
		if err != nil {
			return fmt.Errorf("af.CreateUser with service role: %w", err)
		}

		// disable tenant admin account
		af.Token = adminLoginResp.AccessToken
		err = af.UpdateTenant(af_client.Tenant{
			ID:       tenant.ID,
			IsActive: true,
			Administrator: af_client.Administrator{
				IsActive: false,
			},
		})
		if err != nil {
			return fmt.Errorf("af.UpdateTenant(disable admin password): %w", err)
		}

		// update customer properties
		if customer.Properties == nil {
			customer.Properties = make(map[string]string)
		}

		customer.Properties[af_client.PtPropPref+"Tenant Name"] = tenantName
		customer.Properties[af_client.PtPropPref+"Tenant ID"] = tenant.ID
		customer.Properties[af_client.PtPropPref+"Connection String"] = connectionString
		customer.Properties[af_client.PtPropPref+"ClientAccountLogin"] = userROName
		customer.Properties[af_client.PtPropPref+"ClientControlAccountLogin"] = userName
		customer.Properties[af_client.PtPropPref+"ServiceAccountLogin"] = serviceUserName

		affected, err := object.UpdateUser(customer.GetId(), customer, []string{"properties"}, false)
		if err != nil {
			return fmt.Errorf("object.UpdateUser: %w", err)
		}

		if !affected {
			return fmt.Errorf("object.UpdateUser didn't affected rows")
		}

		// email tenant admin info and accounts for created tenant
		err = notify.NotifyPTAFTenantCreated(&notify.PTAFTenantCreatedMessage{
			ClientName:          customer.Name,
			ClientDisplayName:   customer.DisplayName,
			ClientURL:           fmt.Sprintf("%s/clients/%s/%s", conf.GetConfigString("origin"), customer.Owner, customer.Name),
			ServiceUserName:     serviceUserName,
			ServiceUserPwd:      serviceUserPwd,
			UserROName:          userROName,
			UserROPwd:           userROPwd,
			UserName:            userName,
			UserPwd:             userPwd,
			TenantAdminName:     tenantAdminName,
			TenantAdminPassword: tenantAdminPassword,
			PTAFLoginLink:       util.GetUrlHost(afHost),
			ConnectionString:    connectionString,
		}, customerOrganization.Email)
		if err != nil {
			return fmt.Errorf("notifyPTAFTenantCreated: %w", err)
		}
	}

	return nil
}
