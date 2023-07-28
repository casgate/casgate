package tenant

import (
	"fmt"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	af_client "github.com/casdoor/casdoor/pt_af_sdk"
)

func DisableTenant(subscription *object.Subscription) error {
	afHost := conf.GetConfigString("PT_AF_URL")
	afLogin := conf.GetConfigString("PT_AF_LOGIN")
	afPwd := conf.GetConfigString("PT_AF_PASSWORD")
	afFingerPrint := conf.GetConfigString("PT_AF_FINGERPRINT")
	af := af_client.NewPtAF(afHost)

	adminLoginResp, err := af.Login(af_client.LoginRequest{
		Username:    afLogin,
		Password:    afPwd,
		Fingerprint: afFingerPrint,
	})
	if err != nil {
		return fmt.Errorf("af.Login: %w", err)
	}

	af.Token = adminLoginResp.AccessToken

	customer, err := object.GetUser(subscription.User)
	if err != nil {
		return fmt.Errorf("object.GetUser: %w", err)
	}

	if tenantID, found := customer.Properties[af_client.PtPropPref+"Tenant ID"]; found {
		existingTenant, err := af.GetTenant(tenantID)
		if err != nil {
			return fmt.Errorf("af.GetTenant: %w", err)
		}

		if existingTenant != nil {
			// tenant exist - disable
			err = af.SetTenantStatus(tenantID, false)
			if err != nil {
				return fmt.Errorf("af.SetTenantStatus: %w", err)
			}
			return nil
		}
	}

	return nil
}
