package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	"github.com/casdoor/casdoor/pt_af_logic/tenant"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type PilotExpired struct {
	Base
}

func (st *PilotExpired) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *PilotExpired) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRolePartner:     PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionCancelled},
		PTAFLTypes.UserRoleGlobalAdmin: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionPilot},
	}
}
func (st *PilotExpired) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error

	err := notify.NotifyAdminSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyAdminSubscriptionUpdated: %w", err))
	}

	err = notify.NotifyPartnerSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyPartnerSubscriptionUpdated: %w", err))
	}

	err = tenant.DisableTenant(subscription)
	if err != nil {
		errs = append(errs, fmt.Errorf("tenant.DisableTenant: %w", err))
	}

	return errs
}
