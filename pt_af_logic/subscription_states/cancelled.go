package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	"github.com/casdoor/casdoor/pt_af_logic/tenant"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type Cancelled struct {
	Base
}

func (st *Cancelled) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *Cancelled) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error
	err := notify.NotifyPartnerSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyPartnerSubscriptionUpdated: %s", err))
	}

	if !subscription.WasPilot {
		return errs
	}

	err = tenant.DisableTenant(subscription)
	if err != nil {
		errs = append(errs, fmt.Errorf("tenant.DisableTenant: %w", err))
	}

	return errs
}
