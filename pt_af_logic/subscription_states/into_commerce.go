package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type IntoCommerce struct {
	Base
}

func (st *IntoCommerce) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *IntoCommerce) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRoleGlobalAdmin: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionAuthorized, PTAFLTypes.SubscriptionCancelled},
	}
}

func (st *IntoCommerce) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error

	err := notify.NotifyAdminSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyAdminSubscriptionUpdated: %w", err))
	}

	return errs
}
