package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type PreAuthorized struct {
	Base
}

func (st *PreAuthorized) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameDescription,
			PTAFLTypes.SubscriptionFieldNameDiscount,
		},
	}
}

func (st *PreAuthorized) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRolePartner: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionIntoCommerce, PTAFLTypes.SubscriptionCancelled},
	}
}

func (st *PreAuthorized) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error
	err := notify.NotifyPartnerSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyPartnerSubscriptionUpdated: %w", err))
	}

	return errs
}
