package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type Unauthorized struct {
	Base
}

func (st *Unauthorized) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameSubPlan,
			PTAFLTypes.SubscriptionFieldNameDiscount,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *Unauthorized) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRolePartner: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionPending, PTAFLTypes.SubscriptionCancelled},
	}
}

func (st *Unauthorized) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error
	err := notify.NotifyPartnerSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyPartnerSubscriptionUpdated: %w", err))
	}

	return errs
}
