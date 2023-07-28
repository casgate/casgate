package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	"github.com/casdoor/casdoor/pt_af_logic/tenant"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type Started struct {
	Base
}

func (st *Started) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *Started) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRolePartner: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionPreFinished},
	}
}

func (st *Started) RequiredFields() PTAFLTypes.SubscriptionFieldNames {
	return PTAFLTypes.SubscriptionFieldNames{
		PTAFLTypes.SubscriptionFieldNameStartDate,
	}
}

func (st *Started) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error

	err := notify.NotifyCRMSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyCRMSubscriptionUpdated: %w", err))
	}

	// create or enable tenant at pt af
	err = tenant.CreateOrEnableTenant(subscription)
	if err != nil {
		errs = append(errs, fmt.Errorf("tenant.CreateOrEnableTenant: %w", err))
	}

	return errs
}
