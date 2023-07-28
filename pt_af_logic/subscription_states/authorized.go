package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type Authorized struct {
	Base
}

func (st *Authorized) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRoleDistributor: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameStartDate,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *Authorized) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRoleDistributor: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionStarted, PTAFLTypes.SubscriptionCancelled},
	}
}

func (st *Authorized) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error

	err := notify.NotifyDistributorSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyDistributorSubscriptionUpdated: %w", err))
	}

	err = notify.NotifyCRMSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyCRMSubscriptionUpdated: %w", err))
	}

	return errs
}
