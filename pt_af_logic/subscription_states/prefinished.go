package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type PreFinished struct {
	Base
}

func (st *PreFinished) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRoleDistributor: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameEndDate,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *PreFinished) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRoleDistributor: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionFinished},
	}
}

func (st *PreFinished) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error

	err := notify.NotifyDistributorSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyDistributorSubscriptionUpdated: %w", err))
	}

	return errs
}
