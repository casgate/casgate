package subscription_states

import (
	"fmt"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type Finished struct {
	Base
}

func (st *Finished) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *Finished) RequiredFields() PTAFLTypes.SubscriptionFieldNames {
	return PTAFLTypes.SubscriptionFieldNames{
		PTAFLTypes.SubscriptionFieldNameEndDate,
	}
}

func (st *Finished) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error

	err := notify.NotifyCRMSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyCRMSubscriptionUpdated: %w", err))
	}

	return errs
}
