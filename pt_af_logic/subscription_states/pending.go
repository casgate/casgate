package subscription_states

import (
	"errors"
	"fmt"

	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
	"github.com/xorm-io/builder"
)

type Pending struct {
	Base
}

func (st *Pending) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameSubPlan,
			PTAFLTypes.SubscriptionFieldNameDiscount,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *Pending) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRoleGlobalAdmin: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionUnauthorized, PTAFLTypes.SubscriptionPreAuthorized},
	}
}

func (st *Pending) RequiredFields() PTAFLTypes.SubscriptionFieldNames {
	return PTAFLTypes.SubscriptionFieldNames{
		PTAFLTypes.SubscriptionFieldNameSubUser,
		PTAFLTypes.SubscriptionFieldNameSubPlan,
		PTAFLTypes.SubscriptionFieldNameDiscount,
	}
}

func (st *Pending) ValidateRequirements(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	filter := builder.Neq{"state": []string{
		PTAFLTypes.SubscriptionNew.String(),
		PTAFLTypes.SubscriptionCancelled.String(),
		PTAFLTypes.SubscriptionPreFinished.String(),
		PTAFLTypes.SubscriptionFinished.String(),
	}}

	if subscription.User == "" {
		//should never happen - user is required field for pending state
		return errors.New("empty user")
	}

	userSubscriptionsCount, err := object.GetSubscriptionCount(subscription.Owner, "subscription.user", subscription.User, filter)
	if err != nil {
		return fmt.Errorf("object.GetSubscriptionCount: %w", err)
	}

	if userSubscriptionsCount > 0 {
		return errors.New(i18n.Translate(PTAFLTypes.PtlmLanguage, "subscription:Customer has active subscriptions"))
	}

	return nil
}

func (st *Pending) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error

	err := notify.NotifyAdminSubscriptionUpdated(user, subscription, old)
	if err != nil {
		errs = append(errs, fmt.Errorf("NotifyAdminSubscriptionUpdated: %w", err))
	}

	return errs
}
