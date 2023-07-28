package subscription_states

import (
	"github.com/casdoor/casdoor/object"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type Base struct{}

func (st *Base) ValidateRequirements(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	return nil
}

func (st *Base) FillSubscription(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	return nil
}

func (st *Base) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return nil
}

func (st *Base) Transitions() PTAFLTypes.SubscriptionTransitions {
	return nil
}

func (st *Base) RequiredFields() PTAFLTypes.SubscriptionFieldNames {
	return nil
}

func (st *Base) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	return nil
}
