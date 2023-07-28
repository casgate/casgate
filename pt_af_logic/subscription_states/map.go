package subscription_states

import (
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/types"
)

type SubscriptionState interface {
	FieldPermissions() types.SubscriptionFieldPermissions
	Transitions() types.SubscriptionTransitions
	RequiredFields() types.SubscriptionFieldNames
	// ValidateRequirements additional checks for current state
	ValidateRequirements(user *object.User, subscription *object.Subscription, old *object.Subscription) error
	// FillSubscription fills some calculated subscription fields for transition to state
	FillSubscription(user *object.User, subscription *object.Subscription, old *object.Subscription) error
	// PostAction makes some actions after state change
	PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error
}

var SubscriptionStateMap = map[types.SubscriptionStateName]SubscriptionState{
	types.SubscriptionNew:           &New{},
	types.SubscriptionPilot:         &Pilot{},
	types.SubscriptionPilotExpired:  &PilotExpired{},
	types.SubscriptionPending:       &Pending{},
	types.SubscriptionPreAuthorized: &PreAuthorized{},
	types.SubscriptionIntoCommerce:  &IntoCommerce{},
	types.SubscriptionUnauthorized:  &Unauthorized{},
	types.SubscriptionAuthorized:    &Authorized{},
	types.SubscriptionStarted:       &Started{},
	types.SubscriptionPreFinished:   &PreFinished{},
	types.SubscriptionFinished:      &Finished{},
	types.SubscriptionCancelled:     &Cancelled{},
}
