package subscription_states

import (
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
)

type New struct {
	Base
}

func (st *New) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameName,
			PTAFLTypes.SubscriptionFieldNameDisplayName,
			PTAFLTypes.SubscriptionFieldNameSubUser,
			PTAFLTypes.SubscriptionFieldNameSubPlan,
			PTAFLTypes.SubscriptionFieldNameDiscount,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *New) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRolePartner: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionPending, PTAFLTypes.SubscriptionPilot},
	}
}
