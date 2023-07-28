package subscription_states

import (
	"errors"
	"fmt"
	"time"

	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/tenant"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/builder"
)

type Pilot struct {
	Base
}

func (st *Pilot) FieldPermissions() PTAFLTypes.SubscriptionFieldPermissions {
	return PTAFLTypes.SubscriptionFieldPermissions{
		PTAFLTypes.UserRolePartner: {
			PTAFLTypes.SubscriptionFieldNameSubPlan,
			PTAFLTypes.SubscriptionFieldNameDiscount,
			PTAFLTypes.SubscriptionFieldNameDescription,
		},
	}
}

func (st *Pilot) Transitions() PTAFLTypes.SubscriptionTransitions {
	return PTAFLTypes.SubscriptionTransitions{
		PTAFLTypes.UserRolePartner: PTAFLTypes.SubscriptionStateNames{PTAFLTypes.SubscriptionPending, PTAFLTypes.SubscriptionCancelled},
	}
}

func (st *Pilot) RequiredFields() PTAFLTypes.SubscriptionFieldNames {
	return PTAFLTypes.SubscriptionFieldNames{
		PTAFLTypes.SubscriptionFieldNameSubUser,
	}
}

func (st *Pilot) ValidateRequirements(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	filter := builder.And(builder.Eq{
		"subscription.user": subscription.User,
	},
		builder.Neq{
			"state": []string{
				PTAFLTypes.SubscriptionNew.String(),
				PTAFLTypes.SubscriptionCancelled.String(),
				PTAFLTypes.SubscriptionFinished.String(),
			}}.Or(builder.And(
			builder.Eq{
				"state":     PTAFLTypes.SubscriptionCancelled.String(),
				"was_pilot": true},
			builder.Expr("TO_DATE(approve_time,'YYYY-MM-DD')>TO_DATE(?,'YYYY-MM-DD')",
				time.Now().AddDate(0, -3, 0).Format("2006-01-02")),
		)).Or(builder.And(
			builder.Eq{
				"state": PTAFLTypes.SubscriptionFinished.String(),
			},
			builder.Gt{
				"end_date": time.Now().Truncate(24*time.Hour).AddDate(0, -1, 0),
			},
		)))

	if subscription.User == "" {
		//should never happen - user is required field for pending state
		return errors.New("empty user")
	}

	userSubscriptionsCount, err := object.GetSubscriptionCount(subscription.Owner, "", "", filter)
	if err != nil {
		return fmt.Errorf("object.GetSubscriptionCount(customerLimit): %w", err)
	}

	if userSubscriptionsCount > 0 {
		return errors.New(i18n.Translate(PTAFLTypes.PtlmLanguage, "subscription:Customer doesn't meet the requirements for pilot"))
	}

	filterPilotLimit := builder.Eq{
		"was_pilot": true,
		"state": []string{
			PTAFLTypes.SubscriptionPilot.String(),
			PTAFLTypes.SubscriptionPending.String(),
			PTAFLTypes.SubscriptionUnauthorized.String(),
			PTAFLTypes.SubscriptionPreAuthorized.String(),
			PTAFLTypes.SubscriptionPilotExpired.String(),
		},
	}

	organization, err := object.GetOrganization(util.GetId("admin", subscription.Owner))
	if err != nil {
		return fmt.Errorf("object.GetOrganization: %w", err)
	}

	partnerPilotSubscriptionsCount, err := object.GetSubscriptionCount(subscription.Owner, "", "", filterPilotLimit)
	if err != nil {
		return fmt.Errorf("object.GetSubscriptionCount(partnerLimit): %w", err)
	}

	if uint(partnerPilotSubscriptionsCount) >= organization.PilotLimit {
		return errors.New(i18n.Translate(PTAFLTypes.PtlmLanguage, "subscription:Pilot Limit exceeded"))
	}

	return nil
}

func (st *Pilot) FillSubscription(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	subscription.WasPilot = true

	mskLoc, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		return fmt.Errorf("time.LoadLocation: %w", err)
	}

	expiryDate := time.Now().In(mskLoc).Truncate(24*time.Hour).AddDate(0, 1, 0)
	subscription.PilotExpiryDate = &expiryDate

	return nil
}

func (st *Pilot) PostAction(user *object.User, subscription *object.Subscription, old *object.Subscription) []error {
	var errs []error
	// create or enable tenant at pt af
	err := tenant.CreateOrEnableTenant(subscription)
	if err != nil {
		errs = append(errs, fmt.Errorf("tenant.CreateOrEnableTenant: %w", err))
	}

	return errs
}
