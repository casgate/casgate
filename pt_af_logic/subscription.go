package pt_af_logic

import (
	"errors"
	"fmt"
	"time"

	"github.com/beego/beego/context"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic/notify"
	"github.com/casdoor/casdoor/pt_af_logic/subscription_states"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/builder"
)

// ValidateSubscriptionStateIsAllowed checks if user has permission to assign a new subscription state
func ValidateSubscriptionStateIsAllowed(subscriptionRole PTAFLTypes.UserRole, oldStateName, nextStateName PTAFLTypes.SubscriptionStateName) error {
	if oldStateName == nextStateName {
		return nil
	}

	oldState, ok := subscription_states.SubscriptionStateMap[oldStateName]
	if !ok {
		return fmt.Errorf("incorrect old state: %s", oldStateName)
	}

	roleAvailableTransitions, ok := oldState.Transitions()[subscriptionRole]
	if !ok {
		return PTAFLTypes.NewStateChangeForbiddenError(roleAvailableTransitions)
	}

	if !roleAvailableTransitions.Contains(nextStateName) {
		return PTAFLTypes.NewStateChangeForbiddenError(roleAvailableTransitions)
	}

	return nil
}

func ValidateSubscriptionRequiredFieldsIsFilled(
	userRole PTAFLTypes.UserRole,
	old, new *object.Subscription,
) error {
	if userRole == PTAFLTypes.UserRoleGlobalAdmin {
		return nil
	}

	if old.State == new.State {
		return nil
	}

	newState, ok := subscription_states.SubscriptionStateMap[PTAFLTypes.SubscriptionStateName(new.State)]
	if !ok {
		return fmt.Errorf("incorrect state: %s", new.State)
	}
	requiredFields := newState.RequiredFields()
	for _, requiredField := range requiredFields {
		switch requiredField {
		case PTAFLTypes.SubscriptionFieldNameSubUser:
			if new.User == "" {
				return PTAFLTypes.NewRequiredFieldNotFilledError(PTAFLTypes.SubscriptionFieldNameSubUser)
			}
		case PTAFLTypes.SubscriptionFieldNameDiscount:
			if new.Discount < 15 || new.Discount > 40 || new.Discount%5 != 0 {
				return PTAFLTypes.NewRequiredFieldNotFilledError(PTAFLTypes.SubscriptionFieldNameDiscount)
			}
		case PTAFLTypes.SubscriptionFieldNameSubPlan:
			if new.Plan == "" {
				return PTAFLTypes.NewRequiredFieldNotFilledError(PTAFLTypes.SubscriptionFieldNameSubPlan)
			}
		case PTAFLTypes.SubscriptionFieldNameStartDate:
			if new.StartDate.IsZero() {
				return PTAFLTypes.NewRequiredFieldNotFilledError(PTAFLTypes.SubscriptionFieldNameStartDate)
			}
		case PTAFLTypes.SubscriptionFieldNameEndDate:
			if new.EndDate.IsZero() {
				return PTAFLTypes.NewRequiredFieldNotFilledError(PTAFLTypes.SubscriptionFieldNameEndDate)
			}
		}
	}

	return nil
}

// ValidateSubscriptionFieldsChangeIsAllowed checks if user has permission to change fields
func ValidateSubscriptionFieldsChangeIsAllowed(
	userRole PTAFLTypes.UserRole,
	old, new *object.Subscription,
) error {
	oldState, ok := subscription_states.SubscriptionStateMap[PTAFLTypes.SubscriptionStateName(old.State)]
	if !ok {
		return fmt.Errorf("incorrect state: %s", new.State)
	}

	newState, ok := subscription_states.SubscriptionStateMap[PTAFLTypes.SubscriptionStateName(new.State)]
	if !ok {
		return fmt.Errorf("incorrect state: %s", new.State)
	}

	oldRoleFieldPermission := oldState.FieldPermissions()[userRole]
	newRoleFieldPermission := newState.FieldPermissions()[userRole]

	if old.Name != new.Name {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameName)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameName)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameName)
		}
	}

	if old.DisplayName != new.DisplayName {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDisplayName)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDisplayName)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameDisplayName)
		}
	}

	if !old.StartDate.Equal(new.StartDate) {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameStartDate)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameStartDate)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameStartDate)
		}
	}

	if !old.EndDate.Equal(new.EndDate) {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameEndDate)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameEndDate)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameEndDate)
		}
	}

	if old.User != new.User {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameSubUser)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameSubUser)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameSubUser)
		}
	}

	if old.Plan != new.Plan {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameSubPlan)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameSubPlan)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameSubPlan)
		}
	}

	if old.Discount != new.Discount {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDiscount)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDiscount)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameDiscount)
		}
	}

	if old.Description != new.Description {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDescription)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDescription)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameDescription)
		}
	}

	if old.Comment != new.Comment {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameComment)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameComment)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameComment)
		}
	}

	if old.WasPilot != new.WasPilot {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameWasPilot)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameWasPilot)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameWasPilot)
		}
	}

	if old.PilotExpiryDate != new.PilotExpiryDate {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNamePilotExpiryDate)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNamePilotExpiryDate)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNamePilotExpiryDate)
		}
	}

	if old.Approver != new.Approver {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameApprover)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameApprover)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameApprover)
		}
	}

	if old.ApproveTime != new.ApproveTime {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameApproveTime)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameApproveTime)
		if !oldContains && !newContains {
			return PTAFLTypes.NewForbiddenFieldChangeError(PTAFLTypes.SubscriptionFieldNameApproveTime)
		}
	}

	return nil
}

func ValidateSubscriptionStateRequirements(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	if old.State == subscription.State {
		return nil
	}

	stateName := PTAFLTypes.SubscriptionStateName(subscription.State)
	state, ok := subscription_states.SubscriptionStateMap[stateName]
	if !ok {
		return fmt.Errorf("incorrect state: %s", stateName)
	}

	err := state.ValidateRequirements(user, subscription, old)
	if err != nil {
		return err
	}

	return nil
}

func FillSubscriptionByState(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	if old.State == subscription.State {
		return nil
	}

	subscription.Approver = user.GetId()
	subscription.ApproveTime = time.Now().Format("2006-01-02T15:04:05Z07:00")

	stateName := PTAFLTypes.SubscriptionStateName(subscription.State)
	state, ok := subscription_states.SubscriptionStateMap[stateName]
	if !ok {
		return fmt.Errorf("incorrect state: %s", stateName)
	}

	err := state.FillSubscription(user, subscription, old)
	if err != nil {
		return err
	}

	return nil
}

func ValidateSubscriptionUpdate(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	subscriptionRole := GetUserRole(user)

	if subscriptionRole == PTAFLTypes.UserRoleGlobalAdmin {
		return nil
	}

	oldStateName := PTAFLTypes.SubscriptionStateName(old.State)
	newStateName := PTAFLTypes.SubscriptionStateName(subscription.State)

	err := ValidateSubscriptionStateIsAllowed(subscriptionRole, oldStateName, newStateName)
	if err != nil {
		return err
	}

	err = ValidateSubscriptionFieldsChangeIsAllowed(subscriptionRole, old, subscription)
	if err != nil {
		return err
	}

	err = ValidateSubscriptionRequiredFieldsIsFilled(subscriptionRole, old, subscription)
	if err != nil {
		return err
	}

	err = ValidateSubscriptionStateRequirements(user, subscription, old)
	if err != nil {
		return err
	}

	return nil
}

func notifyLogSubscriptionUpdated(actor *object.User, current, old *object.Subscription) error {
	if current.User == "" {
		return errors.New("no client detected in subscription")
	}

	if current.State == PTAFLTypes.SubscriptionNew.String() {
		return nil
	}

	// send notification to log email
	err := notify.NotifyLogSubscriptionUpdated(actor, current, old)
	if err != nil {
		return fmt.Errorf("NotifyLogSubscriptionUpdated: %w", err)
	}

	return nil
}

func ProcessSubscriptionUpdatePostActions(ctx *context.Context, user *object.User, subscription, old *object.Subscription) {
	err := notifyLogSubscriptionUpdated(user, subscription, old)
	if err != nil {
		util.LogError(ctx, fmt.Errorf("notifyLogSubscriptionUpdated: %w", err).Error())
	}

	stateChanged := old.State != subscription.State
	if !stateChanged {
		return
	}

	stateName := PTAFLTypes.SubscriptionStateName(subscription.State)
	state, ok := subscription_states.SubscriptionStateMap[stateName]
	if !ok {
		util.LogError(ctx, fmt.Errorf("incorrect state: %s", stateName).Error())
	}

	errs := state.PostAction(user, subscription, old)
	for _, err := range errs {
		util.LogError(ctx, fmt.Errorf("state.PostAction(%s): %w", stateName, err).Error())
	}
}

func GetSubscriptionFilter(user *object.User) builder.Cond {
	userRole := GetUserRole(user)
	if userRole == PTAFLTypes.UserRoleDistributor {
		return builder.Eq{"state": []string{
			PTAFLTypes.SubscriptionAuthorized.String(),
			PTAFLTypes.SubscriptionStarted.String(),
			PTAFLTypes.SubscriptionPreFinished.String(),
			PTAFLTypes.SubscriptionFinished.String(),
		}}.Or(builder.Eq{"state": PTAFLTypes.SubscriptionCancelled.String(), "approver": user.GetId()})
	}

	return nil
}

func GetAvailableTransitions(user *object.User, subscription *object.Subscription) ([]PTAFLTypes.SubscriptionStateName, error) {
	subscriptionRole := GetUserRole(user)

	subscriptionState := PTAFLTypes.SubscriptionStateName(subscription.State)
	state, ok := subscription_states.SubscriptionStateMap[subscriptionState]
	if !ok {
		return nil, fmt.Errorf("incorrect state: %s", subscriptionState)
	}

	roleAvailableTransitions, _ := state.Transitions()[subscriptionRole]
	roleAvailableTransitions = append([]PTAFLTypes.SubscriptionStateName{subscriptionState}, roleAvailableTransitions...)

	return roleAvailableTransitions, nil
}
