package pt_af_logic

import (
	"fmt"

	"github.com/beego/beego/context"
	"github.com/casdoor/casdoor/object"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
	"github.com/casdoor/casdoor/util"
)

func getUserRole(user *object.User) PTAFLTypes.UserRole {
	if user.IsGlobalAdmin {
		return PTAFLTypes.UserRoleGlobalAdmin
	}

	if user.IsAdmin {
		return PTAFLTypes.UserRolePartner
	}

	//todo: add check for PTAFLTypes.UserRoleDistributor

	return PTAFLTypes.UserRoleUnknown

}

// ValidateSubscriptionStateIsAllowed checks if user has permission to assign a new subscription state
func ValidateSubscriptionStateIsAllowed(subscriptionRole PTAFLTypes.UserRole, oldStateName, nextStateName PTAFLTypes.SubscriptionStateName) error {
	if oldStateName == nextStateName {
		return nil
	}

	oldState, ok := PTAFLTypes.SubscriptionStateMap[oldStateName]
	if !ok {
		return fmt.Errorf("incorrect old state: %s", oldStateName)
	}

	roleAvailableTransitions, ok := oldState.Transitions[subscriptionRole]
	if !ok {
		return PTAFLTypes.NewStateChangeForbiddenError(nextStateName)
	}

	if !roleAvailableTransitions.Contains(nextStateName) {
		return PTAFLTypes.NewStateChangeForbiddenError(nextStateName)
	}

	return nil
}

// ValidateSubscriptionFieldsChangeIsAllowed checks if user has permission to change fields
func ValidateSubscriptionFieldsChangeIsAllowed(
	userRole PTAFLTypes.UserRole,
	old, new *object.Subscription,
) error {
	oldState, ok := PTAFLTypes.SubscriptionStateMap[PTAFLTypes.SubscriptionStateName(old.State)]
	if !ok {
		return fmt.Errorf("incorrect state: %s", new.State)
	}

	newState, ok := PTAFLTypes.SubscriptionStateMap[PTAFLTypes.SubscriptionStateName(new.State)]
	if !ok {
		return fmt.Errorf("incorrect state: %s", new.State)
	}

	oldRoleFieldPermission := oldState.FieldPermissions[userRole]
	newRoleFieldPermission := newState.FieldPermissions[userRole]

	if old.Name != new.Name {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameName)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameName)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameName)
		}
	}

	if old.DisplayName != new.DisplayName {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDisplayName)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDisplayName)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameDisplayName)
		}
	}

	if !old.StartDate.Equal(new.StartDate) {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameStartDate)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameStartDate)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameStartDate)
		}
	}

	if !old.EndDate.Equal(new.EndDate) {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameEndDate)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameEndDate)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameEndDate)
		}
	}

	if old.User != new.User {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameSubUser)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameSubUser)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameSubUser)
		}
	}

	if old.Plan != new.Plan {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameSubPlan)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameSubPlan)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameSubPlan)
		}
	}

	if old.Discount != new.Discount {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDiscount)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDiscount)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameDiscount)
		}
	}

	if old.Description != new.Description {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDescription)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameDescription)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameDescription)
		}
	}

	return nil
}

func ValidateSubscriptionUpdate(user *object.User, subscription *object.Subscription, old *object.Subscription) error {
	subscriptionRole := getUserRole(user)

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

	return nil
}

func ProcessSubscriptionUpdatePostActions(ctx *context.Context, user *object.User, subscription *object.Subscription, oldState string) {
	stateChanged := oldState != subscription.State
	// send emails if response handler above not panics
	if stateChanged {
		err := NotifySubscriptionMembers(user, subscription, oldState)
		if err != nil {
			util.LogError(ctx, fmt.Errorf("NotifySubscriptionMembers: %w", err).Error())
		}
	}

	// create tenant at pt af
	if stateChanged && PTAFLTypes.SubscriptionStateName(subscription.State) == PTAFLTypes.SubscriptionStarted {
		err := CreateTenant(ctx, subscription)
		if err != nil {
			util.LogError(ctx, fmt.Errorf("CreateTenant: %w", err).Error())
		}
	}
}
