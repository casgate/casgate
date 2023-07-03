package pt_af_logic

import (
	"fmt"

	"github.com/beego/beego/context"
	"github.com/casdoor/casdoor/object"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/builder"
)

func GetUserRole(user *object.User) PTAFLTypes.UserRole {
	if user == nil {
		return PTAFLTypes.UserRoleUnknown
	}

	if user.IsGlobalAdmin {
		return PTAFLTypes.UserRoleGlobalAdmin
	}

	if user.IsAdmin {
		return PTAFLTypes.UserRolePartner
	}
	role, _ := object.GetRole(util.GetId(builtInOrgCode, string(PTAFLTypes.UserRoleDistributor)))
	if role != nil {
		userId := user.GetId()
		for _, roleUserId := range role.Users {
			if roleUserId == userId {
				return PTAFLTypes.UserRoleDistributor
			}
		}
	}

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

	if old.Comment != new.Comment {
		oldContains := oldRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameComment)
		newContains := newRoleFieldPermission.Contains(PTAFLTypes.SubscriptionFieldNameComment)
		if !oldContains && !newContains {
			return fmt.Errorf("You are not allowed to change field %s", PTAFLTypes.SubscriptionFieldNameComment)
		}
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

	return nil
}

func ProcessSubscriptionUpdatePostActions(ctx *context.Context, user *object.User, subscription, old *object.Subscription) {
	stateChanged := old.State != subscription.State

	err := NotifySubscriptionUpdated(ctx, user, subscription, old)
	if err != nil {
		util.LogError(ctx, fmt.Errorf("NotifySubscriptionUpdated: %w", err).Error())
	}

	// create tenant at pt af
	if stateChanged && PTAFLTypes.SubscriptionStateName(subscription.State) == PTAFLTypes.SubscriptionStarted {
		err := CreateTenant(ctx, subscription)
		if err != nil {
			util.LogError(ctx, fmt.Errorf("CreateTenant: %w", err).Error())
		}
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
