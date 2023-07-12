package types

import (
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/i18n"
)

type UserRole string

const (
	UserRoleUnknown     UserRole = "unknown"
	UserRoleGlobalAdmin UserRole = "admin"
	UserRolePartner     UserRole = "partner"
	UserRoleDistributor UserRole = "distributor"

	ptlmLanguage = "lm"
)

type SubscriptionStateName string

func (s SubscriptionStateName) String() string {
	return string(s)
}

const (
	SubscriptionNew           SubscriptionStateName = "New"
	SubscriptionPending       SubscriptionStateName = "Pending"
	SubscriptionPreAuthorized SubscriptionStateName = "PreAuthorized"
	SubscriptionIntoCommerce  SubscriptionStateName = "IntoCommerce"
	SubscriptionUnauthorized  SubscriptionStateName = "Unauthorized"
	SubscriptionAuthorized    SubscriptionStateName = "Authorized"
	SubscriptionStarted       SubscriptionStateName = "Started"
	SubscriptionPreFinished   SubscriptionStateName = "PreFinished"
	SubscriptionFinished      SubscriptionStateName = "Finished"
	SubscriptionCancelled     SubscriptionStateName = "Cancelled"
)

type SubscriptionStateNames []SubscriptionStateName

func (s SubscriptionStateNames) Contains(name SubscriptionStateName) bool {
	for _, value := range s {
		if value == name {
			return true
		}
	}

	return false
}

func (s SubscriptionStateNames) String() string {
	var strs []string
	for _, state := range s {
		strs = append(strs, state.String())
	}
	return strings.Join(strs, ", ")
}

type SubscriptionFieldName string

const (
	SubscriptionFieldNameName        SubscriptionFieldName = "Name"
	SubscriptionFieldNameDisplayName SubscriptionFieldName = "Display Name"
	SubscriptionFieldNameStartDate   SubscriptionFieldName = "Start Date"
	SubscriptionFieldNameEndDate     SubscriptionFieldName = "End Date"
	SubscriptionFieldNameSubUser     SubscriptionFieldName = "Sub user"
	SubscriptionFieldNameSubPlan     SubscriptionFieldName = "Sub plan"
	SubscriptionFieldNameDiscount    SubscriptionFieldName = "Discount"
	SubscriptionFieldNameDescription SubscriptionFieldName = "Description"
	SubscriptionFieldNameComment     SubscriptionFieldName = "Comment"
)

type SubscriptionFieldNames []SubscriptionFieldName

func (s SubscriptionFieldNames) Contains(name SubscriptionFieldName) bool {
	if s == nil {
		return false
	}

	for _, value := range s {
		if value == name {
			return true
		}
	}

	return false
}

type SubscriptionFieldPermissions map[UserRole]SubscriptionFieldNames
type SubscriptionTransitions map[UserRole]SubscriptionStateNames
type SubscriptionState struct {
	FieldPermissions SubscriptionFieldPermissions
	Transitions      SubscriptionTransitions
}

var SubscriptionStateMap = map[SubscriptionStateName]SubscriptionState{
	SubscriptionNew: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRolePartner: {
				SubscriptionFieldNameName,
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameSubUser,
				SubscriptionFieldNameSubPlan,
				SubscriptionFieldNameDiscount,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: SubscriptionTransitions{
			UserRolePartner: SubscriptionStateNames{SubscriptionPending},
		},
	},
	SubscriptionPending: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRolePartner: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameSubPlan,
				SubscriptionFieldNameDiscount,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: nil,
	},
	SubscriptionPreAuthorized: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRolePartner: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameDescription,
				SubscriptionFieldNameDiscount,
			},
		},
		Transitions: SubscriptionTransitions{
			UserRolePartner: SubscriptionStateNames{SubscriptionIntoCommerce, SubscriptionCancelled},
		},
	},
	SubscriptionIntoCommerce: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRolePartner: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: nil,
	},
	SubscriptionUnauthorized: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRolePartner: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameSubPlan,
				SubscriptionFieldNameDiscount,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: SubscriptionTransitions{
			UserRolePartner: SubscriptionStateNames{SubscriptionPending, SubscriptionCancelled},
		},
	},
	SubscriptionAuthorized: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRoleDistributor: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameStartDate,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: SubscriptionTransitions{
			UserRoleDistributor: SubscriptionStateNames{SubscriptionStarted, SubscriptionCancelled},
		},
	},
	SubscriptionStarted: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRolePartner: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: SubscriptionTransitions{
			UserRolePartner: SubscriptionStateNames{SubscriptionPreFinished},
		},
	},
	SubscriptionPreFinished: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRoleDistributor: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameEndDate,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: SubscriptionTransitions{
			UserRoleDistributor: SubscriptionStateNames{SubscriptionFinished},
		},
	},
	SubscriptionFinished: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRolePartner: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: nil,
	},
	SubscriptionCancelled: {
		FieldPermissions: SubscriptionFieldPermissions{
			UserRolePartner: {
				SubscriptionFieldNameDisplayName,
				SubscriptionFieldNameDescription,
			},
		},
		Transitions: nil,
	},
}

func NewStateChangeForbiddenError(availableStatusNames []SubscriptionStateName) error {
	if len(availableStatusNames) == 0 {
		return fmt.Errorf("Из текущего статуса вам не доступны переходы в другие статусы")
	}
	var statuses string
	for _, availableStatusName := range availableStatusNames {
		translatedAvailableStatusName := i18n.Translate(ptlmLanguage, fmt.Sprintf("subscription:%s", availableStatusName.String()))
		if statuses == "" {
			statuses = translatedAvailableStatusName
			continue
		}
		statuses = fmt.Sprintf("%s, %s", statuses, translatedAvailableStatusName)
	}
	return fmt.Errorf("Вы можете перевести подписку только в доступные статусы: %s", statuses)
}
