package types

import (
	"fmt"
	"strings"

	"github.com/casdoor/casdoor/i18n"
)

type SubscriptionStateName string

func (s SubscriptionStateName) String() string {
	return string(s)
}

const (
	SubscriptionNew           SubscriptionStateName = "New"           // Новая
	SubscriptionPilot         SubscriptionStateName = "Pilot"         // Пилот
	SubscriptionPilotExpired  SubscriptionStateName = "PilotExpired"  // Истек срок пилота
	SubscriptionPending       SubscriptionStateName = "Pending"       // На рассмотрении
	SubscriptionPreAuthorized SubscriptionStateName = "PreAuthorized" // Утверждена
	SubscriptionIntoCommerce  SubscriptionStateName = "IntoCommerce"  // В коммерцию
	SubscriptionUnauthorized  SubscriptionStateName = "Unauthorized"  // Отклонена
	SubscriptionAuthorized    SubscriptionStateName = "Authorized"    // Авторизована
	SubscriptionStarted       SubscriptionStateName = "Started"       // Действующая
	SubscriptionPreFinished   SubscriptionStateName = "PreFinished"   // Завершается
	SubscriptionFinished      SubscriptionStateName = "Finished"      // Завершена
	SubscriptionCancelled     SubscriptionStateName = "Cancelled"     // Отменена
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
	SubscriptionFieldNameName            SubscriptionFieldName = "Name"
	SubscriptionFieldNameDisplayName     SubscriptionFieldName = "Display Name"
	SubscriptionFieldNameStartDate       SubscriptionFieldName = "Start Date"
	SubscriptionFieldNameEndDate         SubscriptionFieldName = "End Date"
	SubscriptionFieldNameSubUser         SubscriptionFieldName = "User"
	SubscriptionFieldNameSubPlan         SubscriptionFieldName = "Plan"
	SubscriptionFieldNameDiscount        SubscriptionFieldName = "Discount"
	SubscriptionFieldNameDescription     SubscriptionFieldName = "Description"
	SubscriptionFieldNameComment         SubscriptionFieldName = "Comment"
	SubscriptionFieldNameWasPilot        SubscriptionFieldName = "WasPilot"
	SubscriptionFieldNamePilotExpiryDate SubscriptionFieldName = "PilotExpiryDate"
	SubscriptionFieldNameApprover        SubscriptionFieldName = "Approver"
	SubscriptionFieldNameApproveTime     SubscriptionFieldName = "Approve Time"
)

func (s SubscriptionFieldName) String() string {
	return string(s)
}

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

func NewStateChangeForbiddenError(availableStatusNames []SubscriptionStateName) error {
	if len(availableStatusNames) == 0 {
		return fmt.Errorf("Из текущего статуса вам не доступны переходы в другие статусы")
	}
	var statuses string
	for _, availableStatusName := range availableStatusNames {
		translatedAvailableStatusName := i18n.Translate(PtlmLanguage, fmt.Sprintf("subscription:%s", availableStatusName.String()))
		if statuses == "" {
			statuses = translatedAvailableStatusName
			continue
		}
		statuses = fmt.Sprintf("%s, %s", statuses, translatedAvailableStatusName)
	}
	return fmt.Errorf("Вы можете перевести подписку только в доступные статусы: %s", statuses)
}

func NewRequiredFieldNotFilledError(fieldName SubscriptionFieldName) error {
	return fmt.Errorf("Поле %s должно быть заполнено", i18n.Translate(PtlmLanguage, fmt.Sprintf("subscription:%s", fieldName.String())))
}

func NewForbiddenFieldChangeError(fieldName SubscriptionFieldName) error {
	return fmt.Errorf("Вы не можете менять поле %s в текущем статусе", i18n.Translate(PtlmLanguage, fmt.Sprintf("subscription:%s", fieldName.String())))
}
