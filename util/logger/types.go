package logger

type ObjectType string

const (
	ObjectTypeUser        ObjectType = "user"
	ObjectTypeRole        ObjectType = "role"
	ObjectTypeProvider    ObjectType = "provider"
	ObjectTypeApplication ObjectType = "application"
)

type OperationResult string

const (
	OperationResultSuccess OperationResult = "success"
	OperationResultFailure OperationResult = "failure"
)

type OperationName string

const (
	OperationNameUserUpdate  OperationName = "user-update"
	OperationNameAddUser     OperationName = "add-user"
	OperationNameSetPassword OperationName = "set-password"
	OperationNameUserDelete  OperationName = "user-delete"

	OperationNameRoleUpdate OperationName = "role-update"

	OperationNameProviderUpdate OperationName = "provider-update"

	OperationNameApplicationUpdate OperationName = "application-update"
)

type LogMsgDetailed map[string]interface{}
