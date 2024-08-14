package object

import (
	"context"
)

type Repository interface {
	GetUsers(ctx context.Context, owner string) ([]*User, error)
	UpdateUserPasswordChangeTime(ctx context.Context, user *User) error
	GetUsersWithoutRequiredPasswordChange(ctx context.Context, owner string) ([]*User, error)
	ResetUsersPasswordChangeTime(ctx context.Context, owner string) error

	GetOrganization(ctx context.Context, owner, name string, forUpdate bool) (*Organization, error)
	UpdateOrganization(ctx context.Context, owner, name string, organization *Organization) (int64, error)

	GetDomains(ctx context.Context, owner string) ([]*Domain, error)
	UpdateDomain(ctx context.Context, owner, name string, domain *Domain) (int64, error)

	GetRoles(ctx context.Context, owner string) ([]*Role, error)
	UpdateRole(ctx context.Context, owner, name string, role *Role) (int64, error)

	GetGroups(ctx context.Context, owner string) ([]*Group, error)

	GetPermissionsByModelAdapter(ctx context.Context, owner, model, adapter string) ([]*Permission, error)
	GetPermissions(ctx context.Context, owner string) ([]*Permission, error)
	UpdatePermission(ctx context.Context, owner, name string, permission *Permission) (int64, error)

	GetModel(ctx context.Context, owner string, name string, forUpdate bool) (*Model, error)

	GetUserIdProvider(ctx context.Context, userIdProvider *UserIdProvider) (*UserIdProvider, error)
	InsertUserIdProvider(ctx context.Context, userIdProvider *UserIdProvider) (int64, error)
	UpdateUserIdProvider(ctx context.Context, userIdProvider *UserIdProvider, findConditions map[string]interface{}) error

	UpdateEntitiesFieldValue(ctx context.Context, entityName string, fieldName, newValue string, findConditions map[string]interface{}) error
}

func InitRepo(txmanager TransactionManager, repository Repository) {
	trm = txmanager
	repo = repository
}

type TransactionManager interface {
	WithTx(parentCtx context.Context, f func(ctx context.Context) error) error
}

var (
	repo Repository         = nil
	trm  TransactionManager = nil
)
