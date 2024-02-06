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

	GetUserProvider(ctx context.Context, owner, providerName, usernameFromIdp string, forUpdate bool) (*UserProvider, error)
	InsertUserProvider(ctx context.Context, organization *UserProvider) (int64, error)
	UpdateUserProvider(ctx context.Context, userProvider *UserProvider) error

	UpdateEntitiesFieldValue(ctx context.Context, entityName string, fieldName, newValue string, findConditions map[string]interface{}) error
}
