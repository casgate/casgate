package object

import (
	"context"
)

type Repository interface {
	GetUsers(ctx context.Context, owner string) ([]*User, error)

	GetDomains(ctx context.Context, owner string) ([]*Domain, error)

	GetRoles(ctx context.Context, owner string) ([]*Role, error)

	GetGroups(ctx context.Context, owner string) ([]*Group, error)

	GetPermissionsByModelAdapter(ctx context.Context, owner, model, adapter string) ([]*Permission, error)

	GetModel(ctx context.Context, owner string, name string, forUpdate bool) (*Model, error)
}
