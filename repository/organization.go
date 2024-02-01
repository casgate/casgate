package repository

import (
	"context"

	"github.com/casdoor/casdoor/object"
)

func (r *Repo) GetOrganization(ctx context.Context, owner, name string, forUpdate bool) (*object.Organization, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	query := r.trm.GetEngine(ctx).Where("owner = ? and name = ?", owner, name)
	if forUpdate {
		query = query.ForUpdate()
	}

	organization := object.Organization{Owner: owner, Name: name}
	existed, err := query.Get(&organization)
	if err != nil {
		return nil, err
	}

	if existed {
		return &organization, nil
	}

	return nil, nil
}

func (r *Repo) UpdateOrganization(ctx context.Context, owner, name string, organization *object.Organization) (int64, error) {
	return r.updateEntity(ctx, owner, name, organization)
}
