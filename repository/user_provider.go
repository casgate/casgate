package repository

import (
	"context"

	"github.com/casdoor/casdoor/object"
)

func (r *Repo) GetUserProvider(ctx context.Context, owner, providerName, userProviderName string, forUpdate bool) (*object.UserProvider, error) {
	if owner == "" || providerName == "" || userProviderName == "" {
		return nil, nil
	}

	query := r.trm.GetEngine(ctx).Where("owner = ? and provider_name = ? and user_provider_name = ?", owner, providerName, userProviderName)
	if forUpdate {
		query = query.ForUpdate()
	}

	userProvider := object.UserProvider{Owner: owner, ProviderName: providerName, UserProviderName: userProviderName}
	existed, err := query.Get(&userProvider)
	if err != nil {
		return nil, err
	}

	if existed {
		return &userProvider, nil
	}

	return nil, nil
}

func (r *Repo) InsertUserProvider(ctx context.Context, userProvider *object.UserProvider) (int64, error) {
	return r.insertEntity(ctx, userProvider)
}
