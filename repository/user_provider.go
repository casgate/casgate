package repository

import (
	"context"

	"github.com/casdoor/casdoor/object"
)

func (r *Repo) GetUserProvider(ctx context.Context, owner, providerName, usernameFromIdp string, forUpdate bool) (*object.UserProvider, error) {
	if owner == "" || providerName == "" || usernameFromIdp == "" {
		return nil, nil
	}

	query := r.trm.GetEngine(ctx).Where("owner = ? and provider_name = ? and username_from_idp = ?", owner, providerName, usernameFromIdp)
	if forUpdate {
		query = query.ForUpdate()
	}

	userProvider := object.UserProvider{Owner: owner, ProviderName: providerName, UsernameFromIdp: usernameFromIdp}
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

func (r *Repo) UpdateUserProvider(ctx context.Context, userProvider *object.UserProvider) error {
	return r.UpdateEntitiesFieldValue(ctx, "user_provider", "last_sign_in_time", userProvider.LastSignInTime,
		map[string]interface{}{
			"owner":             userProvider.Owner,
			"provider_name":     userProvider.ProviderName,
			"username_from_idp": userProvider.UsernameFromIdp,
		})
}
