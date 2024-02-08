package repository

import (
	"context"

	"github.com/casdoor/casdoor/object"
)

func (r *Repo) GetUserIdProvider(ctx context.Context, owner, providerName, usernameFromIdp string) (*object.UserIdProvider, error) {
	if owner == "" || providerName == "" || usernameFromIdp == "" {
		return nil, nil
	}

	query := r.trm.GetEngine(ctx).Where("owner = ? and provider_name = ? and username_from_idp = ?", owner, providerName, usernameFromIdp)

	userIdProvider := object.UserIdProvider{Owner: owner, ProviderName: providerName, UsernameFromIdp: usernameFromIdp}
	existed, err := query.Get(&userIdProvider)
	if err != nil {
		return nil, err
	}

	if existed {
		return &userIdProvider, nil
	}

	return nil, nil
}

func (r *Repo) InsertUserIdProvider(ctx context.Context, userIdProvider *object.UserIdProvider) (int64, error) {
	return r.insertEntity(ctx, userIdProvider)
}

func (r *Repo) UpdateUserIdProvider(ctx context.Context, userIdProvider *object.UserIdProvider) error {
	return r.UpdateEntitiesFieldValue(ctx, "user_id_provider", "last_sign_in_time", userIdProvider.LastSignInTime,
		map[string]interface{}{
			"owner":             userIdProvider.Owner,
			"provider_name":     userIdProvider.ProviderName,
			"username_from_idp": userIdProvider.UsernameFromIdp,
		})
}
