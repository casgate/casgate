package repository

import (
	"context"

	"github.com/casdoor/casdoor/object"
)

func (r *Repo) GetExternalUser(ctx context.Context, externalUser *object.ExternalUser) (*object.ExternalUser, error) {
	if externalUser.Owner == "" || !object.CheckUserIdProviderOrigin(*externalUser) || externalUser.UsernameFromIdp == "" {
		return nil, nil
	}

	query := r.trm.GetEngine(ctx)

	existed, err := query.Get(externalUser)
	if err != nil {
		return nil, err
	}

	if existed {
		return externalUser, nil
	}

	return nil, nil
}

func (r *Repo) InsertExternalUser(ctx context.Context, externalUser *object.ExternalUser) (int64, error) {
	return r.insertEntity(ctx, externalUser)
}

func (r *Repo) UpdateExternalUser(ctx context.Context, externalUser *object.ExternalUser, findConditions map[string]interface{}) error {
	return r.UpdateEntitiesFieldValue(ctx, "user_id_provider", "last_sign_in_time", externalUser.LastSignInTime, findConditions)
}
