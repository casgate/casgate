package usecases

import (
	"context"

	"github.com/casdoor/casdoor/object"
)

func (u *UseCases) UpdateUser(ctx context.Context, id string, user *object.User, columns []string, isAdmin bool) (bool, error) {
	userTokens, err := object.GetUserTokens(user)
	if err != nil {
		return false, err
	}

	if len(userTokens) > 0 {
		for _, token := range userTokens {
			token.Permissions = user.Permissions
			token.Roles = user.Roles
		}

		err = object.UpdateTokens(ctx, userTokens, []string{"permissions", "roles"})
		if err != nil {
			return false, err
		}
	}

	affected, err := object.UpdateUser(id, user, columns, isAdmin)
	if err != nil {
		return false, err
	}

	if affected {
		err = object.UpdateUserToOriginalDatabase(user)
		if err != nil {
			return false, err
		}
	}

	return affected, nil
}
