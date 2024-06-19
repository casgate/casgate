package usecases

import (
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/builder"
)

func (u *UseCases) UpdateRole(id string, role *object.Role) (bool, error) {

	oldRole, err := object.GetRole(id)
	if err != nil {
		return false, err
	}

	deletedUserIds := Difference(oldRole.Users, role.Users)
	if len(deletedUserIds) > 0 {
		deletedUserUuids, err := getUsersUUIDs(deletedUserIds)
		if err != nil {
			return false, err
		}

		tokensToDelete, err := object.GetUsersTokens(deletedUserUuids)
		if err != nil {
			return false, err
		}

		tokenIdsToDelete := extractTokenIds(tokensToDelete)
		role.Users = Difference(role.Users, tokenIdsToDelete)
	}

	addedUserIds := Difference(role.Users, oldRole.Users)
	if len(addedUserIds) > 0 {
		newUserIds, err := getUsersUUIDs(addedUserIds)
		if err != nil {
			return false, err
		}

		newTokens, err := object.GetUsersTokens(newUserIds)
		if err != nil {
			return false, err
		}

		for _, token := range newTokens {
			role.Users = append(role.Users, token.GetId())
		}
	}

	return object.UpdateRole(id, role)
}

func Difference(arr1, arr2 []string) []string {
	set := make(map[string]struct{})
	for _, str := range arr2 {
		set[str] = struct{}{}
	}

	var result []string
	for _, str := range arr1 {
		if _, found := set[str]; !found {
			result = append(result, str)
		}
	}

	return result
}

func getUsersUUIDs(userIds []string) ([]string, error) {
	conditions := make([]builder.Cond, len(userIds))
	for i, user := range userIds {
		if user == "" {
			continue
		}
		owner, name := util.GetOwnerAndNameFromId(user)
		conditions[i] = builder.And(builder.Eq{"owner": owner}, builder.Eq{"name": name})
	}

	if len(conditions) == 0 {
		return nil, nil
	}

	cond := builder.Or(conditions...)
	users, err := object.GetUsersWithFilter("", cond)
	if err != nil {
		return nil, err
	}

	userUUIDs := make([]string, len(users))
	for i, user := range users {
		userUUIDs[i] = user.Id
	}

	return userUUIDs, nil
}

func extractTokenIds(tokens []object.User) []string {
	tokenIds := make([]string, len(tokens))
	for i, token := range tokens {
		tokenIds[i] = token.GetId()
	}
	return tokenIds
}
