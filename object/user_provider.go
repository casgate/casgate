package object

import (
	"context"
)

type UserIdProvider struct {
	ProviderDisplayName string `xorm:"-" json:"providerDisplayName"`

	CreatedTime     string `xorm:"varchar(100)" json:"createdTime"`
	LastSignInTime  string `xorm:"varchar(100)" json:"lastSignInTime"`
	UsernameFromIdp string `xorm:"varchar(100)" json:"usernameFromIdp"`
	ProviderName    string `xorm:"varchar(100)" json:"providerName"`
	UserId          string `xorm:"varchar(100)" json:"userId"`
	Owner           string `xorm:"varchar(100)" json:"owner"`
}

func GetGlobalUserIdProviders() ([]*UserIdProvider, error) {
	var userIdProviders []*UserIdProvider

	err := ormer.Engine.Asc("last_sign_in_time").Find(&userIdProviders, &UserIdProvider{})
	if err != nil {
		return userIdProviders, err
	}

	for _, userIdProvider := range userIdProviders {
		err := fillProviderDisplayName(userIdProvider)
		if err != nil {
			return userIdProviders, err
		}
	}

	return userIdProviders, err
}

func GetUserIdProviders(owner string) ([]*UserIdProvider, error) {
	var userIdProviders []*UserIdProvider

	err := ormer.Engine.Where("owner = ? or owner = ?", "admin", owner).Asc("last_sign_in_time").Find(&userIdProviders, &UserIdProvider{})
	if err != nil {
		return userIdProviders, err
	}

	for _, userIdProvider := range userIdProviders {
		err := fillProviderDisplayName(userIdProvider)
		if err != nil {
			return userIdProviders, err
		}
	}

	return userIdProviders, err
}

func AddUserIdProvider(ctx context.Context, userIdProvider *UserIdProvider) (bool, error) {
	var affected int64
	err := trm.WithTx(ctx, func(ctx context.Context) error {
		existedUserIdProvider, err := repo.GetUserIdProvider(ctx, userIdProvider.Owner, userIdProvider.ProviderName, userIdProvider.UsernameFromIdp)
		if err != nil {
			return err
		}
		if existedUserIdProvider == nil {
			affected, err = repo.InsertUserIdProvider(ctx, userIdProvider)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return affected != 0, err
}

func UpdateUserIdProvider(ctx context.Context, userIdProvider *UserIdProvider) error {
	return trm.WithTx(ctx, func(ctx context.Context) error {
		return repo.UpdateUserIdProvider(ctx, userIdProvider)
	})
}

func fillProviderDisplayName(userIdProvider *UserIdProvider) error {
	provider, err := getProvider(userIdProvider.Owner, userIdProvider.ProviderName)
	if err != nil {
		return err
	}
	userIdProvider.ProviderDisplayName = provider.DisplayName
	return nil
}
