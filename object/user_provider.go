package object

import (
	"context"
)

type UserProvider struct {
	ProviderDisplayName string `xorm:"-" json:"providerDisplayName"`

	CreatedTime     string `xorm:"varchar(100)" json:"createdTime"`
	LastSignInTime  string `xorm:"varchar(100)" json:"lastSignInTime"`
	UsernameFromIdp string `xorm:"varchar(100)" json:"usernameFromIdp"`
	ProviderName    string `xorm:"varchar(100)" json:"providerName"`
	UserId          string `xorm:"varchar(100)" json:"userId"`
	Owner           string `xorm:"varchar(100)" json:"owner"`
}

func GetGlobalUserProviders() ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Asc("last_sign_in_time").Find(&userProviders, &UserProvider{})
	if err != nil {
		return userProviders, err
	}

	for _, userProvider := range userProviders {
		err := fillProviderDisplayName(userProvider)
		if err != nil {
			return nil, err
		}
	}

	return userProviders, nil
}

func GetUserProviders(owner string) ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Where("owner = ? or owner = ?", "admin", owner).Asc("last_sign_in_time").Find(&userProviders, &UserProvider{})
	if err != nil {
		return userProviders, err
	}

	for _, userProvider := range userProviders {
		err := fillProviderDisplayName(userProvider)
		if err != nil {
			return nil, err
		}
	}

	return userProviders, nil
}

func AddUserProvider(ctx context.Context, userProvider *UserProvider) (bool, error) {
	var affected int64
	err := trm.WithTx(ctx, func(ctx context.Context) error {
		existedUserProvider, err := repo.GetUserProvider(ctx, userProvider.Owner, userProvider.ProviderName, userProvider.UsernameFromIdp, false)
		if err != nil {
			return err
		}
		if existedUserProvider != nil {
			return nil
		}

		affected, err = repo.InsertUserProvider(ctx, userProvider)
		if err != nil {
			return err
		}
		return nil
	})

	return affected != 0, err
}

func UpdateUserProvider(ctx context.Context, userProvider *UserProvider) error {
	err := trm.WithTx(ctx, func(ctx context.Context) error {
		err := repo.UpdateUserProvider(ctx, userProvider)
		if err != nil {
			return err
		}
		return nil
	})

	return err
}

func fillProviderDisplayName(userProvider *UserProvider) error {
	provider, err := getProvider(userProvider.Owner, userProvider.ProviderName)
	if err != nil {
		return err
	}
	userProvider.ProviderDisplayName = provider.DisplayName
	return nil
}
