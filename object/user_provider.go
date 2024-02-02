package object

import (
	"context"
)

type UserProvider struct {
	UserObj     *User     `xorm:"-" json:"userObj"`
	ProviderObj *Provider `xorm:"-" json:"providerObj"`

	LastSync         string `xorm:"varchar(100)" json:"lastSync"`
	UserProviderName string `xorm:"varchar(100)" json:"userProviderName"`
	ProviderName     string `xorm:"varchar(100)" json:"providerName"`
	UserId           string `xorm:"varchar(100)" json:"userId"`
	Owner            string `xorm:"varchar(100)" json:"owner"`
}

func GetUserProviders(owner string) ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Where("owner = ? or owner = ?", "admin", owner).Desc("last_sync").Find(&userProviders, &UserProvider{})
	if err != nil {
		return userProviders, err
	}

	return userProviders, nil
}

func GetUserProviderCount(owner, field, value string) (int64, error) {
	session := GetSession("", -1, -1, field, value, "last_sync", "desc")
	return session.Where("owner = ? or owner = ? ", "admin", owner).Count(&UserProvider{})
}

func GetPaginationUserProviders(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*UserProvider, error) {
	var userProviders []*UserProvider

	if sortField == "" {
		sortField = "last_sync"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	session := GetSession("", offset, limit, field, value, sortField, sortOrder)
	err := session.Where("owner = ? or owner = ? ", "admin", owner).Find(&userProviders)
	if err != nil {
		return userProviders, err
	}

	return userProviders, nil
}

func GetUserProvider(owner string, providerName string, userProviderName string) (*UserProvider, error) {
	userProvider := UserProvider{
		Owner:            owner,
		UserProviderName: userProviderName,
		ProviderName:     providerName,
	}

	existed, err := ormer.Engine.Get(&userProvider)
	if err != nil {
		return nil, err
	}

	if existed {
		return &userProvider, nil
	} else {
		return nil, nil
	}
}

func AddUserProvider(ctx context.Context, userProvider *UserProvider) (bool, error) {
	var affected int64
	err := trm.WithTx(ctx, func(ctx context.Context) error {
		existedUserProvider, err := repo.GetUserProvider(ctx, userProvider.Owner, userProvider.ProviderName, userProvider.UserProviderName, false)
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
