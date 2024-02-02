package object

import "github.com/casdoor/casdoor/util"

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
	session := GetSession("", -1, -1, field, value, "", "")
	return session.Where("owner = ? or owner = ? ", "admin", owner).Count(&UserProvider{})
}

func GetPaginationUserProviders(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*UserProvider, error) {
	var userProviders []*UserProvider
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

func AddUserProvider(userProvider *UserProvider) (bool, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Desc("last_sync").Find(&userProviders, &UserProvider{
		Owner:        userProvider.Owner,
		ProviderName: userProvider.ProviderName,
		UserId:       userProvider.UserId,
	})
	if err != nil {
		return false, err
	}

	var affected int64
	if len(userProviders) == 0 {
		userProvider.LastSync = util.GetCurrentTime()
		affected, err = ormer.Engine.Insert(userProvider)
	} else {
		var emailLinkingEnabled bool

		applications, err := GetOrganizationApplications("", userProvider.Owner)
		if err != nil {
			return false, err
		}
		for i := range applications {
			for _, provider := range applications[i].Providers {
				if provider.Name == userProvider.ProviderName {
					emailLinkingEnabled = applications[i].EnableLinkWithEmail
				}
			}
		}

		if emailLinkingEnabled {
			userProvider.LastSync = util.GetCurrentTime()
			affected, err = ormer.Engine.Insert(userProvider)
		}
	}

	if err != nil {
		return false, err
	}

	return affected != 0, nil
}
