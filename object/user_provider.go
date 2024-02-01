package object

import "github.com/casdoor/casdoor/util"

type UserProvider struct {
	UserObj     *User     `xorm:"-" json:"userObj"`
	ProviderObj *Provider `xorm:"-" json:"providerObj"`

	LastSync     string `xorm:"varchar(100)" json:"lastSync"`
	UserId       string `xorm:"varchar(100)" json:"userId"`
	ProviderName string `xorm:"varchar(100)" json:"providerName"`
	Owner        string `xorm:"varchar(100)" json:"owner"`
}

func GetAllUserProviders() ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Desc("last_sync").Find(&userProviders, &UserProvider{})
	if err != nil {
		return userProviders, err
	}

	return userProviders, nil
}

func GetUserProvidersByUserId(userId string) ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Desc("last_sync").Find(&userProviders, &UserProvider{UserId: userId})
	if err != nil {
		return userProviders, err
	}

	return userProviders, nil
}

func GetUserProvidersByProviderName(name string) ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Desc("last_sync").Find(&userProviders, &UserProvider{ProviderName: name})
	if err != nil {
		return userProviders, err
	}

	return userProviders, nil
}

func AddUserProvider(userProvider *UserProvider) (bool, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Desc("last_sync").Find(&userProviders, &UserProvider{UserId: userProvider.UserId})
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
