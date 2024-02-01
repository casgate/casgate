package object

import "github.com/casdoor/casdoor/util"

type UserProvider struct {
	UserObj     *User     `xorm:"-" json:"userObj"`
	ProviderObj *Provider `xorm:"-" json:"providerObj"`

	LastSync      string `xorm:"varchar(100)" json:"lastSync"`
	UserName      string `xorm:"varchar(100)" json:"userName"`
	ProviderName  string `xorm:"varchar(100)" json:"providerName"`
	ProviderLogin string `xorm:"varchar(100)" json:"providerLogin"`
	Owner         string `xorm:"varchar(100)" json:"owner"`
}

func GetAllUserProviders() ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Desc("last_sync").Find(&userProviders, &UserProvider{})
	if err != nil {
		return userProviders, err
	}

	return userProviders, nil
}

func GetUserProvidersByUserName(userName string) ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Desc("last_sync").Find(&userProviders, &UserProvider{UserName: userName})
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

func GetUserProvidersByOwner(owner string) ([]*UserProvider, error) {
	var userProviders []*UserProvider

	err := ormer.Engine.Desc("last_sync").Find(&userProviders, &UserProvider{Owner: owner})
	if err != nil {
		return userProviders, err
	}

	return userProviders, nil
}

func GetUserProvider(owner string, providerName string, userName string) (*UserProvider, error) {
	userProvider := UserProvider{
		Owner:        owner,
		UserName:     userName,
		ProviderName: providerName,
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
		Owner:         userProvider.Owner,
		ProviderName:  userProvider.ProviderName,
		ProviderLogin: userProvider.ProviderLogin,
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
