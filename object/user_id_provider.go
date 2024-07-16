package object

import (
	"context"
	"github.com/casdoor/casdoor/orm"
)

type UserIdProvider struct {
	ProviderDisplayName string `xorm:"-" json:"providerDisplayName"`
	LdapServerName      string `xorm:"-" json:"ldapServerName"`

	CreatedTime     string `xorm:"varchar(100)" json:"createdTime"`
	LastSignInTime  string `xorm:"varchar(100)" json:"lastSignInTime"`
	UsernameFromIdp string `xorm:"varchar(100)" json:"usernameFromIdp"`
	ProviderName    string `xorm:"varchar(100)" json:"providerName"`
	LdapId          string `xorm:"varchar(100)" json:"ldapId"`
	UserId          string `xorm:"varchar(100)" json:"userId"`
	Owner           string `xorm:"varchar(100)" json:"owner"`
}

func GetGlobalUserIdProviders() ([]*UserIdProvider, error) {
	var userIdProviders []*UserIdProvider
	var providers []*Provider
	var ldaps []*Ldap

	err := orm.AppOrmer.Engine.Asc("last_sign_in_time").Find(&userIdProviders, &UserIdProvider{})
	if err != nil {
		return userIdProviders, err
	}

	err = orm.AppOrmer.Engine.Find(&providers, &Provider{})
	if err != nil {
		return userIdProviders, err
	}

	err = orm.AppOrmer.Engine.Find(&ldaps, &Ldap{})
	if err != nil {
		return userIdProviders, err
	}

	for i := range userIdProviders {
		for _, provider := range providers {
			if userIdProviders[i].ProviderName == provider.Name {
				userIdProviders[i].ProviderDisplayName = provider.DisplayName
			}
		}
		for _, ldap := range ldaps {
			if userIdProviders[i].LdapId == ldap.Id {
				userIdProviders[i].LdapServerName = ldap.ServerName
			}
		}
	}

	return userIdProviders, err
}

func GetUserIdProviders(owner string) ([]*UserIdProvider, error) {
	var userIdProviders []*UserIdProvider
	var providers []*Provider
	var ldaps []*Ldap

	err := orm.AppOrmer.Engine.Where("owner = ? or owner = ?", "admin", owner).Asc("last_sign_in_time").Find(&userIdProviders, &UserIdProvider{})
	if err != nil {
		return userIdProviders, err
	}

	err = orm.AppOrmer.Engine.Find(&providers, &Provider{})
	if err != nil {
		return userIdProviders, err
	}

	err = orm.AppOrmer.Engine.Find(&ldaps, &Ldap{})
	if err != nil {
		return userIdProviders, err
	}

	for i := range userIdProviders {
		for _, provider := range providers {
			if userIdProviders[i].ProviderName == provider.Name {
				userIdProviders[i].ProviderDisplayName = provider.DisplayName
			}
		}
		for _, ldap := range ldaps {
			if userIdProviders[i].LdapId == ldap.Id {
				userIdProviders[i].LdapServerName = ldap.ServerName
			}
		}
	}

	return userIdProviders, err
}

func AddUserIdProvider(ctx context.Context, userIdProvider *UserIdProvider) (bool, error) {
	var affected int64
	err := trm.WithTx(ctx, func(ctx context.Context) error {
		existedUserIdProvider, err := repo.GetUserIdProvider(ctx, userIdProvider)
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

func UpdateUserIdProvider(ctx context.Context, userIdProvider *UserIdProvider, updateKey string) error {
	updateValue := userIdProvider.ProviderName
	if updateKey == "ldap_id" {
		updateValue = userIdProvider.LdapId
	}
	findConditions := map[string]interface{}{
		"owner":             userIdProvider.Owner,
		updateKey:           updateValue,
		"username_from_idp": userIdProvider.UsernameFromIdp,
	}
	return trm.WithTx(ctx, func(ctx context.Context) error {
		return repo.UpdateUserIdProvider(ctx, userIdProvider, findConditions)
	})
}
