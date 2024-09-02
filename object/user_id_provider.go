package object

import (
	"context"

	"github.com/casdoor/casdoor/ldap_sync"
	"github.com/casdoor/casdoor/orm"
)

// ExternalUser contains integration original data from external identity provider(LDAP)
type ExternalUser struct {
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

func GetAllExternalUsersData() ([]*ExternalUser, error) {
	var externalUsers []*ExternalUser
	var providers []*Provider
	var ldaps []*ldap_sync.Ldap

	err := orm.AppOrmer.Engine.Asc("last_sign_in_time").Find(&externalUsers, &ExternalUser{})
	if err != nil {
		return externalUsers, err
	}

	err = orm.AppOrmer.Engine.Find(&providers, &Provider{})
	if err != nil {
		return externalUsers, err
	}

	err = orm.AppOrmer.Engine.Find(&ldaps, &ldap_sync.Ldap{})
	if err != nil {
		return externalUsers, err
	}

	for i := range externalUsers {
		for _, provider := range providers {
			if externalUsers[i].ProviderName == provider.Name {
				externalUsers[i].ProviderDisplayName = provider.DisplayName
			}
		}
		for _, ldap := range ldaps {
			if externalUsers[i].LdapId == ldap.Id {
				externalUsers[i].LdapServerName = ldap.ServerName
			}
		}
	}

	return externalUsers, err
}

func GetExternalUsersByOwnerOrAdmin(owner string) ([]*ExternalUser, error) {
	var externalUsers []*ExternalUser
	var providers []*Provider
	var ldaps []*ldap_sync.Ldap

	err := orm.AppOrmer.Engine.Where("owner = ? or owner = ?", "admin", owner).Asc("last_sign_in_time").Find(&externalUsers, &ExternalUser{})
	if err != nil {
		return externalUsers, err
	}

	err = orm.AppOrmer.Engine.Find(&providers, &Provider{})
	if err != nil {
		return externalUsers, err
	}

	err = orm.AppOrmer.Engine.Find(&ldaps, &ldap_sync.Ldap{})
	if err != nil {
		return externalUsers, err
	}

	for i := range externalUsers {
		for _, provider := range providers {
			if externalUsers[i].ProviderName == provider.Name {
				externalUsers[i].ProviderDisplayName = provider.DisplayName
			}
		}
		for _, ldap := range ldaps {
			if externalUsers[i].LdapId == ldap.Id {
				externalUsers[i].LdapServerName = ldap.ServerName
			}
		}
	}

	return externalUsers, err
}

func AddExternalUser(ctx context.Context, externalUser *ExternalUser) (bool, error) {
	var affected int64
	err := trm.WithTx(ctx, func(ctx context.Context) error {
		existingExternalUser, err := repo.GetExternalUser(ctx, externalUser)
		if err != nil {
			return err
		}
		if existingExternalUser == nil {
			affected, err = repo.InsertExternalUser(ctx, externalUser)
			if err != nil {
				return err
			}
		}
		return nil
	})

	return affected != 0, err
}

func UpdateExternalUser(ctx context.Context, externalUser *ExternalUser, updateKey string) error {
	updateValue := externalUser.ProviderName
	if updateKey == "ldap_id" {
		updateValue = externalUser.LdapId
	}
	findConditions := map[string]interface{}{
		"owner":             externalUser.Owner,
		updateKey:           updateValue,
		"username_from_idp": externalUser.UsernameFromIdp,
	}
	return trm.WithTx(ctx, func(ctx context.Context) error {
		return repo.UpdateExternalUser(ctx, externalUser, findConditions)
	})
}
