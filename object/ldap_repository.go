// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"fmt"

	"github.com/casdoor/casdoor/ldap_sync"
	"github.com/casdoor/casdoor/orm"

	"github.com/casdoor/casdoor/util"
)

func AddLdap(ldap *ldap_sync.Ldap) (bool, error) {
	if len(ldap.Id) == 0 {
		ldap.Id = util.GenerateId()
	}

	if len(ldap.CreatedTime) == 0 {
		ldap.CreatedTime = util.GetCurrentTime()
	}

	affected, err := orm.AppOrmer.Engine.Insert(ldap)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func CheckLdapExist(ldap *ldap_sync.Ldap) (bool, error) {
	var result []*ldap_sync.Ldap
	err := orm.AppOrmer.Engine.Find(
		&result, &ldap_sync.Ldap{
			Id: ldap.Id,
		})
	if err != nil {
		return false, err
	}

	if len(result) > 0 {
		return true, nil
	}

	return false, nil
}

func GetLdaps(owner string) ([]*ldap_sync.Ldap, error) {
	var ldaps []*ldap_sync.Ldap
	err := orm.AppOrmer.Engine.Desc("created_time").Find(&ldaps, &ldap_sync.Ldap{Owner: owner})
	if err != nil {
		return ldaps, err
	}

	return ldaps, nil
}

func GetLdap(id string) (*ldap_sync.Ldap, error) {
	return getLdap(id)
}

func getLdap(id string) (*ldap_sync.Ldap, error) {
	if util.IsStringsEmpty(id) {
		return nil, nil
	}

	ldap := ldap_sync.Ldap{Id: id}
	existed, err := orm.AppOrmer.Engine.Get(&ldap)
	if err != nil {
		return &ldap, nil
	}

	if existed {
		return &ldap, nil
	} else {
		return nil, nil
	}
}

func GetMaskedLdap(ldap *ldap_sync.Ldap, errs ...error) (*ldap_sync.Ldap, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	if ldap == nil {
		return nil, nil
	}

	if ldap.Password != "" {
		ldap.Password = "***"
	}

	return ldap, nil
}

func GetMaskedLdaps(ldaps []*ldap_sync.Ldap, errs ...error) ([]*ldap_sync.Ldap, error) {
	if len(errs) > 0 && errs[0] != nil {
		return nil, errs[0]
	}

	var err error
	for _, ldap := range ldaps {
		ldap, err = GetMaskedLdap(ldap)
		if err != nil {
			return nil, err
		}
	}
	return ldaps, nil
}

func UpdateLdap(ldap *ldap_sync.Ldap) (bool, error) {
	var l *ldap_sync.Ldap
	var err error
	if l, err = GetLdap(ldap.Id); err != nil {
		return false, nil
	} else if l == nil {
		return false, nil
	}

	if ldap.Password == "***" {
		ldap.Password = l.Password
	}

	affected, err := orm.AppOrmer.Engine.ID(ldap.Id).Cols("owner", "server_name", "host", "cert",
		"port", "enable_ssl", "username", "password", "base_dn", "filter", "filter_fields", "auto_sync",
		"role_mapping_items", "enable_case_insensitivity", "enable_role_mapping", "attribute_mapping_items", "enable_attribute_mapping",
		"enable_cryptographic_auth", "client_cert", "user_mapping_strategy").Update(ldap)
	if err != nil {
		return false, nil
	}

	return affected != 0, nil
}

func DeleteLdap(ldap *ldap_sync.Ldap) (bool, error) {
	affected, err := orm.AppOrmer.Engine.ID(ldap.Id).Delete(&ldap_sync.Ldap{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func GetLdapPassword(ldap ldap_sync.Ldap) (string, error) {
	ldapFromDB := ldap_sync.Ldap{
		Owner:    ldap.Owner,
		Host:     ldap.Host,
		Port:     ldap.Port,
		Username: ldap.Username,
	}

	existed, err := orm.AppOrmer.Engine.Get(&ldapFromDB)
	if err != nil {
		return "", err
	}

	if !existed {
		return "", fmt.Errorf("ldap does not exist")
	}

	return ldapFromDB.Password, nil
}

type LdapRepository struct {
}

func (r *LdapRepository) GetLdap(id string) (*ldap_sync.Ldap, error) {
	return getLdap(id)
}
