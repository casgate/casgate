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
	"github.com/xorm-io/core"

	casdoorcert "github.com/casdoor/casdoor/cert"
	"github.com/casdoor/casdoor/orm"
	"github.com/casdoor/casdoor/util"
)

func GetMaskedCert(cert *casdoorcert.Cert) *casdoorcert.Cert {
	if cert == nil {
		return nil
	}

	if cert.PrivateKey != "" {
		cert.PrivateKey = "***"
	}

	return cert
}

func GetMaskedCerts(certs []*casdoorcert.Cert, err error) ([]*casdoorcert.Cert, error) {
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		cert = GetMaskedCert(cert)
	}
	return certs, nil
}

func GetCertCount(owner, field, value string) (int64, error) {
	session := orm.GetSession("", -1, -1, field, value, "", "")
	return session.Where("owner = ? or owner = ? ", "admin", owner).Count(&casdoorcert.Cert{})
}

func GetCerts(owner string) ([]*casdoorcert.Cert, error) {
	certs := []*casdoorcert.Cert{}
	err := orm.AppOrmer.Engine.Where("owner = ? or owner = ? ", "admin", owner).Desc("created_time").Find(
		&certs,
		&casdoorcert.Cert{},
	)
	if err != nil {
		return certs, err
	}

	return certs, nil
}

func GetPaginationCerts(
	owner string,
	offset, limit int,
	field, value, sortField, sortOrder string,
) ([]*casdoorcert.Cert, error) {
	certs := []*casdoorcert.Cert{}
	session := orm.GetSession("", offset, limit, field, value, sortField, sortOrder)
	err := session.Where("owner = ? or owner = ? ", "admin", owner).Find(&certs)
	if err != nil {
		return certs, err
	}

	return certs, nil
}

func GetGlobalCertsCount(field, value string) (int64, error) {
	session := orm.GetSession("", -1, -1, field, value, "", "")
	return session.Count(&casdoorcert.Cert{})
}

func GetPaginationGlobalCerts(
	owner string,
	offset, limit int,
	field, value, sortField, sortOrder string,
) ([]*casdoorcert.Cert, error) {
	certs := []*casdoorcert.Cert{}
	session := orm.GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&certs)
	if err != nil {
		return certs, err
	}

	return certs, nil
}

func getCert(owner string, name string) (*casdoorcert.Cert, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	cert := casdoorcert.Cert{Owner: owner, Name: name}
	existed, err := orm.AppOrmer.Engine.Get(&cert)
	if err != nil {
		return &cert, err
	}

	if existed {
		return &cert, nil
	} else {
		return nil, nil
	}
}

func GetCert(id string) (*casdoorcert.Cert, error) {
	owner, name, err := util.SplitIdIntoOrgAndName(id)
	if err != nil {
		return nil, err
	}
	return getCert(owner, name)
}

func UpdateCert(id string, cert *casdoorcert.Cert) (bool, error) {
	owner, name, err := util.SplitIdIntoOrgAndName(id)
	if err != nil {
		return false, err
	}
	if c, err := getCert(owner, name); err != nil {
		return false, err
	} else if c == nil {
		return false, nil
	}

	if name != cert.Name {
		err := certChangeTrigger(name, cert.Name)
		if err != nil {
			return false, err
		}
	}
	session := orm.AppOrmer.Engine.ID(core.PK{owner, name}).AllCols()
	if cert.PrivateKey == "***" {
		session.Omit("private_key")
	}
	affected, err := session.Update(cert)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func AddCert(cert *casdoorcert.Cert) (bool, error) {
	if cert.Scope == casdoorcert.ScopeCertJWT && (cert.Certificate == "" || cert.PrivateKey == "") {
		certificate, privateKey := generateRsaKeys(cert.BitSize, cert.ExpireInYears, cert.Name, cert.Owner)
		cert.Certificate = certificate
		cert.PrivateKey = privateKey
	}

	affected, err := orm.AppOrmer.Engine.Insert(cert)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteCert(cert *casdoorcert.Cert) (bool, error) {
	affected, err := orm.AppOrmer.Engine.ID(core.PK{cert.Owner, cert.Name}).Delete(&casdoorcert.Cert{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func getCertByApplication(application *Application) (*casdoorcert.Cert, error) {
	if application.Cert != "" {
		return casdoorcert.GetCertByName(application.Cert)
	} else {
		return GetDefaultCert()
	}
}

func GetDefaultCert() (*casdoorcert.Cert, error) {
	return getCert("admin", "cert-built-in")
}

func certChangeTrigger(oldName string, newName string) error {
	session := orm.AppOrmer.Engine.NewSession()
	defer session.Close()

	err := session.Begin()
	if err != nil {
		return err
	}

	application := new(Application)
	application.Cert = newName
	_, err = session.Where("cert=?", oldName).Update(application)
	if err != nil {
		return err
	}

	return session.Commit()
}
