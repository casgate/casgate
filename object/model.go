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
	"bytes"
	"fmt"

	"github.com/casdoor/casdoor/orm"

	"github.com/casbin/casbin/v2/model"
	"github.com/xorm-io/core"

	"github.com/casdoor/casdoor/util"
)

type Model struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Description string `xorm:"varchar(100)" json:"description"`

	ModelText                string     `xorm:"mediumtext" json:"modelText"`
	IsEnabled                bool       `json:"isEnabled"`
	CustomPolicyMapping      bool       `json:"customPolicyMapping"`
	CustomPolicyMappingRules [][]string `xorm:"mediumtext" json:"customPolicyMappingRules"`

	model.Model `xorm:"-" json:"-"`
}

func GetModelCount(owner, field, value string) (int64, error) {
	session := orm.GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Model{})
}

func GetModels(owner string) ([]*Model, error) {
	models := []*Model{}
	err := orm.AppOrmer.Engine.Desc("created_time").Find(&models, &Model{Owner: owner})
	if err != nil {
		return models, err
	}

	return models, nil
}

func GetPaginationModels(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Model, error) {
	models := []*Model{}
	session := orm.GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&models)
	if err != nil {
		return models, err
	}

	return models, nil
}

func getModel(owner string, name string) (*Model, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	m := Model{Owner: owner, Name: name}
	existed, err := orm.AppOrmer.Engine.Get(&m)
	if err != nil {
		return &m, err
	}

	if existed {
		return &m, nil
	} else {
		return nil, nil
	}
}

func GetModel(id string) (*Model, error) {
	owner, name, err := util.GetOwnerAndNameFromId(id)
	if err != nil {
		return nil, err
	}
	return getModel(owner, name)
}

func UpdateModelWithCheck(id string, modelObj *Model) error {
	// check model grammar
	_, err := model.NewModelFromString(modelObj.ModelText)
	if err != nil {
		return err
	}
	_, err = UpdateModel(id, modelObj)
	if err != nil {
		return err
	}

	return nil
}

func UpdateModel(id string, modelObj *Model) (bool, error) {
	owner, name, err := util.GetOwnerAndNameFromId(id)
	if err != nil {
		return false, err
	}
	m, err := getModel(owner, name)
	if err != nil {
		return false, err
	} else if m == nil {
		return false, nil
	}

	if name != modelObj.Name {
		err := modelChangeTrigger(name, modelObj.Name)
		if err != nil {
			return false, err
		}
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{owner, name}).AllCols().Update(modelObj)
	if err != nil {
		return false, err
	}

	if affected > 0 {
		if !equalRules(m.CustomPolicyMappingRules, modelObj.CustomPolicyMappingRules) ||
			m.CustomPolicyMapping != modelObj.CustomPolicyMapping {
			permissions, err := GetPermissionsByModel(modelObj.Owner, modelObj.Name)
			if err != nil {
				return false, err
			}

			err = ProcessPolicyDifference(permissions)
			if err != nil {
				return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
			}
		}
	}

	return affected != 0, err
}

func AddModel(model *Model) (bool, error) {
	affected, err := orm.AppOrmer.Engine.Insert(model)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteModel(model *Model) (bool, error) {
	affected, err := orm.AppOrmer.Engine.ID(core.PK{model.Owner, model.Name}).Delete(&Model{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (m *Model) GetId() string {
	return fmt.Sprintf("%s/%s", m.Owner, m.Name)
}

func modelChangeTrigger(oldName string, newName string) error {
	session := orm.AppOrmer.Engine.NewSession()
	defer session.Close()

	err := session.Begin()
	if err != nil {
		return err
	}

	permission := new(Permission)
	permission.Model = newName
	_, err = session.Where("model=?", oldName).Update(permission)
	if err != nil {
		session.Rollback()
		return err
	}

	enforcer := new(Enforcer)
	enforcer.Model = newName
	_, err = session.Where("model=?", oldName).Update(enforcer)
	if err != nil {
		session.Rollback()
		return err
	}

	return session.Commit()
}

func HasRoleDefinition(m model.Model) bool {
	if m == nil {
		return false
	}
	return m["g"] != nil
}

func (m *Model) initModel() error {
	if m.Model == nil {
		casbinModel, err := model.NewModelFromString(m.ModelText)
		if err != nil {
			return err
		}
		m.Model = casbinModel
	}

	return nil
}

func equalRules(first, second [][]string) bool {
	var firstBytes []byte
	for _, rule := range first {
		for _, item := range rule {
			firstBytes = append(firstBytes, []byte(item)...)
		}
	}

	var secondBytes []byte
	for _, rule := range second {
		for _, item := range rule {
			secondBytes = append(secondBytes, []byte(item)...)
		}
	}

	return bytes.Equal(firstBytes, secondBytes)
}
