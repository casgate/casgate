// Copyright 2022 The Casdoor Authors. All Rights Reserved.
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
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
	"github.com/xorm-io/core"
)

type Adapter struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	Type            string `xorm:"varchar(100)" json:"type"`
	DatabaseType    string `xorm:"varchar(100)" json:"databaseType"`
	Host            string `xorm:"varchar(100)" json:"host"`
	Port            int    `json:"port"`
	User            string `xorm:"varchar(100)" json:"user"`
	Password        string `xorm:"varchar(100)" json:"password"`
	Database        string `xorm:"varchar(100)" json:"database"`
	Table           string `xorm:"varchar(100)" json:"table"`
	TableNamePrefix string `xorm:"varchar(100)" json:"tableNamePrefix"`

	IsEnabled bool `json:"isEnabled"`

	*xormadapter.Adapter `xorm:"-" json:"-"`
}

func GetAdapterCount(owner, field, value string) (int64, error) {
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Adapter{})
}

func GetAdapters(owner string) ([]*Adapter, error) {
	adapters := []*Adapter{}
	err := ormer.Engine.Desc("created_time").Find(&adapters, &Adapter{Owner: owner})
	if err != nil {
		return adapters, err
	}

	return adapters, nil
}

func GetPaginationAdapters(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Adapter, error) {
	adapters := []*Adapter{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&adapters)
	if err != nil {
		return adapters, err
	}

	return adapters, nil
}

func getAdapter(owner, name string) (*Adapter, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	adapter := Adapter{Owner: owner, Name: name}
	existed, err := ormer.Engine.Get(&adapter)
	if err != nil {
		return nil, err
	}

	if existed {
		return &adapter, nil
	} else {
		return nil, nil
	}
}

func GetAdapter(id string) (*Adapter, error) {
	owner, name := util.GetOwnerAndNameFromId(id)
	return getAdapter(owner, name)
}

func UpdateAdapter(id string, adapter *Adapter) (bool, error) {
	owner, name := util.GetOwnerAndNameFromId(id)
	if adapter, err := getAdapter(owner, name); adapter == nil {
		return false, err
	}

	if name != adapter.Name {
		err := adapterChangeTrigger(name, adapter.Name)
		if err != nil {
			return false, err
		}
	}

	session := ormer.Engine.ID(core.PK{owner, name}).AllCols()
	if adapter.Password == "***" {
		session.Omit("password")
	}
	affected, err := session.Update(adapter)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func AddAdapter(adapter *Adapter) (bool, error) {
	affected, err := ormer.Engine.Insert(adapter)
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func DeleteAdapter(adapter *Adapter) (bool, error) {
	affected, err := ormer.Engine.ID(core.PK{adapter.Owner, adapter.Name}).Delete(&Adapter{})
	if err != nil {
		return false, err
	}

	return affected != 0, nil
}

func (adapter *Adapter) GetId() string {
	return fmt.Sprintf("%s/%s", adapter.Owner, adapter.Name)
}

func (adapter *Adapter) getTable() string {
	if adapter.DatabaseType == "mssql" {
		return fmt.Sprintf("[%s]", adapter.Table)
	} else {
		return adapter.Table
	}
}

func (adapter *Adapter) initAdapter() error {
	if adapter.Adapter == nil {
		var dataSourceName string

		if adapter.builtInAdapter() {
			dataSourceName = conf.GetConfigString("dataSourceName")
		} else {
			switch adapter.DatabaseType {
			case "mssql":
				dataSourceName = fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s", adapter.User,
					adapter.Password, adapter.Host, adapter.Port, adapter.Database)
			case "mysql":
				dataSourceName = fmt.Sprintf("%s:%s@tcp(%s:%d)/", adapter.User,
					adapter.Password, adapter.Host, adapter.Port)
			case "postgres":
				dataSourceName = fmt.Sprintf("user=%s password=%s host=%s port=%d sslmode=disable dbname=%s", adapter.User,
					adapter.Password, adapter.Host, adapter.Port, adapter.Database)
			case "CockroachDB":
				dataSourceName = fmt.Sprintf("user=%s password=%s host=%s port=%d sslmode=disable dbname=%s serial_normalization=virtual_sequence",
					adapter.User, adapter.Password, adapter.Host, adapter.Port, adapter.Database)
			case "sqlite3":
				dataSourceName = fmt.Sprintf("file:%s", adapter.Host)
			default:
				return fmt.Errorf("unsupported database type: %s", adapter.DatabaseType)
			}
		}

		if !isCloudIntranet {
			dataSourceName = strings.ReplaceAll(dataSourceName, "dbi.", "db.")
		}

		var err error
		adapter.Adapter, err = xormadapter.NewAdapterByEngineWithTableName(NewAdapter(adapter.DatabaseType, dataSourceName, adapter.Database).Engine, adapter.getTable(), adapter.TableNamePrefix)
		if err != nil {
			return err
		}
	}
	return nil
}

func adapterChangeTrigger(oldName string, newName string) error {
	session := ormer.Engine.NewSession()
	defer session.Close()

	err := session.Begin()
	if err != nil {
		return err
	}

	enforcer := new(Enforcer)
	enforcer.Adapter = newName
	_, err = session.Where("adapter=?", oldName).Update(enforcer)
	if err != nil {
		session.Rollback()
		return err
	}

	return session.Commit()
}

func safeReturn(policy []string, i int) string {
	if len(policy) > i {
		return policy[i]
	} else {
		return ""
	}
}

func matrixToCasbinRules(Ptype string, policies [][]string) []*xormadapter.CasbinRule {
	res := []*xormadapter.CasbinRule{}

	for _, policy := range policies {
		line := xormadapter.CasbinRule{
			Ptype: Ptype,
			V0:    safeReturn(policy, 0),
			V1:    safeReturn(policy, 1),
			V2:    safeReturn(policy, 2),
			V3:    safeReturn(policy, 3),
			V4:    safeReturn(policy, 4),
			V5:    safeReturn(policy, 5),
		}
		res = append(res, &line)
	}

	return res
}

func GetPolicies(adapter *Adapter) ([]*xormadapter.CasbinRule, error) {
	err := adapter.initAdapter()
	if err != nil {
		return nil, err
	}

	casbinModel := getModelDef()
	err = adapter.LoadPolicy(casbinModel)
	if err != nil {
		return nil, err
	}

	policies := matrixToCasbinRules("p", casbinModel.GetPolicy("p", "p"))
	policies = append(policies, matrixToCasbinRules("g", casbinModel.GetPolicy("g", "g"))...)
	return policies, nil
}

func UpdatePolicy(oldPolicy, newPolicy []string, adapter *Adapter) (bool, error) {
	err := adapter.initAdapter()
	if err != nil {
		return false, err
	}

	casbinModel := getModelDef()
	err = adapter.LoadPolicy(casbinModel)
	if err != nil {
		return false, err
	}

	affected := casbinModel.UpdatePolicy("p", "p", oldPolicy, newPolicy)
	if err != nil {
		return affected, err
	}
	err = adapter.SavePolicy(casbinModel)
	if err != nil {
		return false, err
	}

	return affected, nil
}

func AddPolicy(policy []string, adapter *Adapter) (bool, error) {
	err := adapter.initAdapter()
	if err != nil {
		return false, err
	}

	casbinModel := getModelDef()
	err = adapter.LoadPolicy(casbinModel)
	if err != nil {
		return false, err
	}

	casbinModel.AddPolicy("p", "p", policy)
	err = adapter.SavePolicy(casbinModel)
	if err != nil {
		return false, err
	}

	return true, nil
}

func RemovePolicy(policy []string, adapter *Adapter) (bool, error) {
	err := adapter.initAdapter()
	if err != nil {
		return false, err
	}

	casbinModel := getModelDef()
	err = adapter.LoadPolicy(casbinModel)
	if err != nil {
		return false, err
	}

	affected := casbinModel.RemovePolicy("p", "p", policy)
	if err != nil {
		return affected, err
	}
	err = adapter.SavePolicy(casbinModel)
	if err != nil {
		return false, err
	}

	return affected, nil
}

func (adapter *Adapter) builtInAdapter() bool {
	if adapter.Owner != "built-in" {
		return false
	}

	return adapter.Name == "permission-adapter-built-in" || adapter.Name == "api-adapter-built-in"
}

func getModelDef() model.Model {
	casbinModel := model.NewModel()
	casbinModel.AddDef("p", "p", "_, _, _, _, _, _")
	casbinModel.AddDef("g", "g", "_, _, _, _, _, _")
	return casbinModel
}
