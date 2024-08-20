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
	"github.com/casdoor/casdoor/orm"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/config"
	"github.com/casbin/casbin/v2/log"
	"github.com/casbin/casbin/v2/model"
	"github.com/casdoor/casdoor/conf"
	xormadapter "github.com/casdoor/xorm-adapter/v3"
)

func getPermissionEnforcer(p *Permission, permissionIDs ...string) *casbin.Enforcer {
	// Init an enforcer instance without specifying a model or adapter.
	// If you specify an adapter, it will load all policies, which is a
	// heavy process that can slow down the application.
	enforcer, err := casbin.NewEnforcer(&log.DefaultLogger{}, false)
	if err != nil {
		panic(err)
	}

	err = p.setEnforcerModel(enforcer)
	if err != nil {
		panic(err)
	}

	err = p.setEnforcerAdapter(enforcer)
	if err != nil {
		panic(err)
	}

	policyFilterV5 := []string{p.GetId()}
	if len(permissionIDs) != 0 {
		policyFilterV5 = permissionIDs
	}

	policyFilter := xormadapter.Filter{
		V5: policyFilterV5,
	}

	if !HasRoleDefinition(enforcer.GetModel()) {
		policyFilter.Ptype = []string{"p"}
	}

	err = enforcer.LoadFilteredPolicy(policyFilter)
	if err != nil {
		panic(err)
	}

	return enforcer
}

func (p *Permission) setEnforcerAdapter(enforcer *casbin.Enforcer) error {
	tableName := "permission_rule"
	if len(p.Adapter) != 0 {
		adapterObj, err := getAdapter(p.Owner, p.Adapter)
		if err != nil {
			return err
		}

		if adapterObj != nil && adapterObj.Table != "" {
			tableName = adapterObj.Table
		}
	}
	tableNamePrefix := conf.GetConfigString("tableNamePrefix")
	adapter, err := xormadapter.NewAdapterByEngineWithTableName(orm.AppOrmer.Engine, tableName, tableNamePrefix)
	if err != nil {
		return err
	}

	enforcer.SetAdapter(adapter)
	return nil
}

func (p *Permission) setEnforcerModel(enforcer *casbin.Enforcer) error {
	permissionModel, err := getModel(p.Owner, p.Model)
	if err != nil {
		return err
	}

	// TODO: return error if permissionModel is nil.
	m := model.Model{}
	if permissionModel != nil {
		m, err = GetBuiltInModel(permissionModel.ModelText)
	} else {
		m, err = GetBuiltInModel("")
	}
	if err != nil {
		return err
	}

	err = enforcer.InitWithModelAndAdapter(m, nil)
	if err != nil {
		return err
	}
	return nil
}

func getRolesInRole(roleId string, visited map[string]struct{}) ([]*Role, error) {
	role, err := GetRole(roleId)
	if err != nil {
		return []*Role{}, err
	}

	if role == nil {
		return []*Role{}, nil
	}
	visited[roleId] = struct{}{}

	roles := []*Role{role}
	for _, subRole := range role.Roles {
		if _, ok := visited[subRole]; !ok {
			r, err := getRolesInRole(subRole, visited)
			if err != nil {
				return []*Role{}, err
			}

			roles = append(roles, r...)
		}
	}

	return roles, nil
}

type CasbinRequest = []interface{}

func Enforce(permission *Permission, request *CasbinRequest, permissionIds ...string) (bool, error) {
	enforcer := getPermissionEnforcer(permission, permissionIds...)
	return enforcer.Enforce(*request...)
}

func BatchEnforce(permission *Permission, requests *[]CasbinRequest, permissionIds ...string) ([]bool, error) {
	enforcer := getPermissionEnforcer(permission, permissionIds...)
	return enforcer.BatchEnforce(*requests)
}

func getAllValues(userId string, fn func(enforcer *casbin.Enforcer) []string) []string {
	permissions, _, err := getPermissionsAndRolesByUser(userId)
	if err != nil {
		panic(err)
	}

	for _, role := range GetAllRoles(userId) {
		permissionsByRole, err := GetPermissionsByRole(role)
		if err != nil {
			panic(err)
		}

		permissions = append(permissions, permissionsByRole...)
	}

	var values []string
	for _, permission := range permissions {
		enforcer := getPermissionEnforcer(permission)
		values = append(values, fn(enforcer)...)
	}
	return values
}

func GetAllObjects(userId string) []string {
	return getAllValues(userId, func(enforcer *casbin.Enforcer) []string {
		return enforcer.GetAllObjects()
	})
}

func GetAllActions(userId string) []string {
	return getAllValues(userId, func(enforcer *casbin.Enforcer) []string {
		return enforcer.GetAllActions()
	})
}

func GetAllRoles(userId string) []string {
	roles, err := getRolesByUser(userId)
	if err != nil {
		panic(err)
	}

	var res []string
	for _, role := range roles {
		res = append(res, role.Name)
	}
	return res
}

func GetBuiltInModel(modelText string) (model.Model, error) {
	if modelText == "" {
		modelText = `[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, "", "", permissionId

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`
		return model.NewModelFromString(modelText)
	} else {
		cfg, err := config.NewConfigFromText(modelText)
		if err != nil {
			return nil, err
		}

		// load [policy_definition]
		policyDefinition := strings.Split(cfg.String("policy_definition::p"), ",")
		fieldsNum := len(policyDefinition)
		if fieldsNum > builtInAvailableField {
			panic(fmt.Errorf("the maximum policy_definition field number cannot exceed %d, got %d", builtInAvailableField, fieldsNum))
		}
		// filled empty field with "" and V5 with "permissionId"
		for i := builtInAvailableField - fieldsNum; i > 0; i-- {
			policyDefinition = append(policyDefinition, "")
		}
		policyDefinition = append(policyDefinition, "permissionId")

		m, _ := model.NewModelFromString(modelText)
		m.AddDef("p", "p", strings.Join(policyDefinition, ","))

		return m, err
	}
}
