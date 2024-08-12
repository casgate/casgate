package object

import (
	"context"
	"fmt"
	"github.com/casdoor/casdoor/orm"
	"testing"
	"time"
)

const modelText = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

const (
	testOrgNameDefault   = "test_bench_mapping"
	testModelNameDefault = "test_bench_mapping_model"
)

var modelRules = [][]string{
	{"g", "role.user", "role.domain.name", "role.subrole", "", ""},
	{"p", "role.name", "permission.resource", "permission.action", "", ""},
}

func benchmarkUpdateRole(N int64, b *testing.B) {
	testOrgName := fmt.Sprintf("%s-%d", testOrgNameDefault, N)
	testModelName := fmt.Sprintf("%s-%d", testModelNameDefault, N)
	InitTestConfig()
	clearDB(testOrgName, testModelName)
	err := generateInitialData(N, testOrgName, testModelName)
	if err != nil {
		b.Errorf("generateInitialData error: %s", err)
	}

	defer orm.AppOrmer.Engine.Close()
	defer clearDB(testOrgName, testModelName)

	roles, err := GetRoles(testOrgName)
	if err != nil {
		b.Errorf("GetRoles error: %s", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		new_user := &User{
			Owner: testOrgName,
			Name:  fmt.Sprintf("user_test-%d", i),
		}
		_, err = AddUser(context.Background(), new_user)
		if err != nil {
			b.Errorf("AddUser: %s", err)
		}
		roles[0].Users = append(roles[0].Users, new_user.GetId())
		b.StartTimer()
		res, err := UpdateRole(roles[0].GetId(), roles[0])
		if err != nil {
			b.Errorf("UpdateRole error: %s", err)
		}
		if res != true {
			b.Errorf("update role result is false!")
		}
	}
	b.StopTimer()
}

func BenchmarkUpdateRole(b *testing.B) {
	b.Run("UpdateRole50", func(b *testing.B) {
		benchmarkUpdateRole(50, b)
	})
	b.Run("UpdateRole100", func(b *testing.B) {
		benchmarkUpdateRole(100, b)
	})
	b.Run("UpdateRole200", func(b *testing.B) {
		benchmarkUpdateRole(200, b)
	})
	b.Run("UpdateRole1000", func(b *testing.B) {
		benchmarkUpdateRole(1000, b)
	})
	b.Run("UpdateRole2000", func(b *testing.B) {
		benchmarkUpdateRole(2000, b)
	})
}

func benchmarkDeleteRoleFromPermission(N int64, b *testing.B) {
	testOrgName := fmt.Sprintf("%s-%d", testOrgNameDefault, N)
	testModelName := fmt.Sprintf("%s-%d", testModelNameDefault, N)
	InitTestConfig()
	clearDB(testOrgName, testModelName)
	err := generateInitialData(N, testOrgName, testModelName)
	if err != nil {
		b.Errorf("generateInitialData error: %s", err)
	}

	defer orm.AppOrmer.Engine.Close()
	defer clearDB(testOrgName, testModelName)

	permissions, err := GetPermissions(testOrgName)
	if err != nil {
		b.Errorf("GetRoles error: %s", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		new_user := &User{
			Owner: testOrgName,
			Name:  fmt.Sprintf("user_test-%d", i),
		}
		_, err = AddUser(context.Background(), new_user)
		if err != nil {
			b.Errorf("AddUser: %s", err)
		}
		permissions[5].Users = append(permissions[5].Users, new_user.GetId())
		permissions[5].Roles = []string{}
		b.StartTimer()
		res, err := UpdatePermission(permissions[5].GetId(), permissions[5])
		if err != nil {
			b.Errorf("UpdatePermission error: %s", err)
		}
		if res != true {
			b.Errorf("update permission result is false!")
		}
	}
	b.StopTimer()
}

func BenchmarkDeleteRoleFromPermission(b *testing.B) {
	b.Run("DeleteRoleFromPermission50", func(b *testing.B) {
		benchmarkDeleteRoleFromPermission(50, b)
	})
	b.Run("DeleteRoleFromPermission100", func(b *testing.B) {
		benchmarkDeleteRoleFromPermission(100, b)
	})
	b.Run("DeleteRoleFromPermission200", func(b *testing.B) {
		benchmarkDeleteRoleFromPermission(200, b)
	})
	b.Run("DeleteRoleFromPermission1000", func(b *testing.B) {
		benchmarkDeleteRoleFromPermission(1000, b)
	})
	b.Run("DeleteRoleFromPermission2000", func(b *testing.B) {
		benchmarkDeleteRoleFromPermission(2000, b)
	})
}

func generateInitialData(N int64, testOrgName, testModelName string) error {
	organization := &Organization{
		Owner:       "admin",
		Name:        testOrgName,
		CreatedTime: time.Now().String(),
		DisplayName: testOrgName,
	}
	_, err := AddOrganization(organization)
	if err != nil {
		return fmt.Errorf("AddOrganization: %w", err)
	}
	model := &Model{
		Owner:               organization.Name,
		Name:                testModelName,
		CreatedTime:         time.Now().String(),
		DisplayName:         testModelName,
		ModelText:           modelText,
		IsEnabled:           true,
		CustomPolicyMapping: false,
	}

	new_role := &Role{
		Owner: testOrgName,
		Name:  "admin",
	}
	_, err = orm.AppOrmer.Engine.Insert(new_role)
	if err != nil {
		return fmt.Errorf("AddRole: %w", err)
	}

	for i := int64(0); i < N; i++ {
		new_permission := &Permission{
			Owner:        testOrgName,
			Name:         fmt.Sprintf("Permission%d", i),
			CreatedTime:  time.Now().String(),
			DisplayName:  fmt.Sprintf("Permission%d", i),
			Groups:       nil,
			Users:        nil,
			Roles:        []string{new_role.GetId()},
			Domains:      nil,
			Model:        testModelName,
			ResourceType: "Custom",
			Resources:    []string{fmt.Sprintf("resource%d", i)},
			Actions:      []string{"read"},
			Effect:       "Allow",
			IsEnabled:    true,
		}
		_, err = orm.AppOrmer.Engine.Insert(new_permission)
		if err != nil {
			return fmt.Errorf("AddPermission: %w", err)
		}

		new_domain := &Domain{
			Owner: testOrgName,
			Name:  fmt.Sprintf("domain%d", i),
		}
		_, err = orm.AppOrmer.Engine.Insert(new_domain)
		if err != nil {
			return fmt.Errorf("AddDomain: %w", err)
		}

		new_user := &User{
			Owner: testOrgName,
			Name:  fmt.Sprintf("user%d", i),
		}
		_, err = orm.AppOrmer.Engine.Insert(new_user)
		if err != nil {
			return fmt.Errorf("AddUser: %w", err)
		}

		new_role2 := &Role{
			Owner:   testOrgName,
			Name:    fmt.Sprintf("roleMapping%d", i),
			Roles:   []string{new_role.GetId()},
			Users:   []string{new_user.GetId()},
			Domains: []string{new_domain.GetId()},
		}
		_, err = orm.AppOrmer.Engine.Insert(new_role2)
		if err != nil {
			return fmt.Errorf("AddRole: %w", err)
		}
	}

	_, err = AddModel(model)
	if err != nil {
		return fmt.Errorf("AddModel: %w", err)
	}

	model.CustomPolicyMapping = true
	model.CustomPolicyMappingRules = modelRules

	_, err = UpdateModel(model.GetId(), model)
	if err != nil {
		return fmt.Errorf("UpdateModel: %w", err)
	}

	return nil
}

func clearDB(testOrgName, testModelName string) {
	_, err := orm.AppOrmer.Engine.Delete(&Role{Owner: testOrgName})
	if err != nil {
		panic(err)
	}

	_, err = orm.AppOrmer.Engine.Delete(&User{Owner: testOrgName})
	if err != nil {
		panic(err)
	}

	_, err = orm.AppOrmer.Engine.Delete(&Domain{Owner: testOrgName})
	if err != nil {
		panic(err)
	}

	_, err = orm.AppOrmer.Engine.Where("owner = ?", testOrgName).Cols("roles").Update(&Permission{Roles: []string{}})
	if err != nil {
		panic(err)
	}

	model := &Model{
		Owner:               testOrgName,
		Name:                testModelName,
		CustomPolicyMapping: false,
	}

	_, err = UpdateModel(model.GetId(), model)
	if err != nil {
		panic(fmt.Errorf("UpdateModel: %w", err))
	}

	_, err = orm.AppOrmer.Engine.Delete(&Permission{Owner: testOrgName})
	if err != nil {
		panic(err)
	}

	_, err = DeleteModel(model)
	if err != nil {
		panic(fmt.Errorf("DeleteModel: %w", err))
	}

	_, err = DeleteOrganization("en", &Organization{
		Owner: "admin",
		Name:  testOrgName,
	})
	if err != nil {
		panic(fmt.Errorf("DeleteOrganization: %w", err))
	}
}
