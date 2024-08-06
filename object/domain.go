// Copyright 2023 The Casgate Authors. All Rights Reserved.
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
	"context"
	"fmt"
	"github.com/casdoor/casdoor/orm"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

type Domain struct {
	Owner       string   `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string   `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string   `xorm:"varchar(100)" json:"createdTime"`
	DisplayName string   `xorm:"varchar(100)" json:"displayName"`
	Description string   `xorm:"varchar(100)" json:"description"`
	Tags        []string `xorm:"mediumtext" json:"tags"`

	Domains   []string `xorm:"mediumtext" json:"domains"`
	IsEnabled bool     `json:"isEnabled"`
}

func GetDomainCount(owner, field, value string) (int64, error) {
	session := orm.GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Domain{})
}

func GetDomains(ctx context.Context, owner string) ([]*Domain, error) {
	domains, err := repo.GetDomains(ctx, owner)
	if err != nil {
		return domains, err
	}

	return domains, nil
}

func GetPaginationDomains(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Domain, error) {
	domains := []*Domain{}
	session := orm.GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&domains)
	if err != nil {
		return domains, err
	}

	return domains, nil
}

func getDomain(owner string, name string) (*Domain, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	domain := Domain{Owner: owner, Name: name}
	existed, err := orm.AppOrmer.Engine.Get(&domain)
	if err != nil {
		return &domain, err
	}

	if existed {
		return &domain, nil
	} else {
		return nil, nil
	}
}

func GetDomain(id string) (*Domain, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	return getDomain(owner, name)
}

func UpdateDomain(ctx context.Context, id string, domain *Domain) (bool, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	oldDomain, err := getDomain(owner, name)
	if err != nil {
		return false, err
	}

	if oldDomain == nil {
		return false, nil
	}

	// allParentDomains, _ := GetAncestorDomains(ctx, id)
	// for _, d := range allParentDomains {
	// 	for _, domainId := range d.Domains {
	// 		if id == domainId {
	// 			return false, fmt.Errorf("role %s is in the child domain of %s", id, d.GetId())
	// 		}
	// 	}
	// }

	if name != domain.Name {
		err := domainChangeTrigger(name, domain.Name)
		if err != nil {
			return false, err
		}
	}

	oldDomainReachablePermissions, err := subDomainPermissions(oldDomain)
	if err != nil {
		return false, fmt.Errorf("subRolePermissions: %w", err)
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{owner, name}).AllCols().Update(domain)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		domainReachablePermissions, err := subDomainPermissions(domain)
		if err != nil {
			return false, fmt.Errorf("subDomainPermissions: %w", err)
		}
		domainReachablePermissions = append(domainReachablePermissions, oldDomainReachablePermissions...)
		err = ProcessPolicyDifference(domainReachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func AddDomain(domain *Domain) (bool, error) {
	affected, err := orm.AppOrmer.Engine.Insert(domain)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		domainReachablePermissions, err := subDomainPermissions(domain)
		if err != nil {
			return false, fmt.Errorf("subDomainPermissions: %w", err)
		}

		err = ProcessPolicyDifference(domainReachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func DeleteDomain(domain *Domain) (bool, error) {
	domainId := domain.GetId()

	domainReachablePermissions, err := subDomainPermissions(domain)
	if err != nil {
		return false, fmt.Errorf("subDomainPermissions: %w", err)
	}

	roles, err := GetRolesByDomain(domainId)
	if err != nil {
		return false, fmt.Errorf("GetRolesByDomain: %w", err)
	}

	for _, role := range roles {
		if util.InSlice(role.Domains, domainId) {
			role.Domains = util.DeleteVal(role.Domains, domainId)
			_, err := UpdateRole(role.GetId(), role)
			if err != nil {
				return false, err
			}
		}
	}

	permissions, err := GetPermissionsByDomain(domainId)
	if err != nil {
		return false, fmt.Errorf("GetPermissionsByDomain: %w", err)
	}

	for _, permission := range permissions {
		if util.InSlice(permission.Domains, domainId) {
			permission.Domains = util.DeleteVal(permission.Domains, domainId)
			_, err := UpdatePermission(permission.GetId(), permission)
			if err != nil {
				return false, err
			}
		}
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{domain.Owner, domain.Name}).Delete(&Domain{})
	if err != nil {
		return false, err
	}

	if affected != 0 {
		err = ProcessPolicyDifference(domainReachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func (domain *Domain) GetId() string {
	return domain.Owner + "/" + domain.Name //string concatenation 10x faster than fmt.Sprintf
}

func domainChangeTrigger(oldName string, newName string) error {
	session := orm.AppOrmer.Engine.NewSession()
	defer session.Close()

	err := session.Begin()
	if err != nil {
		return err
	}

	var roles []*Role
	err = orm.AppOrmer.Engine.Find(&roles)
	if err != nil {
		return err
	}

	for _, role := range roles {
		for j, u := range role.Domains {
			owner, name := util.GetOwnerAndNameFromId(u)
			if name == oldName {
				role.Domains[j] = util.GetId(owner, newName)
			}
		}
		_, err = session.Where("name=?", role.Name).And("owner=?", role.Owner).Update(role)
		if err != nil {
			return err
		}
	}

	var permissions []*Permission
	err = orm.AppOrmer.Engine.Find(&permissions)
	if err != nil {
		return err
	}

	for _, permission := range permissions {
		for j, u := range permission.Domains {
			// u = organization/username
			owner, name := util.GetOwnerAndNameFromId(u)
			if name == oldName {
				permission.Domains[j] = util.GetId(owner, newName)
			}
		}
		_, err = session.Where("name=?", permission.Name).And("owner=?", permission.Owner).Update(permission)
		if err != nil {
			return err
		}
	}

	return session.Commit()
}

func subDomainPermissions(domain *Domain) ([]*Permission, error) {
	result := make([]*Permission, 0)

	visited := map[string]struct{}{}
	subDomains, err := getDomainsInDomain(domain.GetId(), visited)
	if err != nil {
		return nil, fmt.Errorf("getDomainsInDomain: %w", err)
	}
	for _, subDomain := range subDomains {
		permissions, err := GetPermissionsByDomain(subDomain.GetId())
		if err != nil {
			return nil, fmt.Errorf("GetPermissionsByDomain: %w", err)
		}
		if len(permissions) > 0 {
			result = append(result, permissions...)
		}

		domainRoles, err := GetPaginationRoles(domain.Owner, -1, -1, "domains", subDomain.GetId(), "", "")
		if err != nil {
			return nil, fmt.Errorf("GetPaginationRoles: %w", err)
		}

		for _, role := range domainRoles {
			rolePermissions, err := subRolePermissions(role)
			if err != nil {
				return nil, fmt.Errorf("subRolePermissions: %w", err)
			}
			if len(rolePermissions) > 0 {
				result = append(result, rolePermissions...)
			}
		}

	}

	return result, nil
}

// GetAncestorDomains returns a list of domains that contain the given domainIds
func GetAncestorDomains(ctx context.Context, domainIds ...string) ([]*Domain, error) {
	owner, _ := util.GetOwnerAndNameFromIdNoCheck(domainIds[0])

	allDomains, err := GetDomains(ctx, owner)
	if err != nil {
		return nil, err
	}

	allDomainsTree := makeAncestorDomainsTreeMap(allDomains)

	return getAncestorEntities(allDomainsTree, domainIds...)
}

func makeAncestorDomainsTreeMap(domains []*Domain) map[string]*TreeNode[*Domain] {
	var (
		domainMap = make(map[string]*TreeNode[*Domain], 0)
	)

	for _, domain := range domains {
		domainMap[domain.GetId()] = &TreeNode[*Domain]{
			ancestors: nil,
			value:     domain,
			children:  nil,
		}
	}

	for _, domain := range domains {
		for _, subdomain := range domain.Domains {
			domainMap[subdomain].ancestors = append(domainMap[subdomain].ancestors, domainMap[domain.GetId()])
			domainMap[domain.GetId()].children = append(domainMap[domain.GetId()].children, domainMap[subdomain])
		}
	}

	return domainMap
}

func getDomainsInDomain(domainId string, visited map[string]struct{}) ([]*Domain, error) {
	domain, err := GetDomain(domainId)
	if err != nil {
		return []*Domain{}, err
	}

	if domain == nil {
		return []*Domain{}, nil
	}
	visited[domainId] = struct{}{}

	domains := []*Domain{domain}
	for _, subDomain := range domain.Domains {
		if _, ok := visited[subDomain]; !ok {
			r, err := getDomainsInDomain(subDomain, visited)
			if err != nil {
				return []*Domain{}, err
			}

			domains = append(domains, r...)
		}
	}

	return domains, nil
}
