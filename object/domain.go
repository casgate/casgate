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
	"fmt"

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
	session := GetSession(owner, -1, -1, field, value, "", "")
	return session.Count(&Domain{})
}

func GetDomains(owner string) ([]*Domain, error) {
	domains := []*Domain{}
	err := ormer.Engine.Desc("created_time").Find(&domains, &Domain{Owner: owner})
	if err != nil {
		return domains, err
	}

	return domains, nil
}

func GetPaginationDomains(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Domain, error) {
	domains := []*Domain{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
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
	existed, err := ormer.Engine.Get(&domain)
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

func UpdateDomain(id string, domain *Domain) (bool, error) {
	owner, name := util.GetOwnerAndNameFromIdNoCheck(id)
	oldDomain, err := getDomain(owner, name)
	if err != nil {
		return false, err
	}

	if oldDomain == nil {
		return false, nil
	}

	if name != domain.Name {
		err := domainChangeTrigger(name, domain.Name)
		if err != nil {
			return false, err
		}
	}

	oldDomainLinkedPermissions, err := subDomainPermissions(oldDomain)
	if err != nil {
		return false, fmt.Errorf("subRolePermissions: %w", err)
	}

	affected, err := ormer.Engine.ID(core.PK{owner, name}).AllCols().Update(domain)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		domainLinkedPermissions, err := subDomainPermissions(domain)
		if err != nil {
			return false, fmt.Errorf("subDomainPermissions: %w", err)
		}
		domainLinkedPermissions = append(domainLinkedPermissions, oldDomainLinkedPermissions...)
		err = processPolicyDifference(domainLinkedPermissions)
		if err != nil {
			return false, fmt.Errorf("processPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func AddDomain(domain *Domain) (bool, error) {
	affected, err := ormer.Engine.Insert(domain)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		domainLinkedPermissions, err := subDomainPermissions(domain)
		if err != nil {
			return false, fmt.Errorf("subDomainPermissions: %w", err)
		}

		err = processPolicyDifference(domainLinkedPermissions)
		if err != nil {
			return false, fmt.Errorf("processPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func DeleteDomain(domain *Domain) (bool, error) {
	domainId := domain.GetId()

	domainLinkedPermissions, err := subDomainPermissions(domain)
	if err != nil {
		return false, fmt.Errorf("subDomainPermissions: %w", err)
	}

	roles, err := GetRolesByDomain(domainId)
	if err != nil {
		return false, fmt.Errorf("GetRolesByDomain: %w", err)
	}

	for _, role := range roles {
		if Contains(role.Domains, domainId) {
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
		if Contains(permission.Domains, domainId) {
			permission.Domains = util.DeleteVal(permission.Domains, domainId)
			_, err := UpdatePermission(permission.GetId(), permission)
			if err != nil {
				return false, err
			}
		}
	}

	affected, err := ormer.Engine.ID(core.PK{domain.Owner, domain.Name}).Delete(&Domain{})
	if err != nil {
		return false, err
	}

	if affected != 0 {
		err = processPolicyDifference(domainLinkedPermissions)
		if err != nil {
			return false, fmt.Errorf("processPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func (domain *Domain) GetId() string {
	return fmt.Sprintf("%s/%s", domain.Owner, domain.Name)
}

func domainChangeTrigger(oldName string, newName string) error {
	session := ormer.Engine.NewSession()
	defer session.Close()

	err := session.Begin()
	if err != nil {
		return err
	}

	var roles []*Role
	err = ormer.Engine.Find(&roles)
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
	err = ormer.Engine.Find(&permissions)
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
func GetAncestorDomains(domainIds ...string) ([]*Domain, error) {
	var (
		result    = []*Domain{}
		domainMap = make(map[string]*Domain)
		visited   = make(map[string]bool)
	)
	if len(domainIds) == 0 {
		return result, nil
	}

	for _, domainId := range domainIds {
		visited[domainId] = true
	}

	owner, _ := util.GetOwnerAndNameFromIdNoCheck(domainIds[0])

	allDomains, err := GetDomains(owner)
	if err != nil {
		return nil, err
	}

	for _, r := range allDomains {
		domainMap[r.GetId()] = r
	}

	for _, r := range allDomains {
		isContain, ok := visited[r.GetId()]
		if isContain {
			result = append(result, r)
		} else if !ok {
			dId := r.GetId()
			visitedC := make(map[string]bool)
			for _, domainId := range domainIds {
				visitedC[domainId] = true
			}
			visited[dId] = containsDomain(r, domainMap, visitedC, domainIds...)
			if visited[dId] {
				result = append(result, r)
			}
		}
	}

	return result, nil
}

// containsDomain is a helper function to check if a domain is related to any domain in the given list domains
func containsDomain(domain *Domain, domainMap map[string]*Domain, visited map[string]bool, domainIds ...string) bool {
	domainId := domain.GetId()
	if isContain, ok := visited[domainId]; ok {
		return isContain
	}

	visited[domain.GetId()] = false

	for _, subDomain := range domain.Domains {
		if util.HasString(domainIds, subDomain) {
			return true
		}

		r, ok := domainMap[subDomain]
		if ok && containsDomain(r, domainMap, visited, domainIds...) {
			return true
		}
	}

	return false
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
