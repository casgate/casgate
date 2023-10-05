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
)

type PolicyBuilder struct {
	entities *Entities
}

func NewPolicyBuilder(owner, model string) (*PolicyBuilder, error) {
	entities, err := getOwnerEntities(owner, model)
	if err != nil {
		return nil, fmt.Errorf("getOwnerEntities: %w", err)
	}

	return &PolicyBuilder{
		entities: entities,
	}, nil
}

func (pb *PolicyBuilder) CalcPermissionPolicies(permission *Permission) ([]casbinPolicy, error) {
	policyPermissions, err := pb.calcPermissionPolicies(permission)

	strPolicies, err := pb.generatePolicies(policyPermissions, permission)
	if err != nil {
		return nil, fmt.Errorf("generatePolicies: %w", err)
	}

	return strPolicies, nil
}

func (pb *PolicyBuilder) calcPermissionPolicies(permission *Permission) ([]policyPermission, error) {
	policyRoles, err := calcEntityPolicies[*Role, policyRole](pb, pb.entities.RolesTree, permission.Roles...)
	if err != nil {
		return nil, fmt.Errorf("calcEntityPolicies[Roles]: %w", err)
	}

	policyGroups, err := calcEntityPolicies[*Group, policyGroup](pb, pb.entities.GroupsTree, permission.Groups...)
	if err != nil {
		return nil, fmt.Errorf("calcEntityPolicies[Groups]: %w", err)
	}

	policyDomains, err := calcEntityPolicies[*Domain, policyDomain](pb, pb.entities.DomainsTree, permission.Domains...)
	if err != nil {
		return nil, fmt.Errorf("calcEntityPolicies[Domains]: %w", err)
	}

	policyPermissions := joinEntitiesWithPermission(permission, policyRoles, policyGroups, policyDomains)

	return policyPermissions, nil
}

func (pb *PolicyBuilder) calcRolePolicies(role *Role) ([]policyRole, error) {
	policyGroups, err := calcEntityPolicies[*Group, policyGroup](pb, pb.entities.GroupsTree, role.Groups...)
	if err != nil {
		return nil, fmt.Errorf("calcEntityPolicies[Groups]: %w", err)
	}
	policyDomains, err := calcEntityPolicies[*Domain, policyDomain](pb, pb.entities.DomainsTree, role.Domains...)
	if err != nil {
		return nil, fmt.Errorf("calcEntityPolicies[Domains]: %w", err)
	}

	policyRoles := joinEntitiesWithRole(role, policyGroups, policyDomains)

	return policyRoles, nil
}

func (pb *PolicyBuilder) calcDomainPolicies(domain *Domain) ([]policyDomain, error) {
	policyDomains := make([]policyDomain, 0, 1)
	policyDomains = append(policyDomains, policyDomain{
		id:   domain.GetId(),
		name: domain.GetId(),
	})
	for _, subdomainId := range domain.Domains {
		policyDomains = append(policyDomains, policyDomain{
			id:        domain.GetId(),
			name:      domain.GetId(),
			subDomain: subdomainId,
		})
	}

	return policyDomains, nil
}

func (pb *PolicyBuilder) calcGroupPolicies(group *Group) ([]policyGroup, error) {
	policyGroups := make([]policyGroup, 0, 1)
	users := pb.entities.UsersByGroup[group.GetId()]

	var parentId string
	if group.Owner != group.ParentId {
		parentId = util.GetId(group.Owner, group.ParentId)
	}
	policyGroups = append(policyGroups, policyGroup{
		id:          group.GetId(),
		name:        group.GetId(),
		parentGroup: parentId,
	})

	for _, user := range users {
		policyGroups = append(policyGroups, policyGroup{
			id:          group.GetId(),
			name:        group.GetId(),
			parentGroup: parentId,
			user:        user.GetId(),
		})
	}

	return policyGroups, nil
}

func (pb *PolicyBuilder) generatePolicies(policyPermissions []policyPermission, permission *Permission) ([]casbinPolicy, error) {
	policies := make([]casbinPolicy, 0)

	policyRules := getPolicyMappingRules(pb.entities.Model, permission)

	for _, policyPermissionItem := range policyPermissions {
	PolicyLoop:
		for _, policyRule := range policyRules {
			policyType := policyRule[0]
			var policyRow casbinPolicy
			policyRow[0] = policyType
			for i, policyItem := range policyRule[1:] {
				policyRowItem, found := getValueByItem(policyPermissionItem, policyItem)
				if !found {
					continue PolicyLoop
				}
				policyRow[i+1] = policyRowItem
			}
			policyRow[6] = policyPermissionItem.id

			policies = append(policies, policyRow)
		}
	}

	return policies, nil
}
