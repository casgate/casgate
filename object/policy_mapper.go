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
	"math"
	"runtime/debug"
	"strings"

	"github.com/casdoor/casdoor/util"
	"golang.org/x/sync/errgroup"
)

type policyDomain struct {
	id        string
	name      string
	subDomain string
}

type policyGroup struct {
	id          string
	name        string
	parentGroup string
	user        string
}

type policyRole struct {
	id      string
	name    string
	domain  policyDomain
	user    string
	group   policyGroup
	subRole string

	empty bool
}

type policyPermission struct {
	id       string
	domain   policyDomain
	resource string
	action   string
	role     policyRole
	user     string
	group    policyGroup
	effect   string

	empty bool
}

func getValueByItem(policyPermissionItem policyPermission, policyItem string) (string, bool) {
	if policyItem == "" {
		return policyItem, true
	}

	if policyItem[:5] == "const" {
		return policyItem[6:], true
	}

	var value string

	switch policyItem {
	case "role.name":
		value = policyPermissionItem.role.name
	case "role.subrole":
		value = policyPermissionItem.role.subRole
	case "role.domain.name":
		value = policyPermissionItem.role.domain.name
	case "role.domain.subdomain":
		value = policyPermissionItem.role.domain.subDomain
	case "role.user":
		value = policyPermissionItem.role.user
	case "role.group.name":
		value = policyPermissionItem.role.group.name
	case "role.group.parentgroup":
		value = policyPermissionItem.role.group.parentGroup
	case "role.group.user":
		value = policyPermissionItem.role.group.user
	case "permission.action":
		value = policyPermissionItem.action
	case "permission.resource":
		value = policyPermissionItem.resource
	case "permission.user":
		value = policyPermissionItem.user
	case "permission.effect":
		value = policyPermissionItem.effect
	case "permission.domain.name":
		value = policyPermissionItem.domain.name
	case "permission.domain.subdomain":
		value = policyPermissionItem.domain.subDomain
	case "permission.group.name":
		value = policyPermissionItem.group.name
	case "permission.group.parentgroup":
		value = policyPermissionItem.group.parentGroup
	case "permission.group.user":
		value = policyPermissionItem.group.user
	}

	if value == "" {
		return value, false
	}

	return value, true
}

func refillWithEmptyStrings(row []string) []string {
	for len(row) < 7 {
		row = append(row, "")
	}
	return row
}

func generatePolicies(policyPermissions []policyPermission, permission *Permission, permissionModel *Model) ([][]string, error) {
	policies := make([][]string, 0)

	policyRules := permissionModel.policyMappingRules(len(permission.Domains) > 0)

	for _, policyPermissionItem := range policyPermissions {
	PolicyLoop:
		for _, policyRule := range policyRules {
			policyType := policyRule[0]
			policyRow := make([]string, 0, len(policyRule)-1)
			policyRow = append(policyRow, policyType)
			for _, policyItem := range policyRule[1:] {
				policyRowItem, found := getValueByItem(policyPermissionItem, policyItem)
				if !found {
					continue PolicyLoop
				}
				policyRow = append(policyRow, policyRowItem)
			}
			policyRow = refillWithEmptyStrings(policyRow)
			policyRow[6] = policyPermissionItem.id

			policies = append(policies, policyRow)
		}
	}

	return policies, nil
}

func Contains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

type groupedPolicy struct {
	g            [][]string
	p            [][]string
	permissionID string
}

func groupPolicies(policies [][]string, permissionMap map[string]*Permission) (map[string]groupedPolicy, error) {
	groupedPolicies := make(map[string]groupedPolicy, len(policies))
	for _, policy := range policies {
		permission := permissionMap[policy[6]]
		modelAdapterKey := util.GetId(permission.Owner, permission.Model) + permission.Adapter
		if _, ok := groupedPolicies[modelAdapterKey]; !ok {
			groupedPolicies[modelAdapterKey] = groupedPolicy{g: make([][]string, 0), p: make([][]string, 0), permissionID: permission.GetId()}
		}
		switch policy[0][0] {
		case 'p':
			temp := groupedPolicies[modelAdapterKey]
			temp.p = append(groupedPolicies[modelAdapterKey].p, policy)
			groupedPolicies[modelAdapterKey] = temp
		case 'g':
			temp := groupedPolicies[modelAdapterKey]
			temp.g = append(groupedPolicies[modelAdapterKey].g, policy)
			groupedPolicies[modelAdapterKey] = temp
		default:
			return nil, fmt.Errorf("wrong policy type")
		}
	}
	return groupedPolicies, nil
}

func removePolicies(policies [][]string, permissionMap map[string]*Permission) error {
	if len(policies) == 0 {
		return nil
	}

	groupedPolicies, err := groupPolicies(policies, permissionMap)
	if err != nil {
		return fmt.Errorf("groupPolicies: %w", err)
	}

	for _, groupedPolicy := range groupedPolicies {
		enforcer := getPermissionEnforcer(permissionMap[groupedPolicy.permissionID])

		for _, policy := range groupedPolicy.p {
			if _, ok := enforcer.GetModel()["p"][policy[0]]; ok {
				enforcer.RemoveNamedPolicy(policy[0], policy[1:])
			}
		}

		for _, policy := range groupedPolicy.g {
			if _, ok := enforcer.GetModel()["g"][policy[0]]; ok {
				enforcer.RemoveNamedGroupingPolicy(policy[0], policy[1:])
			}
		}
	}

	return nil
}

func createPolicies(policies [][]string, permissionMap map[string]*Permission) error {
	if len(policies) == 0 {
		return nil
	}

	groupedPolicies, err := groupPolicies(policies, permissionMap)
	if err != nil {
		return fmt.Errorf("groupPolicies: %w", err)
	}

	created := make(map[string]bool, len(policies))
	for _, groupedPolicy := range groupedPolicies {
		enforcer := getPermissionEnforcer(permissionMap[groupedPolicy.permissionID])

		for _, policy := range groupedPolicy.p {
			key := getPolicyKey(policy)
			if !created[key] {
				enforcer.AddNamedPolicy(policy[0], policy[1:])
				created[key] = true
			}
		}

		for _, policy := range groupedPolicy.g {
			key := getPolicyKey(policy)
			if !created[key] {
				enforcer.AddNamedGroupingPolicy(policy[0], policy[1:])
				created[key] = true
			}
		}
	}

	return nil
}

type Entities struct {
	DomainsTree  map[string]*DomainTreeNode
	RolesTree    map[string]*RoleTreeNode
	GroupsTree   map[string]*GroupTreeNode
	UsersByGroup map[string][]*User
	Model        *Model
}

func processPolicyDifference(sourcePermissions []*Permission) error {
	if len(sourcePermissions) == 0 {
		return nil
	}

	modelProcessed := make(map[string]bool)

	for _, permission := range sourcePermissions {
		modelAdapterKey := util.GetId(permission.Owner, permission.Model) + permission.Adapter
		if !modelProcessed[modelAdapterKey] {
			permissions, err := GetPermissionsByModel(permission.Owner, permission.Model)
			if err != nil {
				return fmt.Errorf("GetPermissionsByModel: %w", err)
			}

			oldPolicies := make([][]string, 0)

			modelPolicies, err := getPermissionPolicies(permissions)
			if err != nil {
				return fmt.Errorf("getPermissionPolicies: %w", err)
			}
			oldPolicies = append(oldPolicies, modelPolicies...)

			permissionMap := make(map[string]*Permission, len(permissions))
			newPolicies := make([][]string, 0)

			owner := permission.Owner
			var ownerEntities Entities
			ownerDomains, err := GetDomains(owner)
			if err != nil {
				return fmt.Errorf("GetDomains: %w", err)
			}
			ownerRoles, err := GetRoles(owner)
			if err != nil {
				return fmt.Errorf("GetRoles: %w", err)
			}
			ownerGroups, err := GetGroups(owner)
			if err != nil {
				return fmt.Errorf("GetGroups: %w", err)
			}
			ownerUsers, err := GetUsers(owner)
			if err != nil {
				return fmt.Errorf("GetUsers: %w", err)
			}
			permissionModel, err := getModel(permission.Owner, permission.Model)
			if err != nil {
				return fmt.Errorf("getModel: %w", err)
			}
			ownerEntities.DomainsTree = makeAncestorDomainsTreeMap(ownerDomains)
			ownerEntities.RolesTree = makeAncestorRolesTreeMap(ownerRoles)
			ownerEntities.GroupsTree = makeAncestorGroupsTreeMap(ownerGroups)
			ownerEntities.UsersByGroup = groupUsersByGroups(ownerUsers)
			ownerEntities.Model = permissionModel

			ctx := context.Background()
			g, ctx := errgroup.WithContext(ctx)
			resultPolicies := make([][][]string, len(permissions))

			// disable gc for calcPolicies time and enable back after for optimization. (up to 10x faster)
			gcpercent := debug.SetGCPercent(-1)
			memlimit := debug.SetMemoryLimit(math.MaxInt64)

			for i, permission := range permissions {
				i, permission := i, permission
				g.Go(func() error {
					policies, err := calcPermissionPolicies(permission, ownerEntities)
					if err != nil {
						return fmt.Errorf("calcPermissionPolicies: %w", err)
					}
					resultPolicies[i] = policies
					return nil
				})

				permissionMap[permission.GetId()] = permission
			}

			if err := g.Wait(); err != nil {
				return fmt.Errorf("g.Wait: %w", err)
			}

			for _, policies := range resultPolicies {
				newPolicies = append(newPolicies, policies...)
			}

			debug.SetGCPercent(gcpercent)
			debug.SetMemoryLimit(memlimit)

			newPoliciesHash := make(map[string]bool, len(newPolicies))
			for _, policy := range newPolicies {
				key := getPolicyKeyWithPermissionID(policy)
				newPoliciesHash[key] = true
			}

			oldPoliciesHash := make(map[string]bool, len(oldPolicies))
			oldPoliciesToRemove := make([][]string, 0, len(oldPolicies))
			for _, policy := range oldPolicies {
				key := getPolicyKeyWithPermissionID(policy)
				if newPoliciesHash[key] {
					oldPoliciesHash[getPolicyKey(policy)] = true
				} else {
					oldPoliciesToRemove = append(oldPoliciesToRemove, policy)
				}
			}

			newPoliciesToCreate := make([][]string, 0, len(oldPolicies))
			for _, policy := range newPolicies {
				key := getPolicyKey(policy)
				if !oldPoliciesHash[key] {
					newPoliciesToCreate = append(newPoliciesToCreate, policy)
				}
			}

			err = removePolicies(oldPoliciesToRemove, permissionMap)
			if err != nil {
				return fmt.Errorf("removePolicy: %w", err)
			}

			err = createPolicies(newPoliciesToCreate, permissionMap)
			if err != nil {
				return fmt.Errorf("createPolicy: %w", err)
			}

			modelProcessed[modelAdapterKey] = true
		}
	}

	return nil
}

func getPolicyKey(policy []string) string {
	return strings.Join(policy[:6], "_")
}

func getPolicyKeyWithPermissionID(policy []string) string {
	return strings.Join(policy[:7], "_")
}
