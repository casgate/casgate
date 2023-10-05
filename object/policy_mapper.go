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

type groupedPolicy struct {
	g            casbinPolicies
	p            casbinPolicies
	permissionID string
}

func ProcessPolicyDifference(sourcePermissions []*Permission) error {
	if len(sourcePermissions) == 0 {
		return nil
	}

	modelProcessed := make(map[string]bool)

	for _, permission := range sourcePermissions {
		modelAdapterKey := util.GetId(permission.Owner, permission.Model) + permission.Adapter
		if !modelProcessed[modelAdapterKey] {
			owner := permission.Owner

			permissions, err := GetPermissionsByModel(owner, permission.Model)
			if err != nil {
				return fmt.Errorf("GetPermissionsByModel: %w", err)
			}

			oldPolicies := make(casbinPolicies, 0)

			modelPolicies, err := getPermissionPolicies(permissions)
			if err != nil {
				return fmt.Errorf("getPermissionPolicies: %w", err)
			}
			oldPolicies = append(oldPolicies, modelPolicies...)

			permissionMap := make(map[string]*Permission, len(permissions))
			newPolicies := make(casbinPolicies, 0)

			ctx := context.Background()
			g, ctx := errgroup.WithContext(ctx)
			resultPolicies := make([]casbinPolicies, len(permissions))

			pb, err := NewPolicyBuilder(owner, permission.Model)
			if err != nil {
				return fmt.Errorf("NewPolicyBuilder: %w", err)
			}

			// disable gc for calcPolicies time and enable back after for optimization. (up to 10x faster)
			gcpercent := debug.SetGCPercent(-1)
			memlimit := debug.SetMemoryLimit(math.MaxInt64)

			for i, permission := range permissions {
				i, permission := i, permission
				g.Go(func() error {
					policies, err := pb.CalcPermissionPolicies(permission)
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
			oldPoliciesToRemove := make(casbinPolicies, 0, len(oldPolicies))
			for _, policy := range oldPolicies {
				key := getPolicyKeyWithPermissionID(policy)
				if newPoliciesHash[key] {
					oldPoliciesHash[getPolicyKey(policy)] = true
				} else {
					oldPoliciesToRemove = append(oldPoliciesToRemove, policy)
				}
			}

			newPoliciesToCreate := make(casbinPolicies, 0, len(oldPolicies))
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

// getPermissionPolicies get policies from db by permissions with same model
func getPermissionPolicies(permissions []*Permission) (casbinPolicies, error) {
	if len(permissions) == 0 {
		return nil, nil
	}

	permissionIds := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		permissionIds = append(permissionIds, permission.GetId())
	}
	enforcer := getPermissionEnforcer(permissions[0], permissionIds...)
	enforcer.GetPolicy()

	result := make(casbinPolicies, 0)
	for _, policy := range enforcer.GetNamedPolicy("p") {
		var casbinPolicy casbinPolicy
		casbinPolicy[0] = "p"
		for i, policyItem := range policy {
			casbinPolicy[i+1] = policyItem
		}
		result = append(result, casbinPolicy)
	}

	model := enforcer.GetModel()
	for gType := range model["g"] {
		for _, policy := range enforcer.GetNamedGroupingPolicy(gType) {
			var casbinPolicy casbinPolicy
			casbinPolicy[0] = gType
			for i, policyItem := range policy {
				casbinPolicy[i+1] = policyItem
			}
			result = append(result, casbinPolicy)
		}
	}

	return result, nil
}

func groupPolicies(policies casbinPolicies, permissionMap map[string]*Permission) (map[string]groupedPolicy, error) {
	groupedPolicies := make(map[string]groupedPolicy, len(policies))
	for _, policy := range policies {
		permission := permissionMap[policy[6]]
		modelAdapterKey := util.GetId(permission.Owner, permission.Model) + permission.Adapter
		if _, ok := groupedPolicies[modelAdapterKey]; !ok {
			groupedPolicies[modelAdapterKey] = groupedPolicy{g: make(casbinPolicies, 0), p: make(casbinPolicies, 0), permissionID: permission.GetId()}
		}

		temp := groupedPolicies[modelAdapterKey]
		switch policy[0][0] {
		case 'p':
			temp.p = append(groupedPolicies[modelAdapterKey].p, policy)
		case 'g':
			temp.g = append(groupedPolicies[modelAdapterKey].g, policy)
		default:
			return nil, fmt.Errorf("wrong policy type")
		}
		groupedPolicies[modelAdapterKey] = temp
	}
	return groupedPolicies, nil
}

func removePolicies(policies casbinPolicies, permissionMap map[string]*Permission) error {
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

func createPolicies(policies casbinPolicies, permissionMap map[string]*Permission) error {
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

func getPolicyKey(policy casbinPolicy) string {
	return strings.Join(policy[:6], "_")
}

func getPolicyKeyWithPermissionID(policy casbinPolicy) string {
	return strings.Join(policy[:7], "_")
}
