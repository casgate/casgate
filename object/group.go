// Copyright 2023 The Casdoor Authors. All Rights Reserved.
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
	"errors"
	"fmt"
	"github.com/casdoor/casdoor/orm"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/builder"
	"github.com/xorm-io/core"
)

type Group struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk unique index" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	UpdatedTime string `xorm:"varchar(100)" json:"updatedTime"`

	DisplayName  string   `xorm:"varchar(100)" json:"displayName"`
	Manager      string   `xorm:"varchar(100)" json:"manager"`
	ContactEmail string   `xorm:"varchar(100)" json:"contactEmail"`
	Type         string   `xorm:"varchar(100)" json:"type"`
	ParentId     string   `xorm:"varchar(100)" json:"parentId"`
	IsTopGroup   bool     `xorm:"bool" json:"isTopGroup"`
	Tags         []string `xorm:"mediumtext" json:"tags"`
	Users        []*User  `xorm:"-" json:"users"`

	Title    string   `json:"title,omitempty"`
	Key      string   `json:"key,omitempty"`
	Children []*Group `json:"children,omitempty"`

	IsEnabled bool `json:"isEnabled"`
}

type GroupNode struct{}

func GetGroupCount(owner, field, value string) (int64, error) {
	session := orm.GetSession(owner, -1, -1, field, value, "", "")
	count, err := session.Count(&Group{})
	if err != nil {
		return 0, err
	}
	return count, nil
}

func GetGroups(owner string) ([]*Group, error) {
	groups := []*Group{}
	err := orm.AppOrmer.Engine.Desc("created_time").Find(&groups, &Group{Owner: owner})
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func GetPaginationGroups(owner string, offset, limit int, field, value, sortField, sortOrder string) ([]*Group, error) {
	groups := []*Group{}
	session := orm.GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&groups)
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func getGroup(owner string, name string) (*Group, error) {
	if owner == "" || name == "" {
		return nil, nil
	}

	group := Group{Owner: owner, Name: name}
	existed, err := orm.AppOrmer.Engine.Get(&group)
	if err != nil {
		return nil, err
	}

	if existed {
		return &group, nil
	} else {
		return nil, nil
	}
}

func GetGroup(id string) (*Group, error) {
	owner, name := util.GetOwnerAndNameFromId(id)
	return getGroup(owner, name)
}

func UpdateGroup(id string, group *Group) (bool, error) {
	owner, name := util.GetOwnerAndNameFromId(id)
	oldGroup, err := getGroup(owner, name)
	if oldGroup == nil {
		return false, err
	}

	err = checkGroupName(group.Name)
	if err != nil {
		return false, err
	}

	if name != group.Name {
		err := GroupChangeTrigger(util.GetId(owner, name), util.GetId(group.Owner, group.Name))
		if err != nil {
			return false, err
		}
	}

	oldGroupReachablePermissions, err := subGroupPermissions(oldGroup)
	if err != nil {
		return false, fmt.Errorf("subGroupPermissions: %w", err)
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{owner, name}).AllCols().Update(group)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		groupReachablePermissions, err := subGroupPermissions(group)
		if err != nil {
			return false, fmt.Errorf("subGroupPermissions: %w", err)
		}
		groupReachablePermissions = append(groupReachablePermissions, oldGroupReachablePermissions...)
		err = ProcessPolicyDifference(groupReachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func AddGroup(group *Group) (bool, error) {
	err := checkGroupName(group.Name)
	if err != nil {
		return false, err
	}

	affected, err := orm.AppOrmer.Engine.Insert(group)
	if err != nil {
		return false, err
	}

	if affected != 0 {
		domainReachablePermissions, err := subGroupPermissions(group)
		if err != nil {
			return false, fmt.Errorf("subGroupPermissions: %w", err)
		}

		err = ProcessPolicyDifference(domainReachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func AddGroups(groups []*Group) (bool, error) {
	if len(groups) == 0 {
		return false, nil
	}
	affected, err := orm.AppOrmer.Engine.Insert(groups)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

func DeleteGroup(group *Group) (bool, error) {
	_, err := orm.AppOrmer.Engine.Get(group)
	if err != nil {
		return false, err
	}

	if count, err := orm.AppOrmer.Engine.Where("parent_id = ?", group.Name).Count(&Group{}); err != nil {
		return false, err
	} else if count > 0 {
		return false, errors.New("group has children group")
	}

	if count, err := GetGroupUserCount(group.GetId(), "", ""); err != nil {
		return false, err
	} else if count > 0 {
		return false, errors.New("group has users")
	}

	if count, err := GetRoleCount(group.Owner, "`groups`", group.GetId()); err != nil {
		return false, err
	} else if count > 0 {
		return false, errors.New("group has linked roles")
	}

	if count, err := GetPermissionCount(group.Owner, "`groups`", group.GetId()); err != nil {
		return false, err
	} else if count > 0 {
		return false, errors.New("group has linked permissions")
	}

	groupReachablePermissions, err := subGroupPermissions(group)
	if err != nil {
		return false, fmt.Errorf("subGroupPermissions: %w", err)
	}

	affected, err := orm.AppOrmer.Engine.ID(core.PK{group.Owner, group.Name}).Delete(&Group{})
	if err != nil {
		return false, err
	}

	if affected != 0 {
		err = ProcessPolicyDifference(groupReachablePermissions)
		if err != nil {
			return false, fmt.Errorf("ProcessPolicyDifference: %w", err)
		}
	}

	return affected != 0, nil
}

func checkGroupName(name string) error {
	exist, err := orm.AppOrmer.Engine.Exist(&Organization{Owner: "admin", Name: name})
	if err != nil {
		return err
	}
	if exist {
		return errors.New("group name can't be same as the organization name")
	}
	return nil
}

func (group *Group) GetId() string {
	return fmt.Sprintf("%s/%s", group.Owner, group.Name)
}

func ConvertToTreeData(groups []*Group, parentId string) []*Group {
	treeData := []*Group{}

	for _, group := range groups {
		if group.ParentId == parentId {
			node := &Group{
				Title: group.DisplayName,
				Key:   group.Name,
				Type:  group.Type,
				Owner: group.Owner,
			}
			children := ConvertToTreeData(groups, group.Name)
			if len(children) > 0 {
				node.Children = children
			}
			treeData = append(treeData, node)
		}
	}
	return treeData
}

// GetAncestorGroups returns a list of groups that contain the given groupIds
func GetAncestorGroups(groupIds ...string) ([]*Group, error) {
	if len(groupIds) == 0 {
		return nil, nil
	}

	owner, _ := util.GetOwnerAndNameFromIdNoCheck(groupIds[0])

	allGroups, err := GetGroups(owner)
	if err != nil {
		return nil, err
	}

	allGroupsTree := makeAncestorGroupsTreeMap(allGroups)

	return getAncestorEntities(allGroupsTree, groupIds...)
}

func makeAncestorGroupsTreeMap(groups []*Group) map[string]*TreeNode[*Group] {
	var groupMap = make(map[string]*TreeNode[*Group], 0)

	for _, group := range groups {
		groupMap[group.GetId()] = &TreeNode[*Group]{
			ancestors: nil,
			value:     group,
			children:  nil,
		}
	}

	for _, group := range groups {
		if group.Owner != group.ParentId {
			parentId := util.GetId(group.Owner, group.ParentId)
			groupMap[parentId].children = append(groupMap[parentId].children, groupMap[group.GetId()])
			groupMap[group.GetId()].ancestors = append(groupMap[group.GetId()].children, groupMap[parentId])
		}
	}

	return groupMap
}

func GetGroupUserCount(groupId string, field, value string) (int64, error) {
	owner, _ := util.GetOwnerAndNameFromId(groupId)
	names, err := userEnforcer.GetUserNamesByGroupName(groupId)
	if err != nil {
		return 0, err
	}

	if field == "" && value == "" {
		return int64(len(names)), nil
	} else {
		return orm.AppOrmer.Engine.Table("user").
			Where("owner = ?", owner).In("name", names).
			And(builder.Like{util.CamelToSnakeCase(field), value}).
			Count()
	}
}

func GetPaginationGroupUsers(groupId string, offset, limit int, field, value, sortField, sortOrder string) ([]*User, error) {
	users := []*User{}
	owner, _ := util.GetOwnerAndNameFromId(groupId)
	names, err := userEnforcer.GetUserNamesByGroupName(groupId)
	if err != nil {
		return nil, err
	}

	session := orm.AppOrmer.Engine.Table("user").
		Where("owner = ?", owner).In("name", names)

	if offset != -1 && limit != -1 {
		session.Limit(limit, offset)
	}

	if field != "" && value != "" {
		session = session.And(builder.Like{util.CamelToSnakeCase(field), value})
	}

	if sortField == "" || sortOrder == "" {
		sortField = "created_time"
	}
	if sortOrder == "ascend" {
		session = session.Asc(util.SnakeString(sortField))
	} else {
		session = session.Desc(util.SnakeString(sortField))
	}

	err = session.Find(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func GetGroupUsers(groupId string) ([]*User, error) {
	users := []*User{}
	owner, _ := util.GetOwnerAndNameFromId(groupId)
	names, err := userEnforcer.GetUserNamesByGroupName(groupId)

	err = orm.AppOrmer.Engine.Where("owner = ?", owner).In("name", names).Find(&users)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func GroupChangeTrigger(oldName, newName string) error {
	session := orm.AppOrmer.Engine.NewSession()
	defer session.Close()
	err := session.Begin()
	if err != nil {
		return err
	}

	users := []*User{}
	err = session.Where(builder.Like{"`groups`", oldName}).Find(&users)
	if err != nil {
		return err
	}

	for _, user := range users {
		user.Groups = util.ReplaceVal(user.Groups, oldName, newName)
		_, err := updateUser(user.GetId(), user, []string{"groups"})
		if err != nil {
			return err
		}
	}

	groups := []*Group{}
	err = session.Where("parent_id = ?", oldName).Find(&groups)
	for _, group := range groups {
		group.ParentId = newName
		_, err := session.ID(core.PK{group.Owner, group.Name}).Cols("parent_id").Update(group)
		if err != nil {
			return err
		}
	}

	permissions := []*Permission{}
	err = session.Where(builder.Like{"`groups`", oldName}).Find(&permissions)
	if err != nil {
		return err
	}

	for _, permission := range permissions {
		permission.Groups = util.ReplaceVal(permission.Groups, oldName, newName)
		_, err := session.ID(core.PK{permission.Owner, permission.Name}).Cols("groups").Update(permission)
		if err != nil {
			return err
		}
	}

	roles := []*Role{}
	err = session.Where(builder.Like{"`groups`", oldName}).Find(&roles)
	if err != nil {
		return err
	}

	for _, role := range roles {
		role.Groups = util.ReplaceVal(role.Groups, oldName, newName)
		_, err := session.ID(core.PK{role.Owner, role.Name}).Cols("groups").Update(role)
		if err != nil {
			return err
		}
	}

	err = session.Commit()
	if err != nil {
		return err
	}
	return nil
}

func getGroupsInGroup(groupId string) ([]*Group, error) {
	group, err := GetGroup(groupId)
	if err != nil {
		return []*Group{}, err
	}

	if group == nil {
		return []*Group{}, nil
	}

	subGroups, err := getGroupsByParentGroup(groupId)
	groups := []*Group{group}

	for _, subGroup := range subGroups {
		r, err := getGroupsInGroup(subGroup.GetId())
		if err != nil {
			return []*Group{}, err
		}

		groups = append(groups, r...)
	}

	return groups, nil
}

func getGroupsByParentGroup(groupId string) ([]*Group, error) {
	owner, parentName := util.GetOwnerAndNameFromId(groupId)

	session := orm.AppOrmer.Engine.NewSession()
	defer session.Close()

	groups := []*Group{}
	err := session.Where("owner=? and parent_id = ?", owner, parentName).Find(&groups)
	if err != nil {
		return nil, err
	}

	return groups, nil
}

func subGroupPermissions(group *Group) ([]*Permission, error) {
	result := make([]*Permission, 0)

	subGroups, err := getGroupsInGroup(group.GetId())
	if err != nil {
		return nil, fmt.Errorf("getGroupsInGroup: %w", err)
	}
	for _, subGroup := range subGroups {
		permissions, err := GetPermissionsByGroup(subGroup.GetId())
		if err != nil {
			return nil, fmt.Errorf("GetPermissionsByGroup: %w", err)
		}
		if len(permissions) > 0 {
			result = append(result, permissions...)
		}

		groupRoles, err := GetPaginationRoles(group.Owner, -1, -1, "`groups`", subGroup.GetId(), "", "")
		if err != nil {
			return nil, fmt.Errorf("GetPaginationRoles: %w", err)
		}

		for _, role := range groupRoles {
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
