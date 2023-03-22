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

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

type Subscription struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(100) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`
	DisplayName string `xorm:"varchar(100)" json:"displayName"`
	Duration    int    `json:"expireInDays"`

	Detail      string `xorm:"varchar(255)" json:"detail"`
	Description string `xorm:"varchar(100)" json:"description"`
	Tag         string `xorm:"varchar(100)" json:"tag"`

	State string `xorm:"varchar(100)" json:"state"`
}

func GetSubscriptionCount(owner, field, value string) int {
	session := GetSession(owner, -1, -1, field, value, "", "")
	count, err := session.Count(&Subscription{})
	if err != nil {
		panic(err)
	}

	return int(count)
}

func GetSubscriptions(owner string) []*Subscription {
	subscriptions := []*Subscription{}
	err := adapter.Engine.Desc("created_time").Find(&subscriptions, &Subscription{Owner: owner})
	if err != nil {
		panic(err)
	}

	return subscriptions
}

func GetPaginationSubscriptions(owner string, offset, limit int, field, value, sortField, sortOrder string) []*Subscription {
	subscriptions := []*Subscription{}
	session := GetSession(owner, offset, limit, field, value, sortField, sortOrder)
	err := session.Find(&subscriptions)
	if err != nil {
		panic(err)
	}

	return subscriptions
}

func getSubscription(owner string, name string) *Subscription {
	if owner == "" || name == "" {
		return nil
	}

	subscription := Subscription{Owner: owner, Name: name}
	existed, err := adapter.Engine.Get(&subscription)
	if err != nil {
		panic(err)
	}

	if existed {
		return &subscription
	} else {
		return nil
	}
}

func GetSubscription(id string) *Subscription {
	owner, name := util.GetOwnerAndNameFromId(id)
	return getSubscription(owner, name)
}

func UpdateSubscription(id string, product *Subscription) bool {
	owner, name := util.GetOwnerAndNameFromId(id)
	if getProduct(owner, name) == nil {
		return false
	}

	affected, err := adapter.Engine.ID(core.PK{owner, name}).AllCols().Update(product)
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func AddSubscription(product *Subscription) bool {
	affected, err := adapter.Engine.Insert(product)
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func DeleteSubscription(product *Subscription) bool {
	affected, err := adapter.Engine.ID(core.PK{product.Owner, product.Name}).Delete(&Subscription{})
	if err != nil {
		panic(err)
	}

	return affected != 0
}

func (subscription *Subscription) GetId() string {
	return fmt.Sprintf("%s/%s", subscription.Owner, subscription.Name)
}
