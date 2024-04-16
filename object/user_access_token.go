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
	"errors"
	"fmt"

	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

func MakeTokenUserTag(user *User) string {
	return fmt.Sprintf("<access-token><access-token-user-id:%s>", user.Id)
}

func MakeTokenUserName(owner *User, accessKey string) string {
	return fmt.Sprintf("<AT:%s/%s>", owner.Id, accessKey)
}

func DeleteAccessToken(user *User, token string) (bool, error) {
	tag := fmt.Sprintf("<access-token><access-token-user-id:%s>", user.Id)

	token_user := &User{
		AccessSecret: token,
		Tag: tag,
	}

	affected, err := ormer.Engine.Delete(token_user)
	logs.Error(affected)

	return affected != 0, err
}

func RecreateAccessToken(tokenUser *User) error {
	affected, err := ormer.Engine.ID(core.PK{tokenUser.Owner, tokenUser.Name}).Cols("password_change_time").Update(tokenUser)
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("token not affected")
	}

	return nil
}

func GetAccessTokenUser(token_id string) (*User, error) {
	token_user := &User{
		AccessSecret: token_id,
	}

	present, err := ormer.Engine.Get(token_user)
	if err != nil {
		return nil, err
	}

	if !present {
		return nil, nil
	}

	return token_user, nil
}

type UserAccessToken struct {
	Owner string `json:"owner"`
	AccessToken string `json:"access_token"`
}

func MakeUserForToken(owner *User) *User {
	tokenUser := User{}
	accessKey := util.GenerateId()
	username := MakeTokenUserName(owner, accessKey)

	tokenUser = *owner
	tokenUser.Id = ""
	tokenUser.AccessKey = accessKey
	tokenUser.AccessSecret = util.GenerateId()
	tokenUser.Tag = MakeTokenUserTag(owner)
	tokenUser.Name = username
	tokenUser.DisplayName = username
	tokenUser.CreatedTime = util.GetCurrentTime()
	tokenUser.UpdatedTime = ""

	return &tokenUser
}

func MakeUserAccessToken(user *User) UserAccessToken {
	return UserAccessToken{
		Owner: user.Owner,
		AccessToken: user.AccessSecret,
	}
}
