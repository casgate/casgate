// Copyright 2024 The Casdoor Authors. All Rights Reserved.
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
	"regexp"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

const (
	TokenUser = "token-user"
)

var (
	tagExtractionRegexp   = regexp.MustCompile("<access-token><access-token-user-id:(.+)>")
	tokenValidationRegexp = `^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`

	ExtractOwnerIdError = errors.New("could not extract owner id from tag")
)

func MakeTokenUserTag(user *User) string {
	return fmt.Sprintf("<access-token><access-token-user-id:%s>", user.Id)
}

func ExtractOwnerIdFromTag(tag string) (string, error) {
	res := tagExtractionRegexp.FindStringSubmatch(tag)
	if res == nil {
		return "", ExtractOwnerIdError
	}

	return res[1], nil
}

func MakeTokenUserName(owner *User, accessKey, accessSecret string) string {
	return fmt.Sprintf("<AT:%s/%s>", owner.Id, util.GenerateId())
}

func separateTokenToKeys(token string) (string, string) {
	accessKey := string([]byte(token)[:36])
	accessSecret := string([]byte(token)[36:])

	return accessKey, accessSecret
}

func DeleteApiToken(user *User, token string) (bool, error) {
	tag := fmt.Sprintf("<access-token><access-token-user-id:%s>", user.Id)

	accessKey, accessSecret := separateTokenToKeys(token)

	token_user := &User{
		AccessKey:    accessKey,
		AccessSecret: accessSecret,
		Tag:          tag,
	}

	affected, err := orm.AppOrmer.Engine.Delete(token_user)

	return affected != 0, err
}

func RecreateApiToken(tokenOwner, tokenUser *User) error {
	tokenUser.AccessKey = util.GenerateId()
	tokenUser.AccessSecret = util.GenerateId()

	affected, err := orm.AppOrmer.Engine.ID(core.PK{tokenUser.Owner, tokenUser.Name}).Update(tokenUser)
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("token not affected")
	}

	return nil
}

func GetApiKeyUser(token string) (*User, error) {
	accessKey, accessSecret := separateTokenToKeys(token)

	token_user := &User{
		AccessKey:    accessKey,
		AccessSecret: accessSecret,
	}

	present, err := orm.AppOrmer.Engine.Get(token_user)
	if err != nil {
		return nil, err
	}

	if !present {
		return nil, nil
	}

	return token_user, nil
}

func GetApiKeyOwner(token string) (*User, error) {
	apiKeyUser, err := GetApiKeyUser(token)
	if err != nil || apiKeyUser == nil {
		return apiKeyUser, err
	}

	ownerId, err := ExtractOwnerIdFromTag(apiKeyUser.Tag)
	if err != nil {
		return nil, err
	}

	owner := &User{
		Id: ownerId,
	}

	present, err := orm.AppOrmer.Engine.Get(owner)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, nil
	}

	return owner, nil
}

type UserApiToken struct {
	Owner    string `json:"owner"`
	ApiToken string `json:"api_token"`
}

func MakeUserForToken(owner *User) *User {
	tokenUser := User{}
	accessKey := util.GenerateId()
	accessSecret := util.GenerateId()

	tokenUser = *owner
	tokenUser.Id = ""
	tokenUser.AccessKey = accessKey
	tokenUser.AccessSecret = accessSecret
	tokenUser.Tag = MakeTokenUserTag(owner)
	tokenUser.Name = MakeTokenUserName(owner, accessKey, accessSecret)
	tokenUser.DisplayName = "<API-TOKEN>"
	tokenUser.CreatedTime = util.GetCurrentTime()
	tokenUser.UpdatedTime = ""
	tokenUser.Type = TokenUser

	return &tokenUser
}

func MakeUserApiToken(user *User) UserApiToken {
	return UserApiToken{
		Owner:    user.Owner,
		ApiToken: user.AccessKey + user.AccessSecret,
	}
}

func GetUserTokens(user *User) ([]User, error) {
	var tokens []User

	tagPattern := fmt.Sprintf("<access-token><access-token-user-id:%s>", user.Id)

	err := orm.AppOrmer.Engine.Where("tag LIKE ?", tagPattern).Find(&tokens)
	if err != nil {
		return nil, err
	}

	return tokens, nil
}

func ValidateToken(token string) bool {
	matched, err := regexp.MatchString(tokenValidationRegexp, token)
	if err != nil {
		fmt.Println("Ошибка при проверке токена:", err)
		return false
	}
	return matched
}
