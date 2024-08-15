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

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/casdoor/casdoor/util/logger"

	"github.com/beego/beego/utils/pagination"
	"github.com/pkg/errors"

	"github.com/casdoor/casdoor/ldap_sync"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

type LdapResp struct {
	// Groups []LdapRespGroup `json:"groups"`
	Users      []object.LdapUser `json:"users"`
	ExistUuids []string          `json:"existUuids"`
}

//type LdapRespGroup struct {
//	GroupId   string
//	GroupName string
//}

type LdapSyncResp struct {
	Exist  []object.LdapUser `json:"exist"`
	Failed []object.LdapUser `json:"failed"`
}

type LdapIdWithNameResp struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type SyncLdapUsersRequest struct {
	Id string
}

const ldapSyncMinIntervalMinutes = 15

// GetLdapUsers
// @Title GetLdapser
// @Tag Account API
// @Description get ldap users
// Param	id	string	true	"id"
// @Success 200 {object} LdapResp The Response object
// @router /get-ldap-users [get]
func (c *ApiController) GetLdapUsers() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	gCtx := c.getRequestCtx()
	record := object.GetRecord(gCtx)
	ldapId := c.Input().Get("ldapId")

	if ldapId == "" {
		c.ResponseBadRequest("ldapId is required")
	}

	ldapServer, err := object.GetLdap(ldapId)
	if err != nil {
		err = errors.Wrap(err, "Get LDAP")
		logger.Error(gCtx, err.Error())
		record.AddReason(err.Error())
		c.ResponseError(err.Error())
		return
	}

	conn, err := ldapServer.GetLdapConn(context.Background())
	if err != nil {
		err = errors.Wrap(err, "Get LDAP connection")
		logger.Error(gCtx, err.Error())
		record.AddReason(err.Error())
		c.ResponseError(err.Error())
		return
	}

	users, err := conn.GetLdapUsers(ldapServer, nil, record)
	if err != nil {
		err = errors.Wrap(err, "Get LDAP users")
		logger.Error(gCtx, err.Error())
		record.AddReason(err.Error())
		c.ResponseError(err.Error())
		return
	}

	uuids := make([]string, len(users))
	for i, user := range users {
		uuids[i] = user.GetLdapUuid()
	}
	existUuids, err := object.GetExistUuids(ldapServer.Owner, uuids)
	if err != nil {
		err = errors.Wrap(err, "Find existed LDAP users")
		logger.Error(gCtx, err.Error())
		record.AddReason(err.Error())
		c.ResponseError(err.Error())
		return
	}

	resp := LdapResp{
		Users:      object.AutoAdjustLdapUser(users),
		ExistUuids: existUuids,
	}
	c.ResponseOk(resp)
}

// GetLdaps
// @Title GetLdaps
// @Tag Account API
// @Description get ldaps
// @Param	owner	query	string	false	"owner"
// @Success 200 {array} object.Ldap The Response object
// @router /get-ldaps [get]
func (c *ApiController) GetLdaps() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	owner := c.Input().Get("owner")

	c.ResponseOk(object.GetMaskedLdaps(object.GetLdaps(owner)))
}

// GetLdapServerNames
// @Title GetLdapServerNames
// @Tag Account API
// @Description get ldaps
// @Param	owner	query	string	false	"owner"
// @Success 200 {array} LdapIdWithNameResp The Response object
// @router /get-ldap-server-names [get]
func (c *ApiController) GetLdapServerNames() {
	owner := c.Input().Get("owner")

	ldaps, err := object.GetLdaps(owner)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	var namesWithId []LdapIdWithNameResp
	for _, ldap := range ldaps {
		namesWithId = append(namesWithId, LdapIdWithNameResp{
			Id:   ldap.Id,
			Name: ldap.ServerName,
		})
	}

	c.ResponseOk(namesWithId)
}

// GetLdap
// @Title GetLdap
// @Tag Account API
// @Description get ldap
// @Param	id	query	string	true	"id"
// @Success 200 {object} object.Ldap The Response object
// @router /get-ldap [get]
func (c *ApiController) GetLdap() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	ldapId := c.Input().Get("ldapId")

	if util.IsStringsEmpty(ldapId) {
		c.ResponseError(c.T("general:Missing parameter"))
		return
	}

	ldap, err := object.GetLdap(ldapId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if ldap == nil {
		c.ResponseOk()
		return
	}

	c.ValidateOrganization(ldap.Owner)
	c.ResponseOk(object.GetMaskedLdap(ldap))
}

// AddLdap
// @Title AddLdap
// @Tag Account API
// @Description add ldap
// @Param	body	body	object.Ldap		true	"The details of the ldap"
// @Success 200 {object} controllers.Response The Response object
// @router /add-ldap [post]
func (c *ApiController) AddLdap() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	gCtx := c.getRequestCtx()
	record := object.GetRecord(gCtx)

	var ldap object.Ldap
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &ldap)
	if err != nil {
		record.AddReason(fmt.Sprintf("Unmarshall: %v", err.Error()))

		c.ResponseError(err.Error())
		return
	}

	anyRequiredLdapFieldEmpty := util.IsStringsEmpty(ldap.Owner, ldap.ServerName, ldap.Host, ldap.BaseDn)
	enabledCryptoAndEmptyCert := ldap.EnableCryptographicAuth && ldap.ClientCert == ""
	disabledCryptoAndEmptyCred := !ldap.EnableCryptographicAuth && util.IsStringsEmpty(ldap.Username, ldap.Password)

	var msg string
	if anyRequiredLdapFieldEmpty {
		msg = c.T("general:Missing required parameter")
	} else if enabledCryptoAndEmptyCert {
		msg = c.T("general:Missing certificate")
	} else if disabledCryptoAndEmptyCred {
		msg = c.T("general:Missing administrator credentials")
	} else if ldap.AutoSync != 0 && ldap.AutoSync < ldapSyncMinIntervalMinutes {
		msg = c.T("general:Ldap sync interval can't be less than 15 minutes")
	}

	if msg != "" {
		record.AddReason(msg)
		c.ResponseError(msg)
		return
	}

	if len(ldap.Id) == 0 {
		ldap.Id = util.GenerateId()
	}

	if ok, err := object.CheckLdapExist(&ldap); err != nil {
		record.AddReason(fmt.Sprintf("Check LDAP exists: %v", err.Error()))

		c.ResponseError(err.Error())
		return
	} else if ok {
		msg := c.T("ldap:Ldap server exist")
		record.AddReason(msg)

		c.ResponseError(msg)
		return
	}

	resp := wrapActionResponse(object.AddLdap(&ldap))
	resp.Data2 = ldap

	if ldap.AutoSync != 0 {
		// Create new context to use in background operation,
		// because request context may timeout or be cancelled by framework code.
		err = object.GetLdapSynchronizationManager().StartAutoSync(context.Background(), ldap.Id, time.Duration(ldap.AutoSync)*time.Minute, record)
		if err != nil {
			record.AddReason(fmt.Sprintf("Get LDAP syncronizer error: %v", err.Error()))

			c.ResponseError(err.Error())
			return
		}
	}

	c.Data["json"] = resp
	c.ServeJSON()
}

// UpdateLdap
// @Title UpdateLdap
// @Tag Account API
// @Description update ldap
// @Param	body	body	object.Ldap		true	"The details of the ldap"
// @Success 200 {object} controllers.Response The Response object
// @router /update-ldap [post]
func (c *ApiController) UpdateLdap() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	gCtx := c.getRequestCtx()
	record := object.GetRecord(gCtx)

	var ldap object.Ldap
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &ldap)

	anyRequiredLdapFieldEmpty := util.IsStringsEmpty(ldap.Owner, ldap.ServerName, ldap.Host, ldap.BaseDn)
	enabledCryptoAndEmptyCert := ldap.EnableCryptographicAuth && ldap.ClientCert == ""
	disabledCryptoAndEmptyCred := !ldap.EnableCryptographicAuth && util.IsStringsEmpty(ldap.Username, ldap.Password)

	var msg string
	if anyRequiredLdapFieldEmpty {
		msg = c.T("general:Missing required parameter")
	} else if enabledCryptoAndEmptyCert {
		msg = c.T("general:Missing client certificate")
	} else if disabledCryptoAndEmptyCred {
		msg = c.T("general:Missing administrator credentials")
	} else if ldap.AutoSync != 0 && ldap.AutoSync < ldapSyncMinIntervalMinutes {
		msg = c.T("general:Ldap sync interval can't be less than 15 minutes")
	}

	if msg != "" {
		record.AddReason(msg)
		c.ResponseError(msg)
		return
	}

	for _, roleMappingItem := range ldap.RoleMappingItems {
		if util.IsStringsEmpty(roleMappingItem.Attribute, roleMappingItem.Role) || len(roleMappingItem.Values) == 0 {
			msg := c.T("general:Missing parameter")
			record.AddReason(msg)

			c.ResponseError(msg)
			return
		}
	}

	prevLdap, err := object.GetLdap(ldap.Id)
	if err != nil {
		record.AddReason(fmt.Sprintf("Get LDAP: %v", err.Error()))

		c.ResponseError(err.Error())
		return
	}

	affected, err := object.UpdateLdap(&ldap)
	if err != nil {
		record.AddReason(fmt.Sprintf("Update LDAP: %v", err.Error()))

		c.ResponseError(err.Error())
		return
	}

	if ldap.AutoSync != 0 {
		err := object.GetLdapSynchronizationManager().StartAutoSync(gCtx, ldap.Id, time.Duration(ldap.AutoSync)*time.Minute, record)
		if err != nil {
			record.AddReason(fmt.Sprintf("Get LDAP syncronizer error: %v", err.Error()))

			c.ResponseError(err.Error())
			return
		}
	} else if ldap.AutoSync == 0 && prevLdap.AutoSync != 0 {
		object.GetLdapSynchronizationManager().StopAutoSync(ldap.Id)
	}

	c.Data["json"] = wrapActionResponse(affected)
	c.ServeJSON()
}

// DeleteLdap
// @Title DeleteLdap
// @Tag Account API
// @Description delete ldap
// @Param	body	body	object.Ldap		true	"The details of the ldap"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-ldap [post]
func (c *ApiController) DeleteLdap() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var ldap object.Ldap
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &ldap)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	affected, err := object.DeleteLdap(&ldap)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	object.GetLdapSynchronizationManager().StopAutoSync(ldap.Id)

	c.Data["json"] = wrapActionResponse(affected)
	c.ServeJSON()
}

// SyncLdapUsers
// @Title SyncLdapUsers
// @Tag Account API
// @Description sync ldap users
// @Param	id	query	string		true	"id"
// @Success 200 {object} LdapSyncResp The Response object
// @router /sync-ldap-users [post]
func (c *ApiController) SyncLdapUsers() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	goCtx := c.getRequestCtx()
	record := object.GetRecord(goCtx)

	record.AddReason("SyncLdapUsers: start sync users")

	id := c.Input().Get("id")

	_, ldapId, err := util.GetOwnerAndNameFromId(id)
	if err != nil {
		err = errors.Wrap(err, "SyncLdapUsers error: Invalid id")
		record.AddReason(err.Error())
		logger.Error(goCtx, err.Error())
		c.ResponseError(err.Error())
		return
	}
	var users []object.LdapUser
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &users)
	if err != nil {
		err = errors.Wrap(err, "SyncLdapUsers error: Failed to unmarshal ldap users")
		record.AddReason(err.Error())
		logger.Error(goCtx, err.Error())
		c.ResponseError(err.Error())
		return
	}
	command := object.LdapSyncCommand{
		LdapUsers: users,
		LdapId:    ldapId,
		Reason:    "manual",
	}
	if request.User != nil {
		command.SyncedByUserID = request.User.Id
	}

	syncResult, err := object.SyncLdapUsers(goCtx, command)
	if err != nil {
		record.AddReason(fmt.Sprintf("SyncLdapUsers error: %s", err.Error()))
		logger.Error(goCtx, err.Error())
		c.ResponseError(err.Error())
		return
	}

	err = object.UpdateLdapSyncTime(ldapId)
	if err != nil {
		record.AddReason(fmt.Sprintf("SyncLdapUsers error: %s", err.Error()))
		logger.Error(goCtx, err.Error())
		c.ResponseError(err.Error())
		return
	}
	if len(syncResult.Failed) != 0 {
		logger.Warn(goCtx, "SyncLdapUsers: sync finished", "ldap_id", command.LdapId, "synced_by_user_id", command.SyncedByUserID, "reason", command.Reason, "new_users", len(syncResult.Added), "updated", len(syncResult.Updated), "errors", len(syncResult.Failed))
	} else {
		logger.Info(goCtx, "SyncLdapUsers: sync finished", "ldap_id", command.LdapId, "synced_by_user_id", command.SyncedByUserID, "reason", command.Reason, "new_users", len(syncResult.Added), "updated", len(syncResult.Updated))
	}
	logger.Info(goCtx, "SyncLdapUsers: users sync finished", "ldap_id", command.LdapId, "synced_by_user_id", command.SyncedByUserID, "reason", command.Reason)

	record.AddReason("SyncLdapUsers: users sync finished")

	c.ResponseOk(&LdapSyncResp{
		Exist:  syncResult.Exist,
		Failed: syncResult.Failed,
	})
}

// SyncLdapUsersV2
// @Title SyncLdapUsersV2
// @Tag Account API
// @Description sync ldap users by ldap uuid
// @Param	body	body	SyncLdapUsersRequest	true
// @Success 200 {object} LdapSyncResp The Response object
// @router /v2/sync-ldap-users [post]
func (c *ApiController) SyncLdapUsersV2() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	syncRequest := SyncLdapUsersRequest{}
	goCtx := c.getRequestCtx()
	record := object.GetRecord(goCtx)
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &syncRequest)
	if err != nil {
		err = errors.Wrap(err, "SyncLdapUsersV2 error: unmarshal users")
		record.AddReason(err.Error())
		logger.Error(goCtx, err.Error())
		c.ResponseError(err.Error())
		return
	}

	record.AddReason("SyncLdapUsersV2: start sync users")

	var users []object.LdapUser
	ldap, err := object.GetLdap(syncRequest.Id)
	if err != nil {
		err = errors.Wrap(err, "SyncLdapUsersV2 error: failed to GetLdap")
		record.AddReason(err.Error())
		logger.Error(goCtx, err.Error())
		c.ResponseError(err.Error())
		return
	}

	conn, err := ldap.GetLdapConn(goCtx)
	if err != nil {
		err = errors.Wrap(err, "SyncLdapUsersV2 error: failed to GetLdapConn")
		record.AddReason(err.Error())
		logger.Error(goCtx, err.Error())
		c.ResponseError(err.Error())
		return
	}

	res, err := conn.GetLdapUsers(ldap, nil, record)
	if err != nil {
		err = errors.Wrap(err, "SyncLdapUsersV2 error: failed to GetLdapUsers")
		record.AddReason(err.Error())
		logger.Error(goCtx, err.Error())
		c.ResponseError(err.Error())
		return
	}
	users = res
	command := object.LdapSyncCommand{
		LdapUsers: users,
		LdapId:    syncRequest.Id,
		Reason:    "manual",
	}
	if request.User != nil {
		command.SyncedByUserID = request.User.Id
	}

	syncResult, err := object.SyncLdapUsers(goCtx, command)
	if err != nil {
		err = errors.Wrap(err, "SyncLdapUsersV2 error")
		record.AddReason(err.Error())
		logger.Error(goCtx, err.Error(), "ldap_id", command.LdapId, "synced_by_user_id", command.SyncedByUserID, "reason", command.Reason)
		c.ResponseError(err.Error())
		return
	}
	if len(syncResult.Failed) != 0 {
		logger.Warn(goCtx, "SyncLdapUsersV2: sync finished", "ldap_id", command.LdapId, "synced_by_user_id", command.SyncedByUserID, "reason", command.Reason, "new_users", len(syncResult.Added), "updated", len(syncResult.Updated), "errors", len(syncResult.Failed))
	} else {
		logger.Info(goCtx, "SyncLdapUsersV2: sync finished", "ldap_id", command.LdapId, "synced_by_user_id", command.SyncedByUserID, "reason", command.Reason, "new_users", len(syncResult.Added), "updated", len(syncResult.Updated))
	}
	record.AddReason("SyncLdapUsersV2: users sync finished")

	c.ResponseOk(&LdapSyncResp{
		Exist:  syncResult.Exist,
		Failed: syncResult.Failed,
	})
}

// TestLdapConnection
// @Title TestLdapConnection
// @Tag Account API
// @Description test ldap connection
// @Param	body	body	object.Ldap		true	"The details of the ldap"
// @Success 200 {object} controllers.Response The Response object
// @router /test-ldap [post]
func (c *ApiController) TestLdapConnection() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var ldap object.Ldap
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &ldap)
	if err != nil || util.IsStringsEmpty(ldap.Owner, ldap.Host, ldap.Username, ldap.Password, ldap.BaseDn) {
		c.ResponseError(c.T("general:Missing parameter"))
		return
	}

	if ldap.Password == "***" {
		pwdFromDB, err := object.GetLdapPassword(ldap)
		if err != nil {
			c.ResponseError(err.Error())
		}

		ldap.Password = pwdFromDB
	}

	for _, roleMappingItem := range ldap.RoleMappingItems {
		if util.IsStringsEmpty(roleMappingItem.Attribute, roleMappingItem.Role) || len(roleMappingItem.Values) == 0 {
			c.ResponseError(c.T("general:Missing parameter"))
			return
		}
	}

	var connection *object.LdapConn
	connection, err = ldap.GetLdapConn(context.Background())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	connection.Conn.Start()

	err = connection.Conn.Bind(ldap.Username, ldap.Password)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	const cnAttr = "cn"
	filter := fmt.Sprintf("(%s=*)", cnAttr)
	attrs := []string{cnAttr}
	// SizeLimit is 2 because of go-ldap returns SizeLimit-1 entities
	searchRequest := goldap.NewSearchRequest(ldap.BaseDn, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 2,
		0, false, filter, attrs, nil)
	searchResult, err := connection.Conn.Search(searchRequest)

	if err != nil && (searchResult == nil || len(searchResult.Entries) == 0) {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk()
}

// GetLdapSyncHistory
// @Title GetLdapSyncHistory
// @Tag Account API
// @Description get detailed ldap sync history info, with list of users and what happened to them
// @Param id query string true "Ldap UUID"
// @Param limit	query	string	10 	false	"Results per page"
// @Param sortOrder	query string "descend" false "descend/ascend"
// @Param p query string 1 false "Page number"
// @Success 200 {array} ldap_sync.LdapSyncHistory The Response object
// @router /get-ldap-sync-history [get]
func (c *ApiController) GetLdapSyncHistory() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	var err error

	ctx := c.getRequestCtx()
	record := object.GetRecord(ctx)

	ldapId := c.Input().Get("id")
	sortOrderRaw := c.Input().Get("sortOrder")
	limit := request.Limit

	if limit <= 0 {
		limit = 10
	}
	sortOrder := "descend"
	if sortOrderRaw == "ascend" {
		sortOrder = "ascend"
	}

	if ldapId == "" {
		err = errors.New("GetLdapSyncHistory: ldap id is required")
		record.AddReason(err.Error())

		c.ResponseBadRequest(err.Error())
	}

	repo := ldap_sync.LdapSyncHistoryRepository{}
	count, err := repo.CountLdapSyncHistoryEntries(ldapId)
	if err != nil {
		err = errors.Wrap(err, "CountLdapSyncHistoryEntries failed")
		record.AddReason(err.Error())

		c.ResponseError(err.Error())
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, limit, count)
	history, err := repo.GetLdapSyncHistory(ldapId, paginator.Offset(), limit, sortOrder)
	if err != nil {
		err = errors.Wrap(err, "GetLdapSyncHistory failed")
		record.AddReason(err.Error())
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(history, paginator.Nums())
}
