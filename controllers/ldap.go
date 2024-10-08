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
	Users      []ldap_sync.LdapUser `json:"users"`
	ExistUuids []string             `json:"existUuids"`
}

type LdapSyncResp struct {
	Exist  []ldap_sync.LdapUser `json:"exist"`
	Failed []ldap_sync.LdapUser `json:"failed"`
}

type LdapIdWithNameResp struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type SyncLdapUsersRequest struct {
	Id string `json:"id"`
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
	record := object.GetRecordBuilderFromContext(gCtx)
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

	conn, err := ldap_sync.GetLdapConn(gCtx, ldapServer)
	if err != nil {
		err = errors.Wrap(err, "Get LDAP connection")
		logger.Error(gCtx, err.Error())
		record.AddReason(err.Error())
		c.ResponseError(err.Error())
		return
	}

	users, err := conn.GetUsersFromLDAP(gCtx, ldapServer, nil)
	if err != nil {
		err = errors.Wrap(err, "Get LDAP users")
		logger.Error(gCtx, err.Error())
		record.AddReason(err.Error())
		c.ResponseError(err.Error())
		return
	}

	uuids := make([]string, len(users))
	for i, user := range users {
		uuids[i] = user.GetLdapUserID()
	}
	existUuids, err := object.GetExistingLdapUserIDs(ldapServer.Owner, uuids)
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
	tracingRecord := object.GetRecordBuilderFromContext(gCtx)

	var ldap ldap_sync.Ldap
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &ldap)
	if err != nil {
		tracingRecord.AddReason(fmt.Sprintf("Unmarshal: %v", err.Error()))

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
		tracingRecord.AddReason(msg)
		c.ResponseError(msg)
		return
	}

	if len(ldap.Id) == 0 {
		ldap.Id = util.GenerateId()
	}

	if ok, err := object.CheckLdapExist(&ldap); err != nil {
		tracingRecord.AddReason(fmt.Sprintf("Check LDAP exists: %v", err.Error()))

		c.ResponseError(err.Error())
		return
	} else if ok {
		msg := c.T("ldap:Ldap server exist")
		tracingRecord.AddReason(msg)

		c.ResponseError(msg)
		return
	}

	resp := wrapActionResponse(object.AddLdap(&ldap))
	resp.Data2 = ldap

	if ldap.AutoSync != 0 {
		// Create new context to use in background operation,
		// because request context may timeout or be cancelled by framework code.
		err := object.GetLdapSyncManager().StartSyncProcess(context.WithoutCancel(gCtx), ldap.Id, time.Duration(ldap.AutoSync)*time.Minute)
		if err != nil {
			tracingRecord.AddReason(fmt.Sprintf("Update LDAP: StartSyncProcess: %v", err.Error()))
			logger.Error(
				gCtx,
				"Add LDAP: StartSyncProcess error",
				"error", err.Error(),
				"ldap_id", ldap.Id,
				"act", logger.OperationNameLdapSyncUsers,
				"r", logger.OperationResultFailure,
			)
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
	tracingRecord := object.GetRecordBuilderFromContext(gCtx)

	var ldap ldap_sync.Ldap
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &ldap)
	if err != nil {
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
		msg = c.T("general:Missing client certificate")
	} else if disabledCryptoAndEmptyCred {
		msg = c.T("general:Missing administrator credentials")
	} else if ldap.AutoSync != 0 && ldap.AutoSync < ldapSyncMinIntervalMinutes {
		msg = c.T("general:Ldap sync interval can't be less than 15 minutes")
	}

	if msg != "" {
		tracingRecord.AddReason(msg)
		c.ResponseError(msg)
		return
	}

	for _, roleMappingItem := range ldap.RoleMappingItems {
		if util.IsStringsEmpty(roleMappingItem.Attribute, roleMappingItem.Role) || len(roleMappingItem.Values) == 0 {
			msg := c.T("general:Missing parameter")
			tracingRecord.AddReason(msg)

			c.ResponseError(msg)
			return
		}
	}

	prevLdap, err := object.GetLdap(ldap.Id)
	if err != nil {
		tracingRecord.AddReason(fmt.Sprintf("Get LDAP: %v", err.Error()))

		c.ResponseError(err.Error())
		return
	}

	affected, err := object.UpdateLdap(&ldap)
	if err != nil {
		tracingRecord.AddReason(fmt.Sprintf("Update LDAP: %v", err.Error()))

		c.ResponseError(err.Error())
		return
	}

	if ldap.AutoSync != 0 {
		// Create new context to use in background operation,
		// because request context may timeout or be cancelled by framework code.
		err := object.GetLdapSyncManager().StartSyncProcess(context.WithoutCancel(gCtx), ldap.Id, time.Duration(ldap.AutoSync)*time.Minute)
		if err != nil {
			tracingRecord.AddReason(fmt.Sprintf("Update LDAP: StartSyncProcess: %v", err.Error()))

			logger.Error(
				gCtx,
				"Update LDAP: StartSyncProcess error",
				"error", err.Error(),
				"ldap_id", ldap.Id,
				"act", logger.OperationNameLdapSyncUsers,
				"r", logger.OperationResultFailure,
			)
			c.ResponseError(err.Error())
			return
		}
	} else if ldap.AutoSync == 0 && prevLdap.AutoSync != 0 {
		object.GetLdapSyncManager().StopSyncProcess(ldap.Id)
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

	var ldap ldap_sync.Ldap
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

	object.GetLdapSyncManager().StopSyncProcess(ldap.Id)

	c.Data["json"] = wrapActionResponse(affected)
	c.ServeJSON()
}

// SyncLdapUsers
// @Title SyncLdapUsers
// @Tag Account API
// @Description sync ldap users
// @Param	id	query	string		true	"id"
// @Success 200 {object} controllers.LdapSyncResp The Response object
// @router /sync-ldap-users [post]
func (c *ApiController) SyncLdapUsers() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	goCtx := c.getRequestCtx()
	record := object.NewRecord(c.Ctx)
	mappingRb := object.NewRecordBuilderWithRequestValues(c.Ctx)
	goCtx = context.WithValue(goCtx, object.RoleMappingRecordDataKey, mappingRb)
	record.Action = "manual LDAP sync"

	logger.SetItem(goCtx, "obj-type", logger.ObjectTypeLDAP)
	logger.SetItem(goCtx, "usr", c.GetSessionUsername())

	id := c.Input().Get("id")
	logger.SetItem(goCtx, "obj", id)
	record.Object = id

	organizationName, ldapId, err := util.SplitIdIntoOrgAndName(id)
	if err != nil {
		logger.Error(
			goCtx,
			"SyncLdapUsers error: Invalid id",
			"error", err.Error(),
			"id", id,
			"ldap_id", ldapId,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsers error: Invalid id",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
		util.SafeGoroutine(func() { object.AddRecord(record) })
		c.ResponseError(err.Error())
		return
	}	
	mappingRb.WithOrganization(organizationName)
	record.Organization = organizationName
	record.Owner = organizationName
	record.Object = ldapId

	var users []ldap_sync.LdapUser
	err = json.Unmarshal(c.Ctx.Input.RequestBody, &users)
	if err != nil {
		logger.Error(
			goCtx,
			"SyncLdapUsers error: Failed to unmarshal ldap users",
			"error", err.Error(),
			"id", id,
			"ldap_id", ldapId,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsers error: Failed to unmarshal ldap users",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
		util.SafeGoroutine(func() { object.AddRecord(record) })
		c.ResponseError(err.Error())
		return
	}
	command := object.LdapSyncCommand{
		LdapUsers: users,
		LdapId:    ldapId,
		Reason:    ldap_sync.LdapSyncReasonManual,
	}
	if request.User != nil {
		command.SyncedByUserID = request.User.Id
		record.User = request.User.Name
		record.Organization = request.User.Owner
	}

	syncResult, err := object.SyncUsersSynchronously(goCtx, command)
	if err != nil {
		logger.Error(
			goCtx,
			"SyncLdapUsers failed",
			"error", err.Error(),
			"id", id,
			"ldap_id", ldapId,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsers failed",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
		util.SafeGoroutine(func() { object.AddRecord(record) })
		c.ResponseError(err.Error())
		return
	}
	if len(syncResult.Failed) != 0 {
		logger.Warn(
			goCtx,
			"SyncLdapUsers: sync finished with errors",
			"id", id,
			"ldap_id", ldapId,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultSuccess,
			"synced_by_user_id", command.SyncedByUserID,
			"reason", command.Reason,
			"new_users", len(syncResult.Added),
			"updated", len(syncResult.Updated),
			"errors", len(syncResult.Failed),
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsers: sync finished with errors",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
	} else {
		logger.Info(
			goCtx,
			"SyncLdapUsers: sync finished",
			"id", id,
			"ldap_id", ldapId,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultSuccess,
			"synced_by_user_id", command.SyncedByUserID,
			"reason", command.Reason,
			"new_users", len(syncResult.Added),
			"updated", len(syncResult.Updated),
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsers: sync finished",
			Status: object.AuditStatusOK,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
	}

	failed := make([]ldap_sync.LdapUser, 0, len(syncResult.Failed))
	for _, f := range syncResult.Failed {
		failed = append(failed, f)
	}
	util.SafeGoroutine(func() { object.AddRecord(record) })

	c.ResponseOk(&LdapSyncResp{
		Exist:  syncResult.Exist,
		Failed: failed,
	})
}

// SyncLdapUsersV2
// @Title SyncLdapUsersV2
// @Tag Account API
// @Description sync ldap users by ldap uuid
// @Param	body	body	controllers.SyncLdapUsersRequest	true
// @Success 200 {object} controllers.LdapSyncResp The Response object
// @router /v2/sync-ldap-users [post]
func (c *ApiController) SyncLdapUsersV2() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	syncRequest := SyncLdapUsersRequest{}
	ctx := c.getRequestCtx()
	record := object.NewRecord(c.Ctx)
	record.Action = "manual LDAP sync"
	mappingRb := object.NewRecordBuilderWithRequestValues(c.Ctx)
	ctx = context.WithValue(ctx, object.RoleMappingRecordDataKey, mappingRb)

	err := json.Unmarshal(c.Ctx.Input.RequestBody, &syncRequest)
	if err != nil {
		logger.Error(
			ctx,
			"SyncLdapUsersV2 error: unmarshal request",
			"error", err.Error(),
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsersV2 error: unmarshal request",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
		util.SafeGoroutine(func() { object.AddRecord(record) })
		c.ResponseError(err.Error())
		return
	}

	ldap, err := object.GetLdap(syncRequest.Id)
	if err != nil {
		err = errors.Wrap(err, "SyncLdapUsersV2 error: failed to GetLdap")
		logger.Error(
			ctx,
			"SyncLdapUsersV2 error: failed to GetLdap",
			"error", err.Error(),
			"ldap_id", syncRequest.Id,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsersV2 error: failed to GetLdap",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
		util.SafeGoroutine(func() { object.AddRecord(record) })
		c.ResponseError(err.Error())
		return
	}
	mappingRb.WithOrganization(ldap.Owner)
	record.Organization = ldap.Owner
	record.Owner = ldap.Owner
	record.Object = ldap.Id

	conn, err := ldap_sync.GetLdapConn(ctx, ldap)
	if err != nil {
		logger.Error(
			ctx,
			"SyncLdapUsersV2 error: failed to GetLdapConn",
			"error", err.Error(),
			"ldap_id", syncRequest.Id,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsersV2 error: failed to GetLdapConn",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
		util.SafeGoroutine(func() { object.AddRecord(record) })
		c.ResponseError(err.Error())
		return
	}

	res, err := conn.GetUsersFromLDAP(ctx, ldap, nil)
	if err != nil {
		logger.Error(
			ctx,
			"SyncLdapUsersV2 error: failed to GetUsersFromLDAP",
			"error", err.Error(),
			"ldap_id", syncRequest.Id,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsersV2 error: failed to GetLdapConn",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
		util.SafeGoroutine(func() { object.AddRecord(record) })
		c.ResponseError(err.Error())
		return
	}
	command := object.LdapSyncCommand{
		LdapUsers: res,
		LdapId:    syncRequest.Id,
		Reason:    ldap_sync.LdapSyncReasonManual,
	}
	if request.User != nil {
		command.SyncedByUserID = request.User.Id
		record.User = request.User.Name
	}

	syncResult, err := object.SyncUsersSynchronously(ctx, command)
	if err != nil {
		logger.Error(
			ctx,
			"SyncLdapUsersV2 failed",
			"error", err.Error(),
			"ldap_id", command.LdapId,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsersV2 error: failed to GetLdapConn",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
		util.SafeGoroutine(func() { object.AddRecord(record) })
		c.ResponseError(err.Error())
		return
	}
	if len(syncResult.Failed) != 0 {
		logger.Warn(
			ctx,
			"SyncLdapUsersV2: sync finished with errors",
			"ldap_id", command.LdapId,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultSuccess,
			"synced_by_user_id", command.SyncedByUserID,
			"reason", command.Reason,
			"new_users", len(syncResult.Added),
			"updated", len(syncResult.Updated),
			"errors", len(syncResult.Failed),
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsers: sync finished with errors",
			Status: object.AuditStatusError,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
	} else {
		logger.Info(
			ctx,
			"SyncLdapUsersV2: sync finished",
			"ldap_id", command.LdapId,
			"reason", ldap_sync.LdapSyncReasonManual,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultSuccess,
			"synced_by_user_id", command.SyncedByUserID,
			"reason", command.Reason,
			"new_users", len(syncResult.Added),
			"updated", len(syncResult.Updated),
		)
		auditResponse := object.AuditRecordResponse{
			Msg:    "SyncLdapUsers: sync finished",
			Status: object.AuditStatusOK,
		}
		if jsonResp, err := json.Marshal(auditResponse); err == nil {
			record.Response = string(jsonResp)
		}
	}

	failed := make([]ldap_sync.LdapUser, 0, len(syncResult.Failed))
	for _, f := range syncResult.Failed {
		failed = append(failed, f)
	}
	util.SafeGoroutine(func() { object.AddRecord(record) })

	c.ResponseOk(&LdapSyncResp{
		Exist:  syncResult.Exist,
		Failed: failed,
	})
}

// TestLdapConnection
// @Title TestLdapConnection
// @Tag Account API
// @Description test ldap connection
// @Param	body	body	ldap_sync.Ldap		true	"The details of the ldap"
// @Success 200 {object} controllers.Response The Response object
// @router /test-ldap [post]
func (c *ApiController) TestLdapConnection() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var ldap ldap_sync.Ldap
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &ldap)
	if err != nil || util.IsStringsEmpty(ldap.Owner, ldap.Host, ldap.BaseDn) {
		c.ResponseError(c.T("general:Missing parameter"))
		return
	}
	if !(ldap.EnableCryptographicAuth && ldap.EnableSsl) {
		if util.IsStringsEmpty(ldap.Username, ldap.Password) {
			c.ResponseError(c.T("general:Missing parameter"))
			return
		}
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

	var connection *ldap_sync.LdapConn
	connection, err = ldap_sync.GetLdapConn(c.Ctx.Request.Context(), &ldap)
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
	record := object.GetRecordBuilderFromContext(ctx)

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
