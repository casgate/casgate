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

package controllers

import (
	"encoding/json"

	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// GetSessions
// @Title GetSessions
// @Tag Session API
// @Description Get organization user sessions.
// @Param   owner     query    string  true        "The organization name"
// @Success 200 {array} string The Response object
// @router /get-sessions [get]
func (c *ApiController) GetSessions() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	if !c.IsGlobalAdmin() && request.Owner == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}
	
	count, err := object.GetSessionCount(request.Owner, request.Field, request.Value)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, request.Limit, count)
	sessions, err := object.GetPaginationSessions(request.Owner, paginator.Offset(), request.Limit, request.Field, request.Value, request.SortField, request.SortOrder)
	if err != nil {
		c.ResponseInternalServerError(err.Error())
		return
	}

	c.ResponseOk(sessions, paginator.Nums())
}

// GetSingleSession
// @Title GetSingleSession
// @Tag Session API
// @Description Get session for one user in one application.
// @Param   id     query    string  true        "The id(organization/application/user) of session"
// @Success 200 {array} string The Response object
// @router /get-session [get]
func (c *ApiController) GetSingleSession() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	session, err := object.GetSingleSession(request.Id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(session)
}

// UpdateSession
// @Title UpdateSession
// @Tag Session API
// @Description Update session for one user in one application.
// @Param   id     query    string  true        "The id(organization/application/user) of session"
// @Success 200 {array} string The Response object
// @router /update-session [post]
func (c *ApiController) UpdateSession() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var session object.Session
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &session)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	sessionFromDb, _ := object.GetSingleSession(util.GetSessionId(session.Owner, session.Name, session.Application))
	if sessionFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(sessionFromDb.Owner) 

	c.Data["json"] = wrapActionResponse(object.UpdateSession(util.GetSessionId(session.Owner, session.Name, session.Application), &session))
	c.ServeJSON()
}

// AddSession
// @Title AddSession
// @Tag Session API
// @Description Add session for one user in one application. If there are other existing sessions, join the session into the list.
// @Param   id     query    string  true        "The id(organization/application/user) of session"
// @Param   sessionId     query    string  true        "sessionId to be added"
// @Success 200 {array} string The Response object
// @router /add-session [post]
func (c *ApiController) AddSession() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	var session object.Session
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &session)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddSession(&session))
	c.ServeJSON()
}

// DeleteSession
// @Title DeleteSession
// @Tag Session API
// @Description Delete session for one user in one application.
// @Param   id     query    string  true        "The id(organization/application/user) of session"
// @Success 200 {array} string The Response object
// @router /delete-session [post]
func (c *ApiController) DeleteSession() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)

	ctx := c.getRequestCtx()
	var session object.Session
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &session)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	sessionFromDb, _ := object.GetSingleSession(util.GetSessionId(session.Owner, session.Name, session.Application))
	if sessionFromDb == nil {
		c.Data["json"] = wrapActionResponse(false)
		c.ServeJSON()
		return
	}
	c.ValidateOrganization(sessionFromDb.Owner) 

	c.Data["json"] = wrapActionResponse(object.DeleteSession(ctx, util.GetSessionId(session.Owner, session.Name, session.Application)))
	c.ServeJSON()
}

// IsSessionDuplicated
// @Title IsSessionDuplicated
// @Tag Session API
// @Description Check if there are other different sessions for one user in one application.
// @Param   id     query    string  true        "The id(organization/application/user) of session"
// @Param   sessionId     query    string  true        "sessionId to be checked"
// @Success 200 {array} string The Response object
// @router /is-session-duplicated [get]
func (c *ApiController) IsSessionDuplicated() {
	request := c.ReadRequestFromQueryParams()
	c.ContinueIfHasRightsOrDenyRequest(request)
	
	id := c.Input().Get("sessionPkId")
	sessionId := c.Input().Get("sessionId")

	isUserSessionDuplicated, err := object.IsSessionDuplicated(id, sessionId)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(isUserSessionDuplicated)
}
