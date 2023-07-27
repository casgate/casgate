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

package controllers

import (
	"encoding/json"
	"time"

	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/pt_af_logic"
	"github.com/casdoor/casdoor/util"
)

// GetSubscriptions
// @Title GetSubscriptions
// @Tag Subscription API
// @Description get subscriptions
// @Param   owner     query    string  true        "The owner of subscriptions"
// @Success 200 {array} object.Subscription The Response object
// @router /get-subscriptions [get]
func (c *ApiController) GetSubscriptions() {
	owner := c.Input().Get("owner")
	limit := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")

	if limit == "" || page == "" {
		subscriptions, err := object.GetSubscriptions(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.Data["json"] = subscriptions
		c.ServeJSON()
	} else {
		user := c.getCurrentUser()
		filter := pt_af_logic.GetSubscriptionFilter(user)

		limit := util.ParseInt(limit)
		count, err := object.GetSubscriptionCount(owner, field, value, filter)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		subscription, err := object.GetPaginationSubscriptions(owner, paginator.Offset(), limit, field, value, sortField, sortOrder, filter)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		c.ResponseOk(subscription, paginator.Nums())
	}
}

// GetSubscription
// @Title GetSubscription
// @Tag Subscription API
// @Description get subscription
// @Param   id     query    string  true        "The id ( owner/name ) of the subscription"
// @Success 200 {object} object.Subscription The Response object
// @router /get-subscription [get]
func (c *ApiController) GetSubscription() {
	id := c.Input().Get("id")

	user := c.getCurrentUser()
	filter := pt_af_logic.GetSubscriptionFilter(user)

	subscription, err := object.GetSubscription(id, filter)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = subscription
	c.ServeJSON()
}

// UpdateSubscription
// @Title UpdateSubscription
// @Tag Subscription API
// @Description update subscription
// @Param   id     query    string  true        "The id ( owner/name ) of the subscription"
// @Param   body    body   object.Subscription  true        "The details of the subscription"
// @Success 200 {object} controllers.Response The Response object
// @router /update-subscription [post]
func (c *ApiController) UpdateSubscription() {
	id := c.Input().Get("id")

	var subscription object.Subscription
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &subscription)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	currentUser := c.getCurrentUser()
	if currentUser == nil {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	filter := pt_af_logic.GetSubscriptionFilter(currentUser)
	old, err := object.GetSubscription(id, filter)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if old == nil {
		c.ResponseError("Could not find subscription to update")
		return
	}

	err = pt_af_logic.ValidateSubscriptionUpdate(currentUser, &subscription, old)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	err = pt_af_logic.UpdateSubscriptionByState(currentUser, &subscription, old)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	affected, err := object.UpdateSubscription(id, &subscription)
	c.Data["json"] = wrapActionResponse(affected, err)
	c.ServeJSON()

	if affected {
		util.SafeGoroutine(func() {
			pt_af_logic.ProcessSubscriptionUpdatePostActions(c.Ctx, currentUser, &subscription, old)
		})

	}
}

// AddSubscription
// @Title AddSubscription
// @Tag Subscription API
// @Description add subscription
// @Param   body    body   object.Subscription  true        "The details of the subscription"
// @Success 200 {object} controllers.Response The Response object
// @router /add-subscription [post]
func (c *ApiController) AddSubscription() {
	var subscription object.Subscription
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &subscription)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	subscription.Submitter = c.GetSessionUsername()
	subscription.Approver = c.GetSessionUsername()
	subscription.ApproveTime = time.Now().Format("2006-01-02T15:04:05Z07:00")

	c.Data["json"] = wrapActionResponse(object.AddSubscription(&subscription))
	c.ServeJSON()
}

// DeleteSubscription
// @Title DeleteSubscription
// @Tag Subscription API
// @Description delete subscription
// @Param   body    body   object.Subscription  true        "The details of the subscription"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-subscription [post]
func (c *ApiController) DeleteSubscription() {
	var subscription object.Subscription
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &subscription)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	user := c.getCurrentUser()
	filter := pt_af_logic.GetSubscriptionFilter(user)
	existing, err := object.GetSubscription(subscription.GetId(), filter)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if existing.State != "New" {
		c.ResponseError("Cannot delete subscription with current status")
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteSubscription(&subscription))
	c.ServeJSON()
}

// GetAvailableSubscriptionStates
// @Title GetAvailableSubscriptionStates
// @Tag Subscription API
// @Description get available subscription states for current user
// @Param   id     query    string  true        "The id ( owner/name ) of the subscription"
// @Success 200 {object} string The Response object
// @router /get-available-subscription-states [get]
func (c *ApiController) GetAvailableSubscriptionStates() {
	id := c.Input().Get("id")

	user := c.getCurrentUser()
	filter := pt_af_logic.GetSubscriptionFilter(user)

	subscription, err := object.GetSubscription(id, filter)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	availableStates, err := pt_af_logic.GetAvailableTransitions(user, subscription)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = availableStates
	c.ServeJSON()
}
