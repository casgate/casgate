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
	"fmt"

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
			panic(err)
		}

		c.Data["json"] = subscriptions
		c.ServeJSON()
	} else {
		limit := util.ParseInt(limit)
		count, err := object.GetSubscriptionCount(owner, field, value)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}

		paginator := pagination.SetPaginator(c.Ctx, limit, count)
		subscription, err := object.GetPaginationSubscriptions(owner, paginator.Offset(), limit, field, value, sortField, sortOrder)
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
// @Success 200 {object} object.subscription The Response object
// @router /get-subscription [get]
func (c *ApiController) GetSubscription() {
	id := c.Input().Get("id")

	subscription, err := object.GetSubscription(id)
	if err != nil {
		panic(err)
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

	// get current user
	currentUser := c.getCurrentUser()
	isGlobalAdmin := currentUser.IsGlobalAdmin
	isOrgAdmin := currentUser.IsAdmin

	// check subscription status
	old, err := object.GetSubscription(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if old == nil {
		c.ResponseError("Could not find subscription to update")
		return
	}

	stateChanged := old.State != subscription.State
	if stateChanged {
		valid, statuses := object.SubscriptionStateCanBeChanged(old.State, subscription.State)
		// global admin can move states in an unrestricted way
		if !valid && !isGlobalAdmin {
			c.ResponseError(fmt.Sprintf(
				"Invalid subscription state. Can be changed to: '%s'", statuses,
			))
			return
		}

		// check for user permissions before allow state to change
		allowed, statuses2 := object.SubscriptionStateAllowedToChange(isGlobalAdmin, isOrgAdmin, old.State, subscription.State)
		if !allowed {
			var errText string
			if len(statuses2) == 0 {
				errText = "State change for current user is restricted"
			} else {
				errText = fmt.Sprintf(
					"Invalid subscription state. Can be changed to: '%s'", statuses2,
				)
			}
			c.ResponseError(errText)
			return
		}
	}

	isNameChanged := old.Name != subscription.Name
	isStartDateChanged := old.StartDate != subscription.StartDate
	isEndDateChanged := old.EndDate != subscription.EndDate
	isSubUserChanged := old.User != subscription.User
	isPlanChanged := old.Plan != subscription.Plan
	isDiscountChanged := old.Discount != subscription.Discount

	currentState := object.SubscriptionState(subscription.State)

	if currentState != object.SubscriptionNew {
		if isNameChanged && !isGlobalAdmin {
			c.ResponseError("Name change is restricted to New subscriptions only")
			return
		}

		if isSubUserChanged {
			c.ResponseError("User change is restricted to New subscriptions only")
			return
		}

		if isPlanChanged {
			if currentState != object.SubscriptionPending && currentState != object.SubscriptionUnauthorized {
				c.ResponseError("Plan change is restricted to New subscriptions only")
				return
			}
		}

		if isDiscountChanged {
			if currentState != object.SubscriptionPending && currentState != object.SubscriptionUnauthorized {
				c.ResponseError("Discount change is restricted to New subscriptions only")
				return
			}
		}

		if isStartDateChanged {
			if !isGlobalAdmin {
				if !isOrgAdmin {
					c.ResponseError("Restricted to organization admin")
					return
				}

				if currentState != object.SubscriptionAuthorized {
					c.ResponseError("StartDate change restricted to Authorized subscription state only")
					return
				}
			}
		}

		if isEndDateChanged {
			if !isGlobalAdmin {
				if !isOrgAdmin {
					c.ResponseError("Restricted to organization admin")
					return
				}

				if currentState != object.SubscriptionPreFinished {
					c.ResponseError("EndDate change restricted to PreFinished subscription state only")
					return
				}
			}
		}
	}

	affected, err := object.UpdateSubscription(id, &subscription)

	c.Data["json"] = wrapActionResponse(affected, err)
	c.ServeJSON()

	if affected {
		// send emails if response handler above not panics
		if stateChanged {
			util.SafeGoroutine(func() {
				if err := pt_af_logic.NotifySubscriptionMembers(currentUser, old, &subscription); err != nil {
					util.LogError(c.Ctx, err.Error())
				}
			})
		}

		// create tenant at pt af
		if object.SubscriptionState(subscription.State) == object.SubscriptionStarted {
			util.SafeGoroutine(func() {
				err := pt_af_logic.CreateTenant(c.Ctx, &subscription)
				if err != nil {
					util.LogError(c.Ctx, err.Error())
				}
			})
		}
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

	existing, err := object.GetSubscription(subscription.GetId())
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if existing.State != "New" && !c.IsGlobalAdmin() {
		c.ResponseError("Cannot delete subscription with current status")
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteSubscription(&subscription))
	c.ServeJSON()
}
