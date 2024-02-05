package controllers

import (
	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// GetUserProviders
// @Title GetUserProviders
// @Tag UserProvider API
// @Description get userProviders
// @Param   owner     query    string  true        "The owner of userProviders"
// @Success 200 {array} object.UserProvider The Response object
// @router /get-user-providers [get]
func (c *ApiController) GetUserProviders() {
	owner := c.Input().Get("owner")
	limitParam := c.Input().Get("pageSize")
	page := c.Input().Get("p")
	field := c.Input().Get("field")
	value := c.Input().Get("value")
	sortField := c.Input().Get("sortField")
	sortOrder := c.Input().Get("sortOrder")

	if !c.IsGlobalAdmin() && owner == "" {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	var limit int
	if limitParam == "" || page == "" {
		limit = -1
	} else {
		limit = util.ParseInt(limitParam)
	}

	count, err := object.GetUserProviderCount(owner, field, value)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, limit, count)
	paginationUserProviders, err := object.GetPaginationUserProviders(owner, paginator.Offset(), limit, field, value, sortField, sortOrder)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	err = fillUserProviders(paginationUserProviders)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(paginationUserProviders, paginator.Nums())
}

// GetUserProvider
// @Title GetUserProvider
// @Tag UserProvider API
// @Description get userProvider
// @Param   owner        		query    string  true        "The owner of the provider"
// @Param   providerName 		query    string  true        "The name of the provider"
// @Param   userProviderName    query    string  true        "The name of the user in the provider"
// @Success 200 {object} object.UserProvider The Response object
// @router /get-user-provider [get]
func (c *ApiController) GetUserProvider() {
	owner := c.Input().Get("owner")
	providerName := c.Input().Get("providerName")
	userProviderName := c.Input().Get("userProviderName")

	if _, res := c.RequireAdmin(); !res {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	if owner == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": owner")
	}

	if providerName == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": providerName")
	}

	if userProviderName == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": userProviderName")
	}

	userProvider, err := object.GetUserProvider(owner, providerName, userProviderName)

	if userProvider == nil {
		c.ResponseError(c.T("general:The userProvider doesn't exist"))
		return
	}

	err = fillUserProviders([]*object.UserProvider{userProvider})
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(userProvider)
}

func fillUserProviders(userProviders []*object.UserProvider) (err error) {
	for _, provider := range userProviders {
		provider.ProviderObj, err = object.GetProvider(util.GetId(provider.Owner, provider.ProviderName))
		if err != nil {
			return err
		}

		provider.UserObj, err = object.GetUser(util.GetId(provider.Owner, provider.UserProviderName))
		if err != nil {
			return err
		}
	}

	return nil
}
