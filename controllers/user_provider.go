package controllers

import (
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// GetAllUserProviders
// @Title GetAllUserProviders
// @Tag UserProvider API
// @Description get userProviders
// @Success 200 {array} object.UserProvider The Response object
// @router /get-user-providers [get]
func (c *ApiController) GetAllUserProviders() {
	if _, res := c.RequireAdmin(); !res {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	userProviders, err := object.GetAllUserProviders()

	err = fillUserProviders(userProviders)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(userProviders)
}

// GetUserProvidersByOwner
// @Title GetUserProvidersByOwner
// @Tag UserProvider API
// @Description get userProviders by owner
// @Param   owner query    string  true        "The owner of the provider"
// @Success 200 {array} object.UserProvider The Response object
// @router /get-user-providers-by-owner [get]
func (c *ApiController) GetUserProvidersByOwner() {
	owner := c.Input().Get("owner")

	if _, res := c.RequireAdmin(); !res {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	if owner == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": owner")
	}

	userProviders, err := object.GetUserProvidersByOwner(owner)

	err = fillUserProviders(userProviders)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(userProviders)
}

// GetUserProvidersByUserName
// @Title GetUserProvidersByUserName
// @Tag UserProvider API
// @Description get userProviders by username
// @Param   userName query    string  true        "The name of the user"
// @Success 200 {array} object.UserProvider The Response object
// @router /get-user-providers-by-user-name [get]
func (c *ApiController) GetUserProvidersByUserName() {
	userName := c.Input().Get("userName")

	if _, res := c.RequireAdmin(); !res {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	if userName == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": userName")
	}

	userProviders, err := object.GetUserProvidersByUserName(userName)

	err = fillUserProviders(userProviders)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(userProviders)
}

// GetUserProvider
// @Title GetUserProvider
// @Tag UserProvider API
// @Description get userProvider
// @Param   owner        query    string  true        "The owner of the provider"
// @Param   providerName query    string  true        "The name of the provider"
// @Param   userName     query    string  true        "The name of the user"
// @Success 200 {object} object.UserProvider The Response object
// @router /get-user-provider [get]
func (c *ApiController) GetUserProvider() {
	owner := c.Input().Get("owner")
	providerName := c.Input().Get("providerName")
	userName := c.Input().Get("userName")

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

	if userName == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": userName")
	}

	userProvider, err := object.GetUserProvider(owner, providerName, userName)

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

// GetUserProvidersByProviderName
// @Title GetUserProvidersByProviderName
// @Tag UserProvider API
// @Description get userProviders by provider name
// @Param   providerName query    string  true        "The name of the provider"
// @Success 200 {array} object.UserProvider The Response object
// @router /get-user-providers-by-provider-name [get]
func (c *ApiController) GetUserProvidersByProviderName() {
	providerName := c.Input().Get("providerName")

	if _, res := c.RequireAdmin(); !res {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	if providerName == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": providerName")
	}

	userProviders, err := object.GetUserProvidersByProviderName(providerName)

	err = fillUserProviders(userProviders)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(userProviders)
}

func fillUserProviders(userProviders []*object.UserProvider) (err error) {
	for _, provider := range userProviders {
		provider.ProviderObj, err = object.GetProvider(util.GetId(provider.Owner, provider.ProviderName))
		if err != nil {
			return err
		}

		provider.UserObj, err = object.GetUser(util.GetId(provider.Owner, provider.UserName))
		if err != nil {
			return err
		}
	}

	return nil
}
