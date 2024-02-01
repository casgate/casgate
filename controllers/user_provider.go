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

// GetUserProvidersByUserId
// @Title GetUserProvidersByUserId
// @Tag UserProvider API
// @Description get userProviders by user id
// @Param   userId query    string  true        "The userId of the user"
// @Success 200 {array} object.UserProvider The Response object
// @router /get-user-providers-by-user-id [get]
func (c *ApiController) GetUserProvidersByUserId() {
	userId := c.Input().Get("userId")

	if _, res := c.RequireAdmin(); !res {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	if userId == "" {
		c.ResponseError(c.T("general:Missing parameter") + ": userId")
	}

	userProviders, err := object.GetUserProvidersByUserId(userId)

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

		provider.UserObj, err = object.GetUserByUserId(provider.Owner, provider.UserId)
		if err != nil {
			return err
		}
	}

	return nil
}
