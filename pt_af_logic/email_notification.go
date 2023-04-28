package pt_af_logic

import (
	"errors"
	"github.com/casdoor/casdoor/object"
)

type Message struct {
	Action                string      `json:"action"`
	ShortName             string      `json:"shortName"`
	KppOrInn              string      `json:"kppOrInn"`
	Product               string      `json:"product"`
	Plan                  string      `json:"plan"`
	ClientContact         ContactData `json:"clientContact"`
	PartnerShortName      string      `json:"partnerShortName"`
	PartnerManagerContact ContactData `json:"partnerManagerContact"`
}

type ContactData struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

func Send(message *Message) error {
	provider := getBuiltInEmailProvider()
	if provider != nil {
		return errors.New("no email provider registered")
	}

	return object.SendEmail(provider, "", "", provider.Receiver, provider.Receiver)
}

func getBuiltInEmailProvider() *object.Provider {
	providers := object.GetProviders("built-in")
	for _, provider := range providers {
		if provider.Category == "Email" {
			return provider
		}
	}
	return nil
}

func getBuiltInAdmins() []string {
	users := object.GetUsers("built-in")
	emails := []string{}
	for _, user := range users {
		if user.IsGlobalAdmin {
			emails = append(emails, user.Email)
		}
	}
	return emails
}
