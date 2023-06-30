package pt_af_logic

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"strings"

	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/object"
	af_client "github.com/casdoor/casdoor/pt_af_sdk"
)

type Message struct {
	Action                string            `json:"action"`
	ClientShortName       string            `json:"clientShortName"`
	ClientProperties      map[string]string `json:"clientProperties"`
	ClientContact         ContactData       `json:"clientContact"`
	Product               string            `json:"product"`
	Plan                  string            `json:"plan"`
	PartnerShortName      string            `json:"partnerShortName"`
	PartnerManagerContact ContactData       `json:"partnerManagerContact"`
}

type ContactData struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
	Name  string `json:"name"`
}

type SubscriptionStateChangeMessage struct {
	Actor          ContactData
	PartnerManager ContactData
	PartnerUser    ContactData
	Organization   *object.Organization
	Subscription   *object.Subscription
	NewStatus      string
	OldStatus      string
}

type PartnerCreatedMessage struct {
	PartnerName        string
	PartnerDisplayName string
	PartnerURL         string
	PartnerAccount     string
	PartnerUserName    string
}

type PTAFTenantCreatedMessage struct {
	ClientName          string
	ClientDisplayName   string
	ClientURL           string
	ServiceUserName     string
	ServiceUserPwd      string
	UserROName          string
	UserROPwd           string
	TenantAdminName     string
	TenantAdminPassword string
	PTAFLoginLink       string
	ConnectionString    string
}

type PartnerConfirmedMessage struct {
	PartnerUserName string
	PartnerLoginURL string
}

const (
	subscriptionStateChangeEmailSubject = `[PT LMP] Subscription status changed`
	partnerConfirmedSubject             = `[PT LMP] Registration confirmed`
)

func notifyPTAFTenantCreated(msg *PTAFTenantCreatedMessage, email string) error {
	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}

	titleTmpl, err := template.New("").Parse(partnerCreateAccountsSubjTmpl)
	if err != nil {
		return fmt.Errorf("template.Parse: %w", err)
	}

	var titleBuf bytes.Buffer
	err = titleTmpl.Execute(&titleBuf, msg)
	if err != nil {
		return fmt.Errorf("titleTmpl.Execute: %w", err)
	}

	bodyTmpl, err := template.New("").Parse(partnerCreateAccountsBodyTmpl)
	if err != nil {
		return fmt.Errorf("template.Parse: %w", err)
	}

	var bodyBuf bytes.Buffer
	err = bodyTmpl.Execute(&bodyBuf, msg)
	if err != nil {
		return fmt.Errorf("bodyTmpl.Execute: %w", err)
	}

	err = object.SendEmail(provider, titleBuf.String(), bodyBuf.String(), email, provider.DisplayName)
	if err != nil {
		return fmt.Errorf("object.SendEmail: %w", err)
	}

	return nil
}

// NotifyPartnerConfirmed notify that his account confirmed, and now he can log in.
func NotifyPartnerConfirmed(oldUser, user *object.User) error {
	userConfirmed := user.IsAdmin == true && user.IsForbidden == false && (oldUser.IsAdmin != true || oldUser.IsForbidden == true)
	if !userConfirmed {
		return nil
	}

	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}

	msg := PartnerConfirmedMessage{
		PartnerUserName: user.Name,
		PartnerLoginURL: fmt.Sprintf("%s/login/%s", conf.GetConfigString("origin"), user.Owner),
	}

	bodyTmpl, err := template.New("").Parse(partnerConfirmedBodyTmpl)
	if err != nil {
		return fmt.Errorf("template.New.Parse: %w", err)
	}

	var bodyBuf bytes.Buffer
	if err := bodyTmpl.Execute(&bodyBuf, msg); err != nil {
		return fmt.Errorf("tmpl.Execute: %w", err)
	}

	err = object.SendEmail(provider, partnerConfirmedSubject, bodyBuf.String(), user.Email, provider.DisplayName)
	if err != nil {
		return fmt.Errorf("object.SendEmail: %w", err)
	}

	return nil
}

// NotifyPartnerCreated notify global admin that first manager in organization is created (signup-ed)
func NotifyPartnerCreated(user *object.User, organization *object.Organization) error {
	count, err := object.GetUserCount(user.Owner, "", "", "")
	if err != nil {
		return fmt.Errorf("object.GetUserCount: %w", err)
	}

	if count != 1 {
		// global admin must be notified only for first registered user
		return nil
	}

	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}

	msg := PartnerCreatedMessage{
		PartnerName:        organization.Name,
		PartnerDisplayName: organization.DisplayName,
		PartnerURL:         fmt.Sprintf("%s/organizations/%s", conf.GetConfigString("origin"), organization.Name),
		PartnerAccount:     fmt.Sprintf("%s/users/%s/%s", conf.GetConfigString("origin"), organization.Name, user.Name),
		PartnerUserName:    user.Name,
	}

	titleTmpl, err := template.New("").Parse(partnerCreatedSubjTmpl)
	if err != nil {
		return fmt.Errorf("template.Parse: %w", err)
	}

	var titleBuf bytes.Buffer
	err = titleTmpl.Execute(&titleBuf, msg)
	if err != nil {
		return fmt.Errorf("titleTmpl.Execute: %w", err)
	}

	bodyTmpl, err := template.New("").Parse(partnerCreatedBodyTmpl)
	if err != nil {
		return fmt.Errorf("template.New.Parse: %w", err)
	}

	var bodyBuf bytes.Buffer
	if err := bodyTmpl.Execute(&bodyBuf, msg); err != nil {
		return fmt.Errorf("tmpl.Execute: %w", err)
	}

	recipients := getBuiltInAdmins()
	for _, email := range recipients {
		errS := object.SendEmail(provider, titleBuf.String(), bodyBuf.String(), email, provider.DisplayName)
		if errS != nil {
			err = fmt.Errorf("%v; %v", err, errS)
		} else {
			err = errS
		}
	}

	return err
}

// NotifySubscriptionMembers composes subscription state change message and sends emails to its members
func NotifySubscriptionMembers(actor *object.User, current *object.Subscription, oldState string) error {
	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}
	if current.User == "" {
		return errors.New("no client detected in subscription")
	}

	orgId := fmt.Sprintf("admin/%s", current.Owner)
	organization, _ := object.GetOrganization(orgId)
	partnerManager := getPartnerManager(current.Owner)
	if partnerManager == nil {
		return errors.New("no partner manager detected")
	}
	client, _ := object.GetUser(current.User)

	var clientProps = make(map[string]string)
	for prop := range client.Properties {
		if !strings.HasPrefix(prop, af_client.PtPropPref) {
			clientProps[prop] = client.Properties[prop]
		}
	}

	// compose payload
	msg := SubscriptionStateChangeMessage{
		Actor: ContactData{
			Email: actor.Email,
			Phone: actor.Phone,
			Name:  actor.DisplayName,
		},
		PartnerManager: ContactData{
			Email: partnerManager.Email,
			Phone: partnerManager.Phone,
			Name:  partnerManager.DisplayName,
		},
		PartnerUser: ContactData{
			Email: client.Email,
			Phone: client.Phone,
			Name:  client.DisplayName,
		},
		Organization: organization,
		Subscription: current,
		NewStatus:    current.State,
		OldStatus:    oldState,
	}

	recipients := getSubscriptionStateRecipients(current)

	errors := make(chan error, len(recipients))
	defer close(errors)
	for _, email := range recipients {
		go func(dst string) {
			var templateName string

			// im really concerned about this way and sure it have not to be like that
			// probably should be a separate functional handler to handle each recipient
			if dst == client.Email || dst == partnerManager.Email {
				templateName = partnerSubscriptionTmpl
			} else {
				templateName = builtInAdminTmpl
			}

			tmpl, err := template.New("").Parse(templateName)
			if err != nil {
				errors <- err
				return
			}

			var wr bytes.Buffer
			if err := tmpl.Execute(&wr, msg); err != nil {
				errors <- err
				return
			}

			errors <- object.SendEmail(provider, subscriptionStateChangeEmailSubject, wr.String(), dst, provider.DisplayName)
		}(email)
	}

	var err error
	for range recipients {
		if e := <-errors; e != nil {
			if err != nil {
				err = fmt.Errorf("%v; %v", err, e)
			} else {
				err = e
			}
		}
	}

	return err
}

func getSubscriptionStateRecipients(sub *object.Subscription) []string {
	recipients := getBuiltInAdmins()

	switch sub.State {
	case "Pending":
		{
			// nothing to do
			break
		}
	case "PreAuthorized":
		{
			partnerAdmin := getPartnerManager(sub.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			break
		}
	case "Unauthorized":
		{
			partnerAdmin := getPartnerManager(sub.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			break
		}
	case "Authorized":
		{
			partnerUser := getPartnerUser(sub.Owner)
			if partnerUser != nil {
				recipients = append(recipients, partnerUser.Email)
			}
			break
		}
	case "Started":
		{
			partnerAdmin := getPartnerManager(sub.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			break
		}
	case "PreFinished":
		{
			recipients = getAdmins(sub.Owner)
			break
		}
	case "Finished":
		{
			recipients = getAdmins(sub.Owner)
			break
		}
	case "Cancelled":
		{
			recipients = getAdmins(sub.Owner)
			break
		}
	default:
		return recipients
	}

	return recipients
}

func getBuiltInEmailProvider() *object.Provider {
	providers, _ := object.GetProviders(builtInOrgCode)
	for _, provider := range providers {
		if provider.Category == "Email" {
			return provider
		}
	}
	return nil
}

func getAdmins(organization string) []string {
	users, _ := object.GetUsers(organization)
	var emails []string
	for _, user := range users {
		if user.IsAdmin {
			emails = append(emails, user.Email)
		}
	}
	return emails
}

func getPartnerManager(organization string) *object.User {
	users, _ := object.GetUsers(organization)
	for _, user := range users {
		if user.IsAdmin {
			return user
		}
	}
	return nil
}

func getPartnerUser(organization string) *object.User {
	users, _ := object.GetUsers(organization)
	for _, user := range users {
		if !user.IsAdmin {
			return user
		}
	}
	return nil
}

func getBuiltInAdmins() []string {
	users, _ := object.GetUsers(builtInOrgCode)
	var emails []string
	for _, user := range users {
		if user.IsGlobalAdmin {
			emails = append(emails, user.Email)
		}
	}
	return emails
}
