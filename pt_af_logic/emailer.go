package pt_af_logic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/casdoor/casdoor/object"
	af_client "github.com/casdoor/casdoor/pt_af_sdk"
	"html/template"
	"strings"
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

// default organization
const builtInOrgCode = "built-in"

const subscriptionStateChangeEmailSubject = `Subscription status changed`

func getEmailSubjectAndTemplate(action string) (string, string, bool) {
	switch action {
	case action:

	}
	return "", "", false
}

func Email(subscription *object.Subscription) error {
	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}
	if subscription.User == "" {
		return errors.New("no client detected in subscription")
	}

	orgId := fmt.Sprintf("admin/%s", subscription.Owner)
	organization := object.GetOrganization(orgId)
	partnerManager := getPartnerManager(subscription.Owner)
	if partnerManager == nil {
		return errors.New("no partner manager detected")
	}
	client := object.GetUser(subscription.User)

	var clientProps = make(map[string]string)
	for prop := range client.Properties {
		if !strings.HasPrefix(prop, af_client.PtPropPref) {
			clientProps[prop] = client.Properties[prop]
		}
	}

	msg := Message{
		PartnerShortName: organization.Name,
		Plan:             subscription.Plan,
		ClientShortName:  client.Name,
		ClientContact: ContactData{
			Email: client.Email,
			Phone: client.Phone,
			Name:  client.DisplayName,
		},
		ClientProperties: clientProps,
		PartnerManagerContact: ContactData{
			Email: partnerManager.Email,
			Phone: partnerManager.Phone,
			Name:  partnerManager.DisplayName,
		},
		Product: "PT Application Firewall",
	}

	var recipients []string
	var subject string
	switch subscription.State {
	case "Pending":
		{
			recipients = getBuiltInAdmins()
			subject = "Subscription created"
			msg.Action = "Create"
		}
	case "Pre-authorized":
		{
			recipients = getAdmins(subscription.Owner)
			partnerAdmin := getPartnerManager(subscription.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			subject = "Subscription pre-authorized"
			msg.Action = "Pre-authorized"
		}
	case "Unauthorized":
		{
			recipients = getAdmins(subscription.Owner)
			partnerAdmin := getPartnerManager(subscription.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			subject = "Subscription unauthorized"
			msg.Action = "Approve"
		}
	case "Authorized":
		{
			recipients = getAdmins(subscription.Owner)
			partnerUser := getPartnerUser(subscription.Owner)
			if partnerUser != nil {
				recipients = append(recipients, partnerUser.Email)
			}
			subject = "Subscription authorized"
			msg.Action = "Authorized"
		}
	case "Started":
		{
			recipients = getAdmins(subscription.Owner)
			partnerAdmin := getPartnerManager(subscription.Owner)
			if partnerAdmin != nil {
				recipients = append(recipients, partnerAdmin.Email)
			}
			subject = "Subscription started"
			msg.Action = "Started"
		}
	case "Cancelled":
		{
			recipients = getAdmins(subscription.Owner)
			subject = "Subscription cancelled"
			msg.Action = "Cancelled"
		}
	case "Finished":
		{
			recipients = getAdmins(subscription.Owner)
			subject = "Subscription finished"
			msg.Action = "Finished"
		}
	default:
		return fmt.Errorf("could not handle subscription status: %s", subscription.State)
	}

	data, err := json.Marshal(msg)
	content := string(data)
	if err != nil {
		return err
	}

	errors := make(chan error, 256)
	defer close(errors)
	for _, email := range recipients {
		go func(dst string) {
			errors <- object.SendEmail(provider, subject, content, dst, provider.DisplayName)
		}(email)
	}

	for range recipients {
		if e := <-errors; e != nil {
			if err != nil {
				err = fmt.Errorf("%w; %w", err, e)
			} else {
				err = e
			}
		}
	}

	return err
}

// NotifySubscriptionMembers composes subscription state change message and sends emails to its members
func NotifySubscriptionMembers(actor *object.User, old, current *object.Subscription) error {
	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}
	if current.User == "" {
		return errors.New("no client detected in subscription")
	}

	orgId := fmt.Sprintf("admin/%s", current.Owner)
	organization := object.GetOrganization(orgId)
	partnerManager := getPartnerManager(current.Owner)
	if partnerManager == nil {
		return errors.New("no partner manager detected")
	}
	client := object.GetUser(current.User)

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
		OldStatus:    old.State,
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
				err = fmt.Errorf("%w; %w", err, e)
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
	providers := object.GetProviders(builtInOrgCode)
	for _, provider := range providers {
		if provider.Category == "Email" {
			return provider
		}
	}
	return nil
}

func getAdmins(organization string) []string {
	users := object.GetUsers(organization)
	var emails []string
	for _, user := range users {
		if user.IsAdmin {
			emails = append(emails, user.Email)
		}
	}
	return emails
}

func getPartnerManager(organization string) *object.User {
	users := object.GetUsers(organization)
	for _, user := range users {
		if user.IsAdmin {
			return user
		}
	}
	return nil
}

func getPartnerUser(organization string) *object.User {
	users := object.GetUsers(organization)
	for _, user := range users {
		if !user.IsAdmin {
			return user
		}
	}
	return nil
}

func getBuiltInAdmins() []string {
	users := object.GetUsers(builtInOrgCode)
	var emails []string
	for _, user := range users {
		if user.IsGlobalAdmin {
			emails = append(emails, user.Email)
		}
	}
	return emails
}
