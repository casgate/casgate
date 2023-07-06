package pt_af_logic

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"strconv"
	"time"

	"github.com/beego/beego/context"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/object"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
	"github.com/casdoor/casdoor/util"
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
	UserName            string
	UserPwd             string
	TenantAdminName     string
	TenantAdminPassword string
	PTAFLoginLink       string
	ConnectionString    string
}

type PartnerConfirmedMessage struct {
	PartnerUserName string
	PartnerLoginURL string
}

type SubscriptionUpdatedMessage struct {
	//title
	SubscriptionName   string
	PartnerName        string
	ClientName         string
	SubscriptionStatus string
	//body
	PartnerDisplayName         string
	PartnerURL                 string
	SubscriptionURL            string
	ClientDisplayName          string
	ClientURL                  string
	OldPlanDisplayName         string
	OldPlanURL                 string
	PlanURL                    string
	PlanDisplayName            string
	OldSubscriptionDiscount    string
	SubscriptionDiscount       string
	OldSubscriptionStartDate   string
	SubscriptionStartDate      string
	OldSubscriptionEndDate     string
	SubscriptionEndDate        string
	OldSubscriptionStatus      string
	OldSubscriptionDescription string
	SubscriptionDescription    string
	OldSubscriptionComment     string
	SubscriptionComment        string
	SubscriptionCreator        string
	SubscriptionCreatorURL     string
	SubscriptionMover          string
	SubscriptionMoverURL       string
	SubscriptionMoveTime       string
	SubscriptionEditor         string
	SubscriptionEditorURL      string
	SubscriptionEditTime       string
}

type SubscriptionUpdatedPartnerMessage struct {
}

const (
	ptlmLanguage = "lm"

	partnerConfirmedSubject = `[PT LMP] Registration confirmed`
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

// NotifySubscriptionUpdated composes subscription state change message and sends emails to its members
func NotifySubscriptionUpdated(ctx *context.Context, actor *object.User, current, old *object.Subscription) error {
	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}
	if current.User == "" {
		return errors.New("no client detected in subscription")
	}

	stateChanged := old.State != current.State

	switch current.State {
	case PTAFLTypes.SubscriptionNew.String():
		return nil
	case PTAFLTypes.SubscriptionPreAuthorized.String(), PTAFLTypes.SubscriptionUnauthorized.String():
		if stateChanged {
			err := NotifyPartnerSubscriptionUpdated(actor, current, old)
			if err != nil {
				util.LogError(ctx, fmt.Errorf("NotifyPartnerSubscriptionUpdated: %w", err).Error())
			}
		}
	case PTAFLTypes.SubscriptionAuthorized.String(), PTAFLTypes.SubscriptionPreFinished.String():
		if stateChanged {
			recipients := getDistributors(ctx)
			err := NotifyAdminDistributorSubscriptionUpdated(actor, current, old, recipients)
			if err != nil {
				util.LogError(ctx, fmt.Errorf("NotifyAdminDistributorSubscriptionUpdated(distributors): %w", err).Error())
			}
		}
	}

	// send admin notification
	recipients := getBuiltInAdmins()
	err := NotifyAdminDistributorSubscriptionUpdated(actor, current, old, recipients)
	if err != nil {
		util.LogError(ctx, fmt.Errorf("NotifyAdminDistributorSubscriptionUpdated(admins): %w", err).Error())
	}

	return nil
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

func getDistributors(ctx *context.Context) []string {
	var emails []string
	role, _ := object.GetRole(util.GetId(builtInOrgCode, string(PTAFLTypes.UserRoleDistributor)))
	if role != nil {
		for _, roleUserId := range role.Users {
			roleUser, err := object.GetUser(roleUserId)
			if err != nil {
				util.LogError(ctx, fmt.Errorf("object.GetUser: %w", err).Error())
			}
			if roleUser != nil && roleUser.Email != "" {
				emails = append(emails, roleUser.Email)
			}
		}
	}
	return emails
}

func NotifyAdminDistributorSubscriptionUpdated(actor *object.User, current, old *object.Subscription, recipients []string) error {
	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}

	msg, err := getSubscriptionUpdateMessage(actor, current, old)
	if err != nil {
		return fmt.Errorf("getSubscriptionUpdateMessage: %w", err)
	}

	titleTmpl, err := template.New("").Parse(SubscriptionUpdatedSubjTmpl)
	if err != nil {
		return fmt.Errorf("template.Parse(title): %w", err)
	}

	var titleBuf bytes.Buffer
	err = titleTmpl.Execute(&titleBuf, msg)
	if err != nil {
		return fmt.Errorf("titleTmpl.Execute: %w", err)
	}

	bodyTmpl, err := template.New("").Parse(SubscriptionUpdatedBodyTmpl)
	if err != nil {
		return fmt.Errorf("template.Parse(body): %w", err)
	}

	var bodyBuf bytes.Buffer
	if err := bodyTmpl.Execute(&bodyBuf, msg); err != nil {
		return fmt.Errorf("tmpl.Execute: %w", err)
	}

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

func NotifyPartnerSubscriptionUpdated(actor *object.User, current, old *object.Subscription) error {
	provider := getBuiltInEmailProvider()
	if provider == nil {
		return errors.New("no email provider registered")
	}
	orgId := fmt.Sprintf("admin/%s", current.Owner)
	organization, err := object.GetOrganization(orgId)
	if err != nil {
		return fmt.Errorf("object.GetOrganization: %w", err)
	}
	if organization.Email == "" {
		return nil
	}

	msg, err := getSubscriptionUpdateMessage(actor, current, old)
	if err != nil {
		return fmt.Errorf("getSubscriptionUpdateMessage: %w", err)
	}

	titleTmpl, err := template.New("").Parse(SubscriptionUpdatedPartnerSubjTmpl)
	if err != nil {
		return fmt.Errorf("template.Parse(title): %w", err)
	}

	var titleBuf bytes.Buffer
	err = titleTmpl.Execute(&titleBuf, msg)
	if err != nil {
		return fmt.Errorf("titleTmpl.Execute: %w", err)
	}

	bodyTmpl, err := template.New("").Parse(SubscriptionUpdatedPartnerBodyTmpl)
	if err != nil {
		return fmt.Errorf("template.Parse(body): %w", err)
	}

	var bodyBuf bytes.Buffer
	if err := bodyTmpl.Execute(&bodyBuf, msg); err != nil {
		return fmt.Errorf("tmpl.Execute: %w", err)
	}
	err = object.SendEmail(provider, titleBuf.String(), bodyBuf.String(), organization.Email, provider.DisplayName)
	if err != nil {
		return fmt.Errorf("object.SendEmail: %w", err)
	}

	return nil
}

func getSubscriptionUpdateMessage(actor *object.User, current, old *object.Subscription) (*SubscriptionUpdatedMessage, error) {
	orgId := fmt.Sprintf("admin/%s", current.Owner)
	organization, err := object.GetOrganization(orgId)
	if err != nil {
		return nil, fmt.Errorf("object.GetOrganization: %w", err)
	}

	client, err := object.GetUser(current.User)
	if err != nil {
		return nil, fmt.Errorf("object.GetUser: %w", err)
	}

	var (
		oldPlanDisplayName     string
		oldPlanName            string
		currentPlanDisplayName string
		currentPlanName        string
	)

	if old.Plan != "" {
		oldPlan, err := object.GetPlan(old.Plan)
		if err != nil {
			return nil, fmt.Errorf("object.GetPlan(old): %w", err)
		}
		oldPlanDisplayName = oldPlan.DisplayName
		oldPlanName = oldPlan.Name
	}

	if current.Plan != "" {
		plan, err := object.GetPlan(current.Plan)
		if err != nil {
			return nil, fmt.Errorf("object.GetPlan(current): %w", err)
		}
		currentPlanDisplayName = plan.DisplayName
		currentPlanName = plan.Name
	}

	submitter, err := object.GetUser(current.Submitter)
	if err != nil {
		return nil, fmt.Errorf("object.GetUser(submitter): %w", err)
	}

	approver, err := object.GetUser(current.Approver)
	if err != nil {
		return nil, fmt.Errorf("object.GetUser(approver): %w", err)
	}

	mskLoc, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		return nil, fmt.Errorf("time.LoadLocation: %w", err)
	}

	approverTime, err := time.Parse("2006-01-02T15:04:05Z07:00", current.ApproveTime)
	if err != nil {
		return nil, fmt.Errorf("time.Parse: %w", err)
	}

	var (
		oldSubscriptionStartDate string
		subscriptionStartDate    string
		oldSubscriptionEndDate   string
		subscriptionEndDate      string
	)

	if !old.StartDate.IsZero() {
		oldSubscriptionStartDate = old.StartDate.In(mskLoc).Format("2006-01-02 15:04:05")
	}
	if !old.EndDate.IsZero() {
		oldSubscriptionEndDate = old.EndDate.In(mskLoc).Format("2006-01-02 15:04:05")
	}
	if !current.StartDate.IsZero() {
		subscriptionStartDate = current.StartDate.In(mskLoc).Format("2006-01-02 15:04:05")
	}
	if !current.EndDate.IsZero() {
		subscriptionEndDate = current.EndDate.In(mskLoc).Format("2006-01-02 15:04:05")
	}

	return &SubscriptionUpdatedMessage{
		SubscriptionName:           current.Name,
		PartnerName:                organization.Name,
		ClientName:                 client.Name,
		SubscriptionStatus:         i18n.Translate(ptlmLanguage, fmt.Sprintf("subscription:%s", current.State)),
		PartnerDisplayName:         organization.DisplayName,
		PartnerURL:                 fmt.Sprintf("%s/organizations/%s", conf.GetConfigString("origin"), organization.Name),
		SubscriptionURL:            fmt.Sprintf("%s/subscriptions/%s/%s", conf.GetConfigString("origin"), organization.Name, current.Name),
		ClientDisplayName:          client.DisplayName,
		ClientURL:                  fmt.Sprintf("%s/users/%s/%s", conf.GetConfigString("origin"), organization.Name, client.Name),
		OldPlanDisplayName:         oldPlanDisplayName,
		OldPlanURL:                 fmt.Sprintf("%s/plans/%s/%s", conf.GetConfigString("origin"), organization.Name, oldPlanName),
		PlanURL:                    fmt.Sprintf("%s/plans/%s/%s", conf.GetConfigString("origin"), organization.Name, currentPlanName),
		PlanDisplayName:            currentPlanDisplayName,
		OldSubscriptionDiscount:    strconv.FormatInt(int64(old.Discount), 10),
		SubscriptionDiscount:       strconv.FormatInt(int64(current.Discount), 10),
		OldSubscriptionStartDate:   oldSubscriptionStartDate,
		SubscriptionStartDate:      subscriptionStartDate,
		OldSubscriptionEndDate:     oldSubscriptionEndDate,
		SubscriptionEndDate:        subscriptionEndDate,
		OldSubscriptionStatus:      i18n.Translate(ptlmLanguage, fmt.Sprintf("subscription:%s", old.State)),
		OldSubscriptionDescription: old.Description,
		SubscriptionDescription:    current.Description,
		OldSubscriptionComment:     old.Comment,
		SubscriptionComment:        current.Comment,
		SubscriptionCreator:        submitter.Name,
		SubscriptionCreatorURL:     fmt.Sprintf("%s/users/%s/%s", conf.GetConfigString("origin"), submitter.Owner, submitter.Name),
		SubscriptionMover:          approver.Name,
		SubscriptionMoverURL:       fmt.Sprintf("%s/users/%s/%s", conf.GetConfigString("origin"), approver.Owner, approver.Name),
		SubscriptionMoveTime:       approverTime.In(mskLoc).Format("2006-01-02 15:04:05"),
		SubscriptionEditor:         actor.Name,
		SubscriptionEditorURL:      fmt.Sprintf("%s/users/%s/%s", conf.GetConfigString("origin"), actor.Owner, actor.Name),
		SubscriptionEditTime:       time.Now().In(mskLoc).Format("2006-01-02 15:04:05"),
	}, nil
}
