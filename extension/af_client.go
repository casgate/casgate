package af_client

import (
	"crypto/tls"
	"encoding/json"
	"github.com/casdoor/casdoor/util"
	"io/ioutil"
	"net/http"
	"strings"
)

//const token = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJ1c2VyIjp7ImlkIjoiOGUzMWNhOGQtOWM2Yy00OWYyLTg3ZTItZjE2NjgyYmE1MTJiIiwidXNlcm5hbWUiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AcHRzZWN1cml0eS5jb20iLCJwZXJtaXNzaW9ucyI6WyJhdXRoLmFjY291bnQudmlldyIsImF1dGguYWNjb3VudC51cGRhdGUiLCJhdXRoLnRlbmFudHMuY3JlYXRlIiwiYXV0aC50ZW5hbnRzLmRlbGV0ZSIsImF1dGgudGVuYW50cy51cGRhdGUiLCJtb25pdG9yaW5nLmRhdGFiYXNlcy5saXN0IiwibW9uaXRvcmluZy5zeXN0ZW0ubGlzdCIsImxpY2Vuc2UubGljZW5zZS5jcmVhdGUiLCJsaWNlbnNlLmxpY2Vuc2UudXBkYXRlIiwiYmFja3Vwcy5iYWNrdXBzLmxpc3QiLCJiYWNrdXBzLmJhY2t1cHMuY3JlYXRlIiwiYmFja3Vwcy5iYWNrdXBzLnZpZXciLCJiYWNrdXBzLmJhY2t1cHMudXBkYXRlIiwiYmFja3Vwcy5iYWNrdXBzLmRlbGV0ZSIsImJhY2t1cHMucmVzdG9yaW5ncy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLnJ1bGVfc2V0X3VwZGF0ZXMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5hY3Rpb25zLmxpc3QiLCJjb25maWd1cmF0aW9uLmFjdGlvbnMudmlldyIsImNvbmZpZ3VyYXRpb24uYXBwbGljYXRpb25zLmxpc3QiLCJjb25maWd1cmF0aW9uLmFwcGxpY2F0aW9ucy52aWV3IiwiY29uZmlndXJhdGlvbi5hcHBsaWNhdGlvbnMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5hcHBsaWNhdGlvbnMuZGVsZXRlIiwiY29uZmlndXJhdGlvbi5hcHBsaWNhdGlvbnMudXBkYXRlIiwiY29uZmlndXJhdGlvbi5wb2xpY2llcy5saXN0IiwiY29uZmlndXJhdGlvbi5wb2xpY2llcy52aWV3IiwiY29uZmlndXJhdGlvbi5wb2xpY2llcy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLnBvbGljaWVzLmRlbGV0ZSIsImNvbmZpZ3VyYXRpb24ucG9saWNpZXMudXBkYXRlIiwiYXV0aC51c2Vycy5saXN0IiwiYXV0aC51c2Vycy52aWV3IiwiYXV0aC51c2Vycy5jcmVhdGUiLCJhdXRoLnVzZXJzLmRlbGV0ZSIsImF1dGgudXNlcnMudXBkYXRlIiwiYXV0aC5wZXJtaXNzaW9ucy5saXN0IiwicmVwb3J0cy5yZXBvcnRzLmxpc3QiLCJyZXBvcnRzLnJlcG9ydHMudmlldyIsInJlcG9ydHMucmVwb3J0cy5jcmVhdGUiLCJyZXBvcnRzLnJlcG9ydHMuZGVsZXRlIiwidGFza3Muc2NoZWR1bGVzLmxpc3QiLCJ0YXNrcy5zY2hlZHVsZXMudmlldyIsInRhc2tzLnNjaGVkdWxlcy5jcmVhdGUiLCJ0YXNrcy5zY2hlZHVsZXMuZGVsZXRlIiwidGFza3Muc2NoZWR1bGVzLnVwZGF0ZSIsInRhc2tzLnRhc2tzLmxpc3QiLCJ0YXNrcy50YXNrcy52aWV3IiwidGFza3MudGFza3MuY3JlYXRlIiwidGFza3MudGFza3MudXBkYXRlIiwidGhyZWF0cy50aHJlYXRzLmxpc3QiLCJsaWNlbnNlLmxpY2Vuc2UubGlzdCIsImF1dGguY3VycmVudF90ZW5hbnQudmlldyIsImF1dGgudGVuYW50cy5saXN0IiwiYXV0aC50ZW5hbnRzLnZpZXciLCJjb25maWd1cmF0aW9uLnBvbGljeV90ZW1wbGF0ZXMubGlzdCIsImNvbmZpZ3VyYXRpb24ucG9saWN5X3RlbXBsYXRlcy52aWV3IiwiY29uZmlndXJhdGlvbi5wb2xpY3lfdGVtcGxhdGVzLmNyZWF0ZSIsImNvbmZpZ3VyYXRpb24ucG9saWN5X3RlbXBsYXRlcy5kZWxldGUiLCJjb25maWd1cmF0aW9uLnBvbGljeV90ZW1wbGF0ZXMudXBkYXRlIiwiY29uZmlndXJhdGlvbi5iYWNrZW5kcy5saXN0IiwiY29uZmlndXJhdGlvbi5iYWNrZW5kcy52aWV3IiwiY29uZmlndXJhdGlvbi5iYWNrZW5kcy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLmJhY2tlbmRzLmRlbGV0ZSIsImNvbmZpZ3VyYXRpb24uYmFja2VuZHMudXBkYXRlIiwiY29uZmlndXJhdGlvbi50cmFmZmljX3Byb2ZpbGVzLmxpc3QiLCJjb25maWd1cmF0aW9uLnRyYWZmaWNfcHJvZmlsZXMudmlldyIsImNvbmZpZ3VyYXRpb24udHJhZmZpY19wcm9maWxlcy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLnRyYWZmaWNfcHJvZmlsZXMuZGVsZXRlIiwiY29uZmlndXJhdGlvbi50cmFmZmljX3Byb2ZpbGVzLnVwZGF0ZSIsImNvbmZpZ3VyYXRpb24uc3NsLmxpc3QiLCJjb25maWd1cmF0aW9uLnNzbC52aWV3IiwiY29uZmlndXJhdGlvbi5zc2wuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5zc2wuZGVsZXRlIiwiY29uZmlndXJhdGlvbi5zc2wudXBkYXRlIiwiY29uZmlndXJhdGlvbi52aXBzLmxpc3QiLCJjb25maWd1cmF0aW9uLnZpcHMudmlldyIsImNvbmZpZ3VyYXRpb24udmlwcy5jcmVhdGUiLCJjb25maWd1cmF0aW9uLnZpcHMuZGVsZXRlIiwiY29uZmlndXJhdGlvbi52aXBzLnVwZGF0ZSIsImF1dGgucm9sZXMuY3JlYXRlIiwiYXV0aC5yb2xlcy5kZWxldGUiLCJhdXRoLnJvbGVzLmxpc3QiLCJhdXRoLnJvbGVzLnVwZGF0ZSIsImF1dGgucm9sZXMudmlldyIsImFib3V0LnN5c3RlbS52aWV3IiwiY29uZmlndXJhdGlvbi5ydWxlX3NldF91cGRhdGVzLnZpZXciLCJjb25maWd1cmF0aW9uLmFjdGlvbnMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5hY3Rpb25zLmRlbGV0ZSIsImNvbmZpZ3VyYXRpb24uYWN0aW9ucy51cGRhdGUiLCJhdWRpdC5ldmVudHMubGlzdCIsImF1ZGl0LmV2ZW50cy52aWV3IiwibW9uaXRvcmluZy5jb25maWd1cmF0aW9uLnZpZXciLCJjb25maWd1cmF0aW9uLnVzZXJfcnVsZXMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi51c2VyX3J1bGVzLmRlbGV0ZSIsImNvbmZpZ3VyYXRpb24udXNlcl9ydWxlcy51cGRhdGUiLCJjb25maWd1cmF0aW9uLnVzZXJfcnVsZXMudmlldyIsImNvbmZpZ3VyYXRpb24udXNlcl9ydWxlcy5saXN0IiwiY29uZmlndXJhdGlvbi5nbG9iYWxfbGlzdHMuY3JlYXRlIiwiY29uZmlndXJhdGlvbi5nbG9iYWxfbGlzdHMuZGVsZXRlIiwiY29uZmlndXJhdGlvbi5nbG9iYWxfbGlzdHMudXBkYXRlIiwiY29uZmlndXJhdGlvbi5nbG9iYWxfbGlzdHMudmlldyIsImNvbmZpZ3VyYXRpb24uZ2xvYmFsX2xpc3RzLmxpc3QiLCJjb25maWd1cmF0aW9uLnJ1bGVfc2V0X3VwZGF0ZXMubGlzdCIsInJlc291cmNlcy5ub2Rlcy5saXN0IiwiYXVkaXQuc3lzdGVtX2V2ZW50cy5saXN0IiwiYXVkaXQuc3lzdGVtX2V2ZW50cy52aWV3IiwiY29uZmlndXJhdGlvbi5pbnRlcm5hbF9iYWxhbmNlci52aWV3IiwiaW5zdGFsbGF0aW9uLm9uX3ByZW1pc2UudmlldyJdLCJ0ZW5hbnRfaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAifSwibGlmZV90aW1lIjo5OTk5OTk5OTksImV4cCI6MjY4MTkzNjQ5MCwianRpIjoiNjZhOTUxNjItNmRjMS00NTEwLWE0ODItZTZhNjg5NjM3MDI5In0.87tBddp9CnqmJVtzGb5m0Q83mlFEa4Ul_t_oqDxrjHIwrSZyX9t9kLyKNgyYTcpX6LHIwHJW8H2yncZjEKYm2g"

const host = "https://m1-26.af.rd.ptsecurity.ru/api/ptaf/v4/"

type LoginRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Fingerprint string `json:"fingerprint"`
}

type LoginResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type TenantRequest struct {
	Name              string                   `json:"name"`
	Description       string                   `json:"description"`
	IsActive          bool                     `json:"is_active"`
	TrafficProcessing TrafficProcessingRequest `json:"traffic_processing"`
	Administrator     AdministratorRequest     `json:"administrator"`
}

type TrafficProcessingRequest struct {
	TrafficProcessingType string `json:"traffic_processing_type"`
}

type AdministratorRequest struct {
	Email                  string `json:"email"`
	Username               string `json:"username"`
	Password               string `json:"password"`
	PasswordChangeRequired bool   `json:"password_change_required"`
}

type Tenant struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	Description            string            `json:"description"`
	IsDefault              bool              `json:"is_default"`
	IsActive               bool              `json:"is_active"`
	BorderConnectionString string            `json:"border_connection_string"`
	TrafficProcessing      TrafficProcessing `json:"traffic_processing"`
	Administrator          Administrator     `json:"administrator"`
}

type TrafficProcessing struct {
	TrafficProcessingType string `json:"traffic_processing_type"`
	Zone                  string `json:"zone"`
	MaxPods               int    `json:"max_pods"`
	MinPods               int    `json:"min_pods"`
	PodSize               string `json:"pod_size"`
	MaxPodsPerNode        int    `json:"max_pods_per_node"`
	MinPodsPerNode        int    `json:"min_pods_per_node"`
}

type Administrator struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	IsActive bool   `json:"is_active"`
}

type CreateUserRequest struct {
	Username               string `json:"username"`
	Email                  string `json:"email"`
	Password               string `json:"password"`
	Role                   string `json:"role"`
	PasswordChangeRequired bool   `json:"password_change_required"`
	IsActive               bool   `json:"is_active"`
}

type Role struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}

type Permission struct {
	Namespace string   `json:"namespace"`
	Entity    string   `json:"entity"`
	Actions   []string `json:"actions"`
}

type RolesSettings struct {
	Roles []Role `json:"roles"`
}

type CreateRoleResponse struct {
	Id          string `json:"id"`
	IsDefault   bool   `json:"is_default"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Permissions []struct {
		Namespace string   `json:"namespace"`
		Entity    string   `json:"entity"`
		Actions   []string `json:"actions"`
	} `json:"permissions"`
}

func Login(request LoginRequest) (*LoginResponse, error) {
	//dev only. should be remove in production
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	body := strings.NewReader(util.StructToJson(request))
	req, _ := http.NewRequest("POST", host+"auth/refresh_tokens", body)

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	responseContent := string(response)

	result := &LoginResponse{}

	err = util.JsonToStruct(responseContent, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func CreateTenant(request TenantRequest) (*Tenant, error) {

	loginRequest := LoginRequest{
		Username:    "admin",
		Password:    "P@ssw0rd",
		Fingerprint: "qwe",
	}

	token, err := Login(loginRequest)

	//dev only. should be remove in production
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	body := strings.NewReader(util.StructToJson(request))
	req, _ := http.NewRequest("POST", host+"auth/tenants", body)

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	responseContent := string(response)

	result := &Tenant{}

	err = util.JsonToStruct(responseContent, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func CreateUser(token string, request CreateUserRequest) {

	//dev only. should be remove in production
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	body := strings.NewReader(util.StructToJson(request))
	req, _ := http.NewRequest("POST", host+"auth/users", body)

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	responseContent := string(response)

	print(responseContent)
}

func GetRoles() []Role {

	path := "roles.json"

	if !util.FileExist(path) {
		return nil
	}

	file := util.ReadStringFromPath(path)

	var settings RolesSettings
	err := json.Unmarshal([]byte(file), &settings)
	if err != nil {
		panic(err)
	}

	return settings.Roles
}

func CreateRole(token string, request Role) (string, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	body := strings.NewReader(util.StructToJson(request))
	req, _ := http.NewRequest("POST", host+"auth/roles", body)

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)

	response, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	responseContent := string(response)

	result := &CreateRoleResponse{}

	err = util.JsonToStruct(responseContent, result)
	if err != nil {
		return "", err
	}

	return result.Id, nil
}
