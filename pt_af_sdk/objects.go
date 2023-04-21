package af_client

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

type Role struct {
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
}
