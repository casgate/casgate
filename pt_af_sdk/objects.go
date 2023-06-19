package af_client

const PtPropPref = "[PT AF]"

type LoginRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Fingerprint string `json:"fingerprint"`
}

type LoginResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type Tenant struct {
	ID                     string            `json:"id,omitempty"`
	Name                   string            `json:"name,omitempty"`
	Description            string            `json:"description,omitempty"`
	IsDefault              bool              `json:"is_default"`
	IsActive               bool              `json:"is_active"`
	BorderConnectionString string            `json:"border_connection_string,omitempty"`
	TrafficProcessing      TrafficProcessing `json:"traffic_processing,omitempty"`
	Administrator          Administrator     `json:"administrator,omitempty"`
}

type TrafficProcessing struct {
	TrafficProcessingType string `json:"traffic_processing_type,omitempty"`
	Zone                  string `json:"zone,omitempty"`
	MaxPods               int    `json:"max_pods,omitempty"`
	MinPods               int    `json:"min_pods,omitempty"`
	PodSize               string `json:"pod_size,omitempty"`
	MaxPodsPerNode        int    `json:"max_pods_per_node,omitempty"`
	MinPodsPerNode        int    `json:"min_pods_per_node,omitempty"`
}

type Administrator struct {
	ID                     string `json:"id,omitempty"`
	Email                  string `json:"email,omitempty"`
	Username               string `json:"username,omitempty"`
	Password               string `json:"password,omitempty"`
	IsActive               bool   `json:"is_active"`
	PasswordChangeRequired bool   `json:"password_change_required"`
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
