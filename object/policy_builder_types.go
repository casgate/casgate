package object

var defaultPolicyMappingRules = [][]string{
	{"p", "permission.user", "permission.resource", "permission.action", "permission.effect"},
	{"p", "role.name", "permission.resource", "permission.action", "permission.effect"},
	{"g", "role.subrole", "role.name"},
	{"g", "role.user", "role.name"},
}

var defaultPolicyDomainMappingRules = [][]string{
	{"p", "permission.user", "permission.domain", "permission.resource", "permission.action", "permission.effect"},
	{"p", "role.name", "permission.domain", "permission.resource", "permission.action", "permission.effect"},
	{"g", "role.subrole", "role.name", "permission.domain"},
	{"g", "role.user", "role.name", "permission.domain"},
}

type policyDomain struct {
	id        string
	name      string
	subDomain string
}

type policyGroup struct {
	id          string
	name        string
	parentGroup string
	user        string
}

type policyRole struct {
	id      string
	name    string
	domain  policyDomain
	user    string
	group   policyGroup
	subRole string

	empty bool
}

type policyPermission struct {
	id       string
	domain   policyDomain
	resource string
	action   string
	role     policyRole
	user     string
	group    policyGroup
	effect   string

	empty bool
}

type casbinPolicy [7]string
type casbinPolicies []casbinPolicy

type Entities struct {
	DomainsTree  map[string]*DomainTreeNode
	RolesTree    map[string]*RoleTreeNode
	GroupsTree   map[string]*GroupTreeNode
	UsersByGroup map[string][]*User
	Model        *Model
}
