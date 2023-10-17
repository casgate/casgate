package object

var defaultPolicyMappingRules = [][]string{
	{"p", "permission.user", "permission.resource", "permission.action", "permission.effect"},
	{"p", "role.name", "permission.resource", "permission.action", "permission.effect"},
	{"g", "role.subrole", "role.name"},
	{"g", "role.user", "role.name"},
}

var defaultPolicyDomainMappingRules = [][]string{
	{"p", "permission.user", "permission.domain.name", "permission.resource", "permission.action", "permission.effect"},
	{"p", "role.name", "permission.domain.name", "permission.resource", "permission.action", "permission.effect"},
	{"g", "role.subrole", "role.name", "permission.domain.name"},
	{"g", "role.user", "role.name", "permission.domain.name"},
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

type policyType interface {
	policyRole | policyGroup | policyDomain
}

type casbinPolicy [7]string
type casbinPolicies []casbinPolicy

type Entities struct {
	DomainsTree  map[string]*TreeNode[*Domain]
	RolesTree    map[string]*TreeNode[*Role]
	GroupsTree   map[string]*TreeNode[*Group]
	UsersByGroup map[string][]*User
	Model        *Model
}

type NodeValueType interface {
	GetId() string
}

type TreeNode[T NodeValueType] struct {
	ancestors []*TreeNode[T]
	value     T
	children  []*TreeNode[T]
}
