package types

type UserRole string

const (
	UserRoleUnknown     UserRole = "unknown"
	UserRoleGlobalAdmin UserRole = "admin"
	UserRolePartner     UserRole = "partner"
	UserRoleDistributor UserRole = "distributor"
)
