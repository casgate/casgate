package pt_af_logic

import (
	"github.com/casdoor/casdoor/object"
	PTAFLTypes "github.com/casdoor/casdoor/pt_af_logic/types"
	"github.com/casdoor/casdoor/util"
)

func GetUserRole(user *object.User) PTAFLTypes.UserRole {
	if user == nil {
		return PTAFLTypes.UserRoleUnknown
	}

	if user.IsGlobalAdmin {
		return PTAFLTypes.UserRoleGlobalAdmin
	}

	if user.IsAdmin {
		return PTAFLTypes.UserRolePartner
	}
	role, _ := object.GetRole(util.GetId(PTAFLTypes.BuiltInOrgCode, string(PTAFLTypes.UserRoleDistributor)))
	if role != nil {
		userId := user.GetId()
		for _, roleUserId := range role.Users {
			if roleUserId == userId {
				return PTAFLTypes.UserRoleDistributor
			}
		}
	}

	return PTAFLTypes.UserRoleUnknown

}
