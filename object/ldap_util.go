package object

import (
	"math"
)

var UacPropertyFlags = []string{
	"SCRIPT",
	"ACCOUNTDISABLE",
	"RESERVED",
	"HOMEDIR_REQUIRED",
	"LOCKOUT",
	"PASSWD_NOTREQD",
	"PASSWD_CANT_CHANGE",
	"ENCRYPTED_TEXT_PWD_ALLOWED",
	"TEMP_DUPLICATE_ACCOUNT",
	"NORMAL_ACCOUNT",
	"RESERVED",
	"INTERDOMAIN_TRUST_ACCOUNT",
	"WORKSTATION_TRUST_ACCOUNT",
	"SERVER_TRUST_ACCOUNT",
	"RESERVED",
	"RESERVED",
	"DONT_EXPIRE_PASSWORD",
	"MNS_LOGON_ACCOUNT",
	"SMARTCARD_REQUIRED",
	"TRUSTED_FOR_DELEGATION",
	"NOT_DELEGATED",
	"USE_DES_KEY_ONLY",
	"DONT_REQ_PREAUTH",
	"PASSWORD_EXPIRED",
	"TRUSTED_TO_AUTH_FOR_DELEGATION",
	"RESERVED",
	"PARTIAL_SECRETS_ACCOUNT",
	"RESERVED",
	"RESERVED",
	"RESERVED",
	"RESERVED",
	"RESERVED",
}

func ConvertUserAccountControl(uac int) []string {
	var flags []string

	for i, uacFlag := range UacPropertyFlags {
		if uac&int(math.Pow(2, float64(i))) != 0 {
			flags = append(flags, uacFlag)
		}
	}

	return flags
}
