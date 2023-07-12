package pt_af_logic

// default organization
const builtInOrgCode = "built-in"

const logEmail = "lmp-log@ptsecurity.com"

const (
	lowerCharSet          = "abcdedfghijklmnopqrstuvwxyz"
	upperCharSet          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numberSet             = "0123456789"
	specialCharSet        = "!#$%&\\\\'*+\\-/=?^\\`{|}~(_)."
	allCharSet            = lowerCharSet + upperCharSet + numberSet
	allCharSetWithSpecial = lowerCharSet + upperCharSet + numberSet + specialCharSet
)
