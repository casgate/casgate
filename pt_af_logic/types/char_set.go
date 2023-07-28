package types

const (
	LowerCharSet          = "abcdedfghijklmnopqrstuvwxyz"
	UpperCharSet          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	NumberSet             = "0123456789"
	SpecialCharSet        = "!#$%&\\\\'*+\\-/=?^\\`{|}~(_)."
	AllCharSet            = LowerCharSet + UpperCharSet + NumberSet
	AllCharSetWithSpecial = LowerCharSet + UpperCharSet + NumberSet + SpecialCharSet
)
