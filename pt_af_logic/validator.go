package pt_af_logic

import (
	"fmt"
	"regexp"
)

const MaxPtAfNameLength = 100

var (
	ptAfNameRegexp = regexp.MustCompile(fmt.Sprintf("^[%s]+$", allCharSetWithSpecial))
)

// ValidateName validate name for PT AF naming rules
func ValidateName(name string) error {
	if len(name) > MaxPtAfNameLength {
		return fmt.Errorf("name %s must be less than %d", name, MaxPtAfNameLength)
	}

	if !ptAfNameRegexp.MatchString(name) {
		return fmt.Errorf("name %s should contain only symbols from list: %s", name, allCharSetWithSpecial)
	}

	return nil
}
