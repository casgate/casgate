package pt_af_logic

import (
	"fmt"
	"regexp"

	"github.com/casdoor/casdoor/pt_af_logic/types"
)

const MaxPtAfNameLength = 100

var (
	ptAfNameRegexp = regexp.MustCompile(fmt.Sprintf("^[%s]+$", types.AllCharSetWithSpecial))
)

// ValidateName validate name for PT AF naming rules
func ValidateName(name string) error {
	if len(name) > MaxPtAfNameLength {
		return fmt.Errorf("name %s must be less than %d", name, MaxPtAfNameLength)
	}

	if !ptAfNameRegexp.MatchString(name) {
		return fmt.Errorf("name %s should contain only symbols from list: %s", name, types.AllCharSetWithSpecial)
	}

	return nil
}
