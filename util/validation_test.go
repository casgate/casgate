package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsFieldValueAllowedForDB(t *testing.T) {
	testCases := []struct {
		description string
		input       string
		expected    bool
	}{
		{"valid value", "name", true},
		{"sql injection", "name/**/is/**/not/**/null/**/and/**/1=(select/**/cast('a'/**/as/**/int))/**/and/**/name/**/", false},
		{"camelCase", "SignupApplication", true},
		{"value with spaces", "Signup Application", false},
	}
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			actual := IsFieldValueAllowedForDB(testCase.input)
			assert.Equal(t, testCase.expected, actual, "The returned value not is expected")
		})
	}
}
