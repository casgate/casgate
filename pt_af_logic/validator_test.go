package pt_af_logic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidator_ValidateName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		value string
		err   bool
	}{
		{
			name:  "valid name",
			value: "name2.Company_+-?\\!`",
		},
		{
			name:  "invalid name",
			value: "test test",
			err:   true,
		},
		{
			name:  "too long name",
			value: "tttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt",
			err:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := assert.New(t)

			err := ValidateName(tc.value)
			if tc.err {
				a.Error(err)
			} else {
				a.NoError(err)
			}
		})
	}
}
