package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsURLValid(t *testing.T) {
	assert.True(t, IsURLValid("http://google.com"))
	assert.True(t, IsURLValid("google.com"))
	assert.True(t, IsURLValid("http://w.com/cn"))
	assert.True(t, IsURLValid("http://192.158.0.1:90"))
	assert.True(t, IsURLValid("http://192.158.1/1"))
	assert.True(t, IsURLValid("/assets/img/casbin.svg"))
	assert.False(t, IsURLValid("javascript:alert()//."))
	assert.False(t, IsURLValid("javascript://192.158.1/1"))
	assert.False(t, IsURLValid("javascript:alert()"))

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
