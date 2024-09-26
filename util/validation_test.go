package util

import (
	"fmt"
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
}

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

func TestHasSymbolsIllegalForCasbin(t *testing.T) {
	testCases := []struct {
		description string
		input       string
		expected    bool
	}{
		{"upper and lower case cyrillic", "МаМа", false},
		{"ё", "ёж", false},
		{"other symbols", "role.name-_/@&$", false},
		{"space", "space bar", false},
		{"comma", "should,fail", true},
		{"newline1", "should\rfail", true},
		{"newline2", "should\nfail", true},
		{"newline3", "should\n\rfail", true},
		{"comment", "should#fail", true},
		{"quote", "should\"fail", true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			actual := HasSymbolsIllegalForCasbin(testCase.input)
			assert.Equal(t, testCase.expected, actual, fmt.Sprintf("unexpected return value for case: %s", testCase.description))
		})
	}
}
