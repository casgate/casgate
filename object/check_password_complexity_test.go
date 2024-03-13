package object

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidOption_SpecialChar(t *testing.T) {
	for _, p := range []string{
		"Passw0rd!@",
		"!@Test123",
		"Pa$sw0rd",
		"Special_123!",
		"Long-Password#1",
		"Testing;Special:",
		"Super?Secret!123",
		"My~Password_2023",
		"Security&Pass1234",
		"Awesome*Password`",
		"Pa(ssw0rd!@",
		"!@Te)st123",
		"Sp{ec}ial_123!",
		"Long[Pass]word#1",
		"Testing;Spe(cial:",
		"{",
		"}",
		"(",
		")",
		"]",
		"[",
	} {
		t.Run("Password with special characters", func(t *testing.T) {
			result := isValidOption_SpecialChar(p)
			assert.True(t, len(result) == 0)
		})
	}

	for _, p := range []string{
		"Password123",
		"abc123",
		"TestPassword",
	} {
		t.Run("Password without special characters", func(t *testing.T) {
			result := isValidOption_SpecialChar(p)
			assert.True(t, len(result) > 0)
		})
	}
}
