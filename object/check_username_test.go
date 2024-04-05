package object

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckUsername(t *testing.T) {

	for _, username := range []string{
		strings.Repeat("a", 255),
		"Admin",
		"Admin.Admin",
		"admin@mail.com",
		"Admin111",
		"123456789",
		"A",
		"a!#$%&'*+/=?^_`{|}~-@.z",
	} {
		t.Run("Valid usernames", func(t *testing.T) {
			msg := CheckUsername(username, "en")
			assert.True(t, len(msg) == 0)
		})
	}

	for _, username := range []string{
		"",
		strings.Repeat("a", 256),
		".Abc",
		"123-",
		"---",
	} {
		t.Run("Invalid usernames", func(t *testing.T) {
			msg := CheckUsername(username, "en")
			assert.True(t, len(msg) > 0)
		})
	}
}
