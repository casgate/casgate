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
}
