package object_test

import (
	"reflect"
	"testing"

	"github.com/casdoor/casdoor/object"
)

func sliceToMap(slice []string) map[string]bool {
	m := make(map[string]bool)
	for _, item := range slice {
		m[item] = true
	}
	return m
}

func TestConvertUserAccountControl(t *testing.T) {
	tests := []struct {
		uac      int
		expected []string
	}{
		{512, []string{"NORMAL_ACCOUNT"}},
		{514, []string{"ACCOUNTDISABLE", "NORMAL_ACCOUNT"}},
		{544, []string{"NORMAL_ACCOUNT", "PASSWD_NOTREQD"}},
		{66048, []string{"NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"}},
		{66050, []string{"ACCOUNTDISABLE", "NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"}},
	}

	for _, test := range tests {
		result := object.ConvertUserAccountControl(test.uac)
		resultMap := sliceToMap(result)
		expectedMap := sliceToMap(test.expected)
		if !reflect.DeepEqual(resultMap, expectedMap) {
			t.Errorf("ConvertUserAccountControl(%d) = %v; want %v", test.uac, result, test.expected)
		}
	}
}
