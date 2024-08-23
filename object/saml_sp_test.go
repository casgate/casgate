package object

import (
	"reflect"
	"testing"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
)

func TestGetAuthData(t *testing.T) {
	id := "123"
	expected := map[string]interface{}{
		"ID":   []string{id},
		"Role": []string{"default", "testRole"},
	}
	tests := []struct {
		name          string
		assertionInfo *saml2.AssertionInfo
	}{
		{
			name: "single_role_disabled",
			assertionInfo: &saml2.AssertionInfo{
				NameID: id,
				Assertions: []types.Assertion{
					{
						AttributeStatement: &types.AttributeStatement{
							Attributes: []types.Attribute{
								{
									Name: "Role",
									Values: []types.AttributeValue{
										{
											Value: "default",
										},
									},
								},
								{
									Name: "Role",
									Values: []types.AttributeValue{
										{
											Value: "testRole",
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "single_role_enabled",
			assertionInfo: &saml2.AssertionInfo{
				NameID: id,
				Assertions: []types.Assertion{
					{
						AttributeStatement: &types.AttributeStatement{
							Attributes: []types.Attribute{
								{
									Name: "Role",
									Values: []types.AttributeValue{
										{
											Value: "default",
										},
										{
											Value: "testRole",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := getAuthData(tt.assertionInfo, &Provider{})
			if !reflect.DeepEqual(res, expected) {
				t.Error("getAuthData result differs from expected")
			}
		})
	}
}
