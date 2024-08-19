package object

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildUserMappedRolesRecord(t *testing.T) {
	oldRoles := []*Role{
		{Owner: "owner1", Name: "name1"},
		{Owner: "owner1", Name: "name2"},
	}
	
	newRoles := []*Role{
		{Owner: "owner1", Name: "name3"},
		{Owner: "owner1", Name: "name4"},
	}

	expectedObjectMessage := map[string]interface{}{
		"userID":   "user123",
		"oldRoles": []string{"owner1/name1", "owner1/name2"},
		"newRoles": []string{"owner1/name3", "owner1/name4"},
	}

	expectedObjectMessageRaw, err := json.Marshal(expectedObjectMessage)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.WithValue(context.Background(), RoleMappingRecordDataKey, NewRecordBuilder())

	record := buildUserMappedRolesRecord(ctx, "user123", oldRoles, newRoles)

	assert.NotNil(t, record)
	assert.NotEmpty(t, record.Name)
	assert.Equal(t, string(expectedObjectMessageRaw), record.Object)
	assert.Equal(t, 0, record.Id)
}
