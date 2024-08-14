package object

import (
	"context"
	"errors"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
)

// Mock implementations of the interfaces
type MockLdapSynchronizer struct {
	sync.Mutex
	syncCalled int
}

func (m *MockLdapSynchronizer) SyncUsers(_ context.Context, _ *Ldap) error {
	m.Lock()
	m.syncCalled++
	m.Unlock()
	return nil
}

type MockLdapRepository struct {
	ldapMap map[string]*Ldap
}

func (m *MockLdapRepository) GetLdap(id string) (*Ldap, error) {
	ldap, exists := m.ldapMap[id]
	if !exists {
		return nil, errors.New("LDAP not found")
	}
	return ldap, nil
}

func TestLdapSynchronizationManager_StartAutoSync(t *testing.T) {
	ctx := context.Background()

	mockSynchronizer := &MockLdapSynchronizer{}
	mockRepo := &MockLdapRepository{
		ldapMap: map[string]*Ldap{
			"ldap1": {Id: "ldap1"},
		},
	}

	manager := NewLdapAutoSynchronizer(mockSynchronizer, mockRepo)
	recordBuilder := &RecordBuilder{}

	err := manager.StartAutoSync(ctx, "ldap1", time.Minute, recordBuilder)
	assert.Nil(t, err)

	// Verify the sync process was started
	time.Sleep(500 * time.Microsecond)
	mockSynchronizer.Lock()
	assert.Equal(t, 1, mockSynchronizer.syncCalled, "Expected sync to be called")
	mockSynchronizer.Unlock()

	// Verify that the stop channel is created
	manager.Lock()
	_, exists := manager.ldapIdToStopChan["ldap1"]
	manager.Unlock()
	assert.True(t, exists, "Expected stop channel to be created")
}

func TestLdapSynchronizationManager_StopAutoSync(t *testing.T) {
	ctx := context.Background()

	mockSynchronizer := &MockLdapSynchronizer{}
	mockRepo := &MockLdapRepository{
		ldapMap: map[string]*Ldap{
			"ldap1": {Id: "ldap1"},
		},
	}

	manager := NewLdapAutoSynchronizer(mockSynchronizer, mockRepo)
	recordBuilder := &RecordBuilder{}

	// Start auto sync
	err := manager.StartAutoSync(ctx, "ldap1", time.Nanosecond, recordBuilder)
	assert.Nil(t, err)
	time.Sleep(100 * time.Microsecond)

	// Stop auto sync and wait for the sync goroutine to be stopped.
	manager.StopAutoSync("ldap1")
	time.Sleep(100 * time.Microsecond)

	// Store number of calls to SyncUsers()
	mockSynchronizer.Lock()
	firstValue := mockSynchronizer.syncCalled
	mockSynchronizer.Unlock()

	// Verify that the stop channel is removed
	manager.Lock()
	_, exists := manager.ldapIdToStopChan["ldap1"]
	manager.Unlock()
	assert.False(t, exists, "Expected stop channel to be removed")

	time.Sleep(200 * time.Microsecond)
	mockSynchronizer.Lock()
	secondValue := mockSynchronizer.syncCalled
	mockSynchronizer.Unlock()

	// Compare previous number of calls to SyncUsers() with current
	assert.Equal(t, firstValue, secondValue, "Expected sync to not be run called after stop")
}

func TestLdapSynchronizationManager_StartAutoSync_NonExistentLdap(t *testing.T) {
	ctx := context.Background()

	mockSynchronizer := &MockLdapSynchronizer{}
	mockRepo := &MockLdapRepository{
		ldapMap: map[string]*Ldap{},
	}

	manager := NewLdapAutoSynchronizer(mockSynchronizer, mockRepo)
	recordBuilder := &RecordBuilder{}

	err := manager.StartAutoSync(ctx, "non-existent", time.Minute, recordBuilder)
	time.Sleep(500 * time.Microsecond)

	assert.NotNil(t, err)
	assert.Equal(t, "LDAP not found", err.Error())

	// Verify that the sync process was not started
	mockSynchronizer.Lock()
	assert.Equal(t, 0, mockSynchronizer.syncCalled, "Expected sync to not be called")
	mockSynchronizer.Unlock()

	// Verify that the stop channel is not created
	manager.Lock()
	_, exists := manager.ldapIdToStopChan["non-existent"]
	manager.Unlock()
	assert.False(t, exists, "Expected stop channel to not be created")
}

func TestLdapSynchronizationManager_WaitForNextSync(t *testing.T) {
	ctx := context.Background()

	mockSynchronizer := &MockLdapSynchronizer{}
	mockRepo := &MockLdapRepository{
		ldapMap: map[string]*Ldap{
			"ldap1": {Id: "ldap1", AutoSync: 1},
		},
	}

	manager := NewLdapAutoSynchronizer(mockSynchronizer, mockRepo)
	recordBuilder := &RecordBuilder{}

	err := manager.StartAutoSync(ctx, "ldap1", time.Nanosecond, recordBuilder)
	assert.Nil(t, err)

	time.Sleep(100 * time.Microsecond)
	mockSynchronizer.Lock()
	assert.LessOrEqual(t, 2, mockSynchronizer.syncCalled,
		"Expected sync with nanosecond period to be called more than two times over 100 milliseconds")
	mockSynchronizer.Unlock()

	// Verify that the stop channel is created
	manager.Lock()
	_, exists := manager.ldapIdToStopChan["ldap1"]
	manager.Unlock()
	assert.True(t, exists, "Expected stop channel to be created")
}
