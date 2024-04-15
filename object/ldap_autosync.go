package object

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/util"
)

type LdapAutoSynchronizer struct {
	sync.Mutex
	ldapIdToStopChan map[string]chan struct{}
}

var globalLdapAutoSynchronizer *LdapAutoSynchronizer

func InitLdapAutoSynchronizer() {
	globalLdapAutoSynchronizer = NewLdapAutoSynchronizer()
	err := globalLdapAutoSynchronizer.LdapAutoSynchronizerStartUpAll()
	if err != nil {
		panic(err)
	}
}

func NewLdapAutoSynchronizer() *LdapAutoSynchronizer {
	return &LdapAutoSynchronizer{
		ldapIdToStopChan: make(map[string]chan struct{}),
	}
}

func GetLdapAutoSynchronizer() *LdapAutoSynchronizer {
	return globalLdapAutoSynchronizer
}

// StartAutoSync
// start autosync for specified ldap, old existing autosync goroutine will be ceased
func (l *LdapAutoSynchronizer) StartAutoSync(ldapId string, recordBuilder *RecordBuilder) error {
	recordBuilder.AddReason(fmt.Sprintf("Start LDAP %s autosync process", ldapId))

	l.Lock()
	defer l.Unlock()

	ldap, err := GetLdap(ldapId)
	if err != nil {
		recordBuilder.AddReason(fmt.Sprintf("Get LDAP: %s", err.Error()))
		return err
	}

	if ldap == nil {
		msg := fmt.Sprintf("ldap %s doesn't exist", ldapId)
		recordBuilder.AddReason(msg)
		return errors.New(msg)
	}
	if res, ok := l.ldapIdToStopChan[ldapId]; ok {
		res <- struct{}{}
		delete(l.ldapIdToStopChan, ldapId)
	}

	stopChan := make(chan struct{})
	l.ldapIdToStopChan[ldapId] = stopChan

	logMsg := fmt.Sprintf("autoSync process started for %s", ldap.Id)
	recordBuilder.AddReason(logMsg)

	logs.Info(logMsg)

	util.SafeGoroutine(func() {
		err := l.syncRoutine(ldap, stopChan)
		recordBuilder.AddReason(fmt.Sprintf("Sync process error: %s", err.Error()))

		if err != nil {
			panic(err)
		}
	})
	return nil
}

func (l *LdapAutoSynchronizer) StopAutoSync(ldapId string) {
	l.Lock()
	defer l.Unlock()
	if res, ok := l.ldapIdToStopChan[ldapId]; ok {
		res <- struct{}{}
		delete(l.ldapIdToStopChan, ldapId)
	}
}

// autosync goroutine
func (l *LdapAutoSynchronizer) syncRoutine(ldap *Ldap, stopChan chan struct{}) error {
	rb := NewRecordBuilder()
	err := syncUsers(ldap, rb)
	util.SafeGoroutine(func() { AddRecord(rb.Build()) })

	if err != nil {
		return err
	}

	ticker := time.NewTicker(time.Duration(ldap.AutoSync) * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stopChan:
			logs.Info(fmt.Sprintf("autoSync goroutine for %s stopped", ldap.Id))
			return nil
		case <-ticker.C:
			rb = NewRecordBuilder()
			err = syncUsers(ldap, rb)
			util.SafeGoroutine(func() { AddRecord(rb.Build()) })

			if err != nil {
				return err
			}
		}
	}
}

func syncUsers(ldap *Ldap, recordBuilder *RecordBuilder) error {
	recordBuilder.AddReason(fmt.Sprintf("autoSync started for %s", ldap.Id))
	// fetch all users
	conn, err := ldap.GetLdapConn()
	if err != nil {
		logs.Warning(fmt.Sprintf("autoSync failed for %s, error %s", ldap.Id, err))
		recordBuilder.AddReason(fmt.Sprintf("autoSync failed for %s, error %s", ldap.Id, err))
		return nil
	}

	users, err := conn.GetLdapUsers(ldap, nil)
	if err != nil {
		logs.Warning(fmt.Sprintf("autoSync failed for %s, error %s", ldap.Id, err))
		recordBuilder.AddReason(fmt.Sprintf("autoSync failed for %s, error %s", ldap.Id, err))
		return nil
	}

	existed, failed, err := SyncLdapUsers(ldap.Owner, AutoAdjustLdapUser(users), ldap.Id)
	if len(failed) != 0 {
		logs.Warning(fmt.Sprintf("ldap autosync, %d new users, but %d user failed during :", len(users)-len(existed)-len(failed), len(failed)), failed)
		logs.Warning(err.Error())
		recordBuilder.AddReason(fmt.Sprintf("ldap autosync, %d new users, but %d user failed during :", len(users)-len(existed)-len(failed), len(failed)))
		recordBuilder.AddReason(err.Error())
	} else {
		logs.Info(fmt.Sprintf("ldap autosync success, %d new users, %d existing users", len(users)-len(existed), len(existed)))
		recordBuilder.AddReason(fmt.Sprintf("ldap autosync success, %d new users, %d existing users", len(users)-len(existed), len(existed)))
	}

	err = UpdateLdapSyncTime(ldap.Id)
	if err != nil {
		return err
	}

	return nil
}

// LdapAutoSynchronizerStartUpAll
// start all autosync goroutine for existing ldap servers in each organizations
func (l *LdapAutoSynchronizer) LdapAutoSynchronizerStartUpAll() error {
	organizations := []*Organization{}
	err := ormer.Engine.Desc("created_time").Find(&organizations)
	if err != nil {
		logs.Info("failed to startup LdapAutoSynchronizer")
	}
	for _, org := range organizations {
		ldaps, err := GetLdaps(org.Name)
		if err != nil {
			return err
		}

		for _, ldap := range ldaps {
			if ldap.AutoSync != 0 {
				rb := NewRecordBuilder()
				err = l.StartAutoSync(ldap.Id, rb)

				util.SafeGoroutine(func() { AddRecord(rb.Build()) })

				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func UpdateLdapSyncTime(ldapId string) error {
	_, err := ormer.Engine.ID(ldapId).Update(&Ldap{LastSync: util.GetCurrentTime()})
	if err != nil {
		return err
	}

	return nil
}
