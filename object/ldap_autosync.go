package object

import (
	"context"
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

func InitLdapAutoSynchronizer(ctx context.Context) {
	globalLdapAutoSynchronizer = NewLdapAutoSynchronizer()
	err := globalLdapAutoSynchronizer.LdapAutoSynchronizerStartUpAll(ctx)
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
func (l *LdapAutoSynchronizer) StartAutoSync(ctx context.Context, ldapId string, recordBuilder *RecordBuilder) error {
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
		err := l.syncRoutine(ctx, ldap, stopChan)
		if err != nil {
			recordBuilder.AddReason(fmt.Sprintf("Sync process error: %s", err.Error()))
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
func (l *LdapAutoSynchronizer) syncRoutine(ctx context.Context, ldap *Ldap, stopChan chan struct{}) error {
	err := syncUsers(ctx, ldap)
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
			err = syncUsers(ctx, ldap)
			if err != nil {
				return err
			}
		}
	}
}

func syncUsers(ctx context.Context, ldap *Ldap) error {
	rb := NewRecordBuilder()

	logs.Info(fmt.Sprintf("autoSync started for %s", ldap.Id))
	rb.AddReason(fmt.Sprintf("autoSync started for %s", ldap.Id))

	// fetch all users
	conn, err := ldap.GetLdapConn()
	if err != nil {
		logAndAddRecord(fmt.Sprintf("autoSync failed for %s, error %s", ldap.Id, err), logs.LevelWarning, rb)
		return nil
	}

	users, err := conn.GetLdapUsers(ldap, nil, rb)
	if err != nil {
		logAndAddRecord(fmt.Sprintf("autoSync failed for %s, error %s", ldap.Id, err), logs.LevelWarning, rb)
		return nil
	}

	existed, failed, err := SyncLdapUsers(ctx, ldap.Owner, AutoAdjustLdapUser(users), ldap.Id)
	if err != nil {
		logAndAddRecord(fmt.Sprintf("ldap autosync error: %s", err.Error()), logs.LevelWarning, rb)
	} else if len(failed) != 0 {
		logAndAddRecord(fmt.Sprintf("ldap autosync finished, %d new users, but %d user failed during :", len(users)-len(existed)-len(failed), len(failed)), logs.LevelWarning, rb)
	} else {
		if len(users) > len(existed) {
			logAndAddRecord(fmt.Sprintf("ldap autosync success, %d new users, %d existing users", len(users)-len(existed), len(existed)), logs.LevelInformational, rb)
		}
	}

	err = UpdateLdapSyncTime(ldap.Id)
	return err
}

func logAndAddRecord(message string, logLevel int, rb *RecordBuilder) {
	if logLevel == logs.LevelWarning {
		logs.Warning(message)
	} else if logLevel == logs.LevelInformational {
		logs.Info(message)
	}

	rb.AddReason(message)
	util.SafeGoroutine(func() { AddRecord(rb.Build()) })
}

// LdapAutoSynchronizerStartUpAll
// start all autosync goroutine for existing ldap servers in each organizations
func (l *LdapAutoSynchronizer) LdapAutoSynchronizerStartUpAll(ctx context.Context) error {
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
				err = l.StartAutoSync(ctx, ldap.Id, rb)

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
