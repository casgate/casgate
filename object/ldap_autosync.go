package object

import (
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
func (l *LdapAutoSynchronizer) StartAutoSync(ldapId string) error {
	l.Lock()
	defer l.Unlock()

	ldap, err := GetLdap(ldapId)
	if err != nil {
		return err
	}

	if ldap == nil {
		return fmt.Errorf("ldap %s doesn't exist", ldapId)
	}
	if res, ok := l.ldapIdToStopChan[ldapId]; ok {
		res <- struct{}{}
		delete(l.ldapIdToStopChan, ldapId)
	}

	stopChan := make(chan struct{})
	l.ldapIdToStopChan[ldapId] = stopChan
	logs.Info(fmt.Sprintf("autoSync started for %s", ldap.Id))
	util.SafeGoroutine(func() {
		err := l.syncRoutine(ldap, stopChan)
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
	err := syncUsers(ldap)
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
			err = syncUsers(ldap)
			if err != nil {
				return err
			}
		}
	}
}

func syncUsers(ldap *Ldap) error {
	// fetch all users
	conn, err := ldap.GetLdapConn()
	if err != nil {
		logs.Warning(fmt.Sprintf("autoSync failed for %s, error %s", ldap.Id, err))
		return nil
	}

	users, err := conn.GetLdapUsers(ldap)
	if err != nil {
		logs.Warning(fmt.Sprintf("autoSync failed for %s, error %s", ldap.Id, err))
		return nil
	}

	failed, err := SyncLdapUsers(ldap.Owner, AutoAdjustLdapUser(users), ldap.Id)
	if len(failed) != 0 {
		logs.Warning(fmt.Sprintf("ldap autosync, %d synchronized users, but %d users failed during synchronizing:", len(users)-len(failed), len(failed)), failed)
		logs.Warning(err.Error())
	} else {
		logs.Info(fmt.Sprintf("ldap autosync success, %d synchronized users", len(users)))
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
	var organizations []*Organization
	err := ormer.Engine.Desc("created_time").Find(&organizations)
	if err != nil {
		logs.Info("failed to Star up LdapAutoSynchronizer; ")
	}
	for _, org := range organizations {
		ldaps, err := GetLdaps(org.Name)
		if err != nil {
			return err
		}

		for _, ldap := range ldaps {
			if ldap.AutoSync != 0 {
				err = l.StartAutoSync(ldap.Id)
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
