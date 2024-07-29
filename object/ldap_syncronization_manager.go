package object

import (
	"context"
	"errors"
	"fmt"
	"github.com/casdoor/casdoor/orm"
	"sync"
	"time"

	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/util"
)

type ILdapSynchronizer interface {
	SyncUsers(ctx context.Context, ldap *Ldap) error
}
type ILdapRepository interface {
	GetLdap(id string) (*Ldap, error)
}

type LdapSynchronizationManager struct {
	sync.Mutex
	syncronizer      ILdapSynchronizer
	repo             ILdapRepository
	ldapIdToStopChan map[string]chan struct{}
}

var globalLdapSynchronizationManager *LdapSynchronizationManager

func InitLdapAutoSynchronizer(ctx context.Context) {
	globalLdapSynchronizationManager = NewLdapAutoSynchronizer(&LdapSyncronizer{}, &LdapRepository{})
	err := globalLdapSynchronizationManager.LdapAutoSynchronizerStartUpAll(ctx)
	if err != nil {
		panic(err)
	}
}

func NewLdapAutoSynchronizer(syncronizer ILdapSynchronizer, repo ILdapRepository) *LdapSynchronizationManager {
	return &LdapSynchronizationManager{
		syncronizer:      syncronizer,
		repo:             repo,
		ldapIdToStopChan: make(map[string]chan struct{}),
	}
}

func GetLdapSynchronizationManager() *LdapSynchronizationManager {
	return globalLdapSynchronizationManager
}

// StartAutoSync
// start autosync for specified ldap, old existing autosync goroutine will be ceased
func (l *LdapSynchronizationManager) StartAutoSync(ctx context.Context, ldapId string, tickDuration time.Duration, recordBuilder *RecordBuilder) error {
	recordBuilder.AddReason(fmt.Sprintf("Start LDAP %s autosync process", ldapId))

	l.Lock()
	defer l.Unlock()

	ldap, err := l.repo.GetLdap(ldapId)
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
		close(res)
		delete(l.ldapIdToStopChan, ldapId)
	}

	stopChan := make(chan struct{})
	l.ldapIdToStopChan[ldapId] = stopChan

	logMsg := fmt.Sprintf("autoSync process started for %s", ldap.Id)
	recordBuilder.AddReason(logMsg)

	logs.Info(logMsg)

	util.SafeGoroutine(func() {
		err := l.syncRoutine(ctx, ldap, stopChan, tickDuration)
		if err != nil {
			recordBuilder.AddReason(fmt.Sprintf("Sync process error: %s", err.Error()))
			panic(err)
		}
	})
	return nil
}

func (l *LdapSynchronizationManager) StopAutoSync(ldapId string) {
	l.Lock()
	defer l.Unlock()
	if res, ok := l.ldapIdToStopChan[ldapId]; ok {
		close(res)
		delete(l.ldapIdToStopChan, ldapId)
	}
}

// autosync goroutine
func (l *LdapSynchronizationManager) syncRoutine(ctx context.Context, ldap *Ldap, stopChan chan struct{}, tickerPeriod time.Duration) error {
	err := l.syncronizer.SyncUsers(ctx, ldap)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(tickerPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-stopChan:
			logs.Info(fmt.Sprintf("autoSync goroutine for %s stopped", ldap.Id))
			return nil
		case <-ticker.C:
			err = l.syncronizer.SyncUsers(ctx, ldap)
			if err != nil {
				return err
			}
		}
	}
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
func (l *LdapSynchronizationManager) LdapAutoSynchronizerStartUpAll(ctx context.Context) error {
	organizations := []*Organization{}
	err := orm.AppOrmer.Engine.Desc("created_time").Find(&organizations)
	if err != nil {
		logs.Info("failed to startup LdapSynchronizationManager")
	}
	for _, org := range organizations {
		// Empty orgName doesn't filter anything through xorm Find() method.
		if org.Name == "" {
			continue
		}
		ldaps, err := GetLdaps(org.Name)
		if err != nil {
			return err
		}

		for _, ldap := range ldaps {
			if ldap.AutoSync != 0 {
				rb := NewRecordBuilder()
				err = l.StartAutoSync(ctx, ldap.Id, time.Duration(ldap.AutoSync)*time.Minute, rb)

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
	_, err := orm.AppOrmer.Engine.ID(ldapId).Update(&Ldap{LastSync: util.GetCurrentTime()})
	if err != nil {
		return err
	}

	return nil
}

type LdapSyncronizer struct{}

func (ls *LdapSyncronizer) SyncUsers(ctx context.Context, ldap *Ldap) error {
	rb := NewRecordBuilder()

	logs.Info(fmt.Sprintf("autoSync started for %s", ldap.Id))
	rb.AddReason(fmt.Sprintf("autoSync started for %s", ldap.Id))

	// fetch all users
	conn, err := ldap.GetLdapConn(ctx)
	if err != nil {
		logAndAddRecord(fmt.Sprintf("autoSync failed for %s: failed to call GetLdapConn: error %s", ldap.Id, err), logs.LevelWarning, rb)
		return nil
	}

	users, err := conn.GetLdapUsers(ldap, nil, rb)
	if err != nil {
		logAndAddRecord(fmt.Sprintf("autoSync failed for %s: failed to call GetLdapUsers: error %s", ldap.Id, err), logs.LevelWarning, rb)
		return nil
	}

	syncResult, err := SyncLdapUsers(ctx, LdapSyncCommand{LdapUsers: AutoAdjustLdapUser(users), LdapId: ldap.Id, Reason: "auto"})
	if err != nil {
		logAndAddRecord(fmt.Sprintf("ldap id: %s autosync error: %s", ldap.Id, err.Error()), logs.LevelWarning, rb)
	} else if len(syncResult.Failed) != 0 {
		logAndAddRecord(fmt.Sprintf("ldap id: %s autosync finished, %d new users, but %d user failed during :", ldap.Id, len(syncResult.Added), len(syncResult.Failed)), logs.LevelWarning, rb)
	} else {
		logAndAddRecord(fmt.Sprintf("ldap id: %s autosync success, %d new users, %d updated users", ldap.Id, len(syncResult.Added), len(syncResult.Updated)), logs.LevelInformational, rb)
	}

	return err
}
