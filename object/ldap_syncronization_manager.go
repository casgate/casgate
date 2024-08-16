package object

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/casdoor/casdoor/ldap_sync"
	"github.com/casdoor/casdoor/orm"
	"github.com/casdoor/casdoor/util/logger"

	"github.com/casdoor/casdoor/util"
)

type ILdapSynchronizer interface {
	SyncUsers(ctx context.Context, ldap *ldap_sync.Ldap) error
}
type ILdapRepository interface {
	GetLdap(id string) (*ldap_sync.Ldap, error)
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
		err = errors.Wrap(err, "StartAutoSync error: failed to GetLdap")
		recordBuilder.AddReason(fmt.Sprintf("Get LDAP: %s", err.Error()))
		return err
	}

	if ldap == nil {
		msg := fmt.Sprintf("StartAutoSync failed: ldap doesn't exist")
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

	logger.Info(
		ctx,
		"autoSync process started",
		"ldap_id", ldapId,
		"reason", ldap_sync.LdapSyncReasonAuto,
		"act", logger.OperationNameLdapSyncUsers,
		"r", logger.OperationResultSuccess,
	)

	util.SafeGoroutine(func() {
		err := l.syncRoutine(ctx, ldap, stopChan, tickDuration)
		if err != nil {
			recordBuilder.AddReason(fmt.Sprintf("Sync process error: %s", err.Error()))
			logger.Info(
				ctx,
				"syncRoutine failed",
				"error", err.Error(),
				"ldap_id", ldapId,
				"reason", ldap_sync.LdapSyncReasonAuto,
				"act", logger.OperationNameLdapSyncUsers,
				"r", logger.OperationResultFailure,
			)
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
func (l *LdapSynchronizationManager) syncRoutine(
	ctx context.Context,
	ldap *ldap_sync.Ldap,
	stopChan chan struct{},
	tickerPeriod time.Duration,
) error {
	err := l.syncronizer.SyncUsers(ctx, ldap)
	if err != nil {
		return err
	}

	ticker := time.NewTicker(tickerPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-stopChan:
			logger.Info(
				ctx,
				"autoSync goroutine stopped",
				"ldap_id", ldap.Id,
				"ldap_owner", ldap.Owner,
				"reason", ldap_sync.LdapSyncReasonAuto,
				"act", logger.OperationNameLdapSyncUsers,
				"r", logger.OperationResultSuccess,
			)
			return nil
		case <-ticker.C:
			err = l.syncronizer.SyncUsers(ctx, ldap)
			if err != nil {
				return err
			}
		}
	}
}

// LdapAutoSynchronizerStartUpAll
// start all autosync goroutine for existing ldap servers in each organizations
func (l *LdapSynchronizationManager) LdapAutoSynchronizerStartUpAll(ctx context.Context) error {
	organizations := []*Organization{}
	err := orm.AppOrmer.Engine.Desc("created_time").Find(&organizations)
	if err != nil {
		logger.Error(
			ctx,
			"failed to startup LdapSynchronizationManager: failed to get organizations",
			"reason", ldap_sync.LdapSyncReasonAuto,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
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
	_, err := orm.AppOrmer.Engine.ID(ldapId).Update(&ldap_sync.Ldap{LastSync: util.GetCurrentTime()})
	if err != nil {
		return err
	}

	return nil
}

type LdapSyncronizer struct{}

func (ls *LdapSyncronizer) SyncUsers(ctx context.Context, ldap *ldap_sync.Ldap) error {
	rb := NewRecordBuilder()
	logger.Info(
		ctx,
		"autoSync started",
		"ldap_id", ldap.Id,
		"ldap_owner", ldap.Owner,
		"reason", ldap_sync.LdapSyncReasonAuto,
		"act", logger.OperationNameLdapSyncUsers,
		"r", logger.OperationResultSuccess,
	)
	rb.AddReason(fmt.Sprintf("autoSync started for %s", ldap.Id))

	// fetch all users
	conn, err := ldap_sync.GetLdapConn(ctx, ldap)
	if err != nil {
		logger.Error(
			ctx,
			"autoSync failed: failed to call GetLdapConn",
			"error", err.Error(),
			"ldap_id", ldap.Id,
			"ldap_owner", ldap.Owner,
			"reason", ldap_sync.LdapSyncReasonAuto,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		rb.AddReason(err.Error())
		util.SafeGoroutine(func() { AddRecord(rb.Build()) })
		return nil
	}

	users, err := conn.GetUsersFromLDAP(ldap, nil, rb)
	if err != nil {
		logger.Error(
			ctx,
			"autoSync failed: failed to call GetUsersFromLDAP",
			"error", err.Error(),
			"ldap_id", ldap.Id,
			"ldap_owner", ldap.Owner,
			"reason", ldap_sync.LdapSyncReasonAuto,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		rb.AddReason(err.Error())
		util.SafeGoroutine(func() { AddRecord(rb.Build()) })
		return nil
	}

	syncResult, err := SyncLdapUsers(
		ctx,
		LdapSyncCommand{LdapUsers: AutoAdjustLdapUser(users), LdapId: ldap.Id, Reason: ldap_sync.LdapSyncReasonAuto},
	)
	if err != nil {
		logger.Error(
			ctx,
			"autosync error",
			"error", err.Error(),
			"ldap_id", ldap.Id,
			"ldap_owner", ldap.Owner,
			"reason", ldap_sync.LdapSyncReasonAuto,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultFailure,
		)
		rb.AddReason(err.Error())
		util.SafeGoroutine(func() { AddRecord(rb.Build()) })
	} else if len(syncResult.Failed) != 0 {
		logger.Warn(
			ctx,
			"autosync finished with errors",
			"ldap_id", ldap.Id,
			"ldap_owner", ldap.Owner,
			"reason", ldap_sync.LdapSyncReasonAuto,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultSuccess,
		)
		rb.AddReason("autosync finished with errors")
		util.SafeGoroutine(func() { AddRecord(rb.Build()) })
	} else {
		logger.Info(
			ctx,
			"autosync success",
			"ldap_id", ldap.Id,
			"ldap_owner", ldap.Owner,
			"reason", ldap_sync.LdapSyncReasonAuto,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultSuccess,
		)
		rb.AddReason("autosync success")
		util.SafeGoroutine(func() { AddRecord(rb.Build()) })
	}

	return err
}
