package object

import (
	"context"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/casdoor/casdoor/ldap_sync"
	"github.com/casdoor/casdoor/orm"
	"github.com/casdoor/casdoor/util/logger"

	"github.com/casdoor/casdoor/util"
)

type ILdapSynchronizer interface {
	SyncLdapUsers(ctx context.Context, ldap *ldap_sync.Ldap) error
}
type ILdapRepository interface {
	GetLdap(id string) (*ldap_sync.Ldap, error)
}

type LdapSyncManager struct {
	sync.Mutex
	syncronizer      ILdapSynchronizer
	repo             ILdapRepository
	ldapIdToStopChan map[string]chan struct{}
}

var globalLdapSynchronizationManager *LdapSyncManager

func RunLDAPSync(ctx context.Context) {
	globalLdapSynchronizationManager = NewLdapSyncManager(&LdapSyncronizer{}, &LdapRepository{})
	err := globalLdapSynchronizationManager.RunLdapSyncForAllConnections(ctx)
	if err != nil {
		panic(err)
	}
}

func NewLdapSyncManager(synchronizer ILdapSynchronizer, repo ILdapRepository) *LdapSyncManager {
	return &LdapSyncManager{
		syncronizer:      synchronizer,
		repo:             repo,
		ldapIdToStopChan: make(map[string]chan struct{}),
	}
}

func GetLdapSyncManager() *LdapSyncManager {
	return globalLdapSynchronizationManager
}

// StartSyncProcess
// start autosync for specified ldap, old existing autosync goroutine will be ceased
func (l *LdapSyncManager) StartSyncProcess(
	ctx context.Context,
	ldapId string,
	tickDuration time.Duration,
) error {

	l.Lock()
	defer l.Unlock()

	ldap, err := l.repo.GetLdap(ldapId)
	if err != nil {
		err = errors.Wrap(err, "StartAutoSync error: failed to GetLdap")
		return err
	}

	if ldap == nil {
		return errors.New("StartAutoSync failed: ldap doesn't exist")
	}
	if res, ok := l.ldapIdToStopChan[ldapId]; ok {
		close(res)
		delete(l.ldapIdToStopChan, ldapId)
	}

	stopChan := make(chan struct{})
	l.ldapIdToStopChan[ldapId] = stopChan

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

func (l *LdapSyncManager) StopSyncProcess(ldapId string) {
	l.Lock()
	defer l.Unlock()
	if res, ok := l.ldapIdToStopChan[ldapId]; ok {
		close(res)
		delete(l.ldapIdToStopChan, ldapId)
	}
}

// autosync goroutine
func (l *LdapSyncManager) syncRoutine(
	ctx context.Context,
	ldap *ldap_sync.Ldap,
	stopChan chan struct{},
	tickerPeriod time.Duration,
) error {
	err := l.syncronizer.SyncLdapUsers(ctx, ldap)
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
			err = l.syncronizer.SyncLdapUsers(ctx, ldap)
			if err != nil {
				return err
			}
		}
	}
}

// RunLdapSyncForAllConnections
// start all autosync goroutine for existing ldap servers in each organizations
func (l *LdapSyncManager) RunLdapSyncForAllConnections(ctx context.Context) error {
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
				err = l.StartSyncProcess(ctx, ldap.Id, time.Duration(ldap.AutoSync)*time.Minute)

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

func (ls *LdapSyncronizer) SyncLdapUsers(ctx context.Context, ldap *ldap_sync.Ldap) error {
	logger.Info(
		ctx,
		"autoSync started",
		"ldap_id", ldap.Id,
		"ldap_owner", ldap.Owner,
		"reason", ldap_sync.LdapSyncReasonAuto,
		"act", logger.OperationNameLdapSyncUsers,
		"r", logger.OperationResultSuccess,
	)

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
		return nil
	}

	users, err := conn.GetUsersFromLDAP(ctx, ldap, nil)
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
		return nil
	}

	syncResult, err := SyncUsersSynchronously(
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
	} else if len(syncResult.Failed) != 0 {
		logger.Warn(
			ctx,
			"autosync finished with errors",
			"ldap_id", ldap.Id,
			"ldap_owner", ldap.Owner,
			"reason", ldap_sync.LdapSyncReasonAuto,
			"act", logger.OperationNameLdapSyncUsers,
			"r", logger.OperationResultSuccess,
			"failed_count", len(syncResult.Failed),
		)
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
	}

	return err
}
