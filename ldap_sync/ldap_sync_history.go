package ldap_sync

import (
	"github.com/casdoor/casdoor/orm"
	"time"
)

type LdapSyncHistory struct {
	Id             int                   `xorm:"int notnull pk autoincr" json:"id"`
	LdapSyncID     int                   `xorm:"'ldap_sync_id' int notnull" json:"ldap_sync_id"`
	LdapID         string                `xorm:"'ldap_id' varchar(100) notnull" json:"ldap_id"`
	StartedAt      time.Time             `xorm:"datetime notnull" json:"started_at"`
	EndedAt        time.Time             `xorm:"datetime" json:"ended_at"`
	Reason         string                `xorm:"varchar(100) notnull" json:"reason"`
	SyncedByUserID string                `xorm:"'synced_by_user_id' varchar(100) notnull" json:"synced_by_user_id"`
	Result         []LdapSyncHistoryUser `xorm:"json" json:"result"`
}

type LdapSyncHistoryUser struct {
	UUID   string
	Action string
}

type LdapSyncHistoryRepository struct{}

func (r *LdapSyncHistoryRepository) CountLdapSyncHistoryEntries(ldapID string) (int64, error) {
	return orm.AppOrmer.Engine.Count(&LdapSyncHistory{LdapID: ldapID})
}

func (r *LdapSyncHistoryRepository) GetLdapSyncHistory(ldapID string, offset, limit int, sortOrder string) ([]*LdapSyncHistory, error) {
	var history []*LdapSyncHistory
	statement := orm.AppOrmer.Engine.Prepare().Limit(limit, offset)
	if sortOrder == "ascend" {
		statement = statement.Asc("ended_at")
	} else {
		statement = statement.Desc("ended_at")
	}
	err := statement.Find(&history, &LdapSyncHistory{LdapID: ldapID}, ldapID)
	if err != nil {
		return nil, err
	}

	return history, nil
}
