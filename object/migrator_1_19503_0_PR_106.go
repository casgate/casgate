package object

import (
	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/orm"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
	"github.com/xorm-io/xorm/schemas"
)

type Migrator_1_19503_0_PR_106 struct{}

func (*Migrator_1_19503_0_PR_106) IsMigrationNeeded() bool {
	table, err := orm.AppOrmer.Engine.TableInfo(&Organization{})
	if err != nil {
		logs.Warn("Table 'organization' does not exist")
		return false
	}
	for _, col := range table.Columns() {
		if col.Name == "password_special_chars" {
			return true
		}
	}
	return false
}

func (*Migrator_1_19503_0_PR_106) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20240315MigrateOrganization -- Set value for organization field password_special_chars",
		Migrate: func(engine *xorm.Engine) error {
			dbType := engine.Dialect().URI().DBType

			if dbType != schemas.POSTGRES && dbType != schemas.MYSQL {
				logs.Warn("You must make migration: Migrator_1_19503_0_PR_106 manually")
				return nil
			}

			tx := engine.NewSession()
			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}

			organizations := []*Organization{}
			err = tx.Table(new(Organization)).Where("password_special_chars IS NULL").Find(&organizations)
			if err != nil {
				return err
			}
			for _, org := range organizations {
				org.PasswordSpecialChars = DefaultOrganizationPasswordSpecialChars
				_, err = tx.Where("owner = ? and name = ?", org.Owner, org.Name).
					Cols("password_special_chars").
					Update(org)
				if err != nil {
					return err
				}
			}
			tx.Commit()
			return nil
		},
	}
	return &migration
}
