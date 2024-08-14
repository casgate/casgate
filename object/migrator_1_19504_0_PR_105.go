package object

import (
	"github.com/beego/beego/logs"
	"github.com/casdoor/casdoor/orm"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
	"github.com/xorm-io/xorm/schemas"
)

type Migrator_1_19504_0_PR_105 struct{}

func (*Migrator_1_19504_0_PR_105) IsMigrationNeeded() bool {
	table, err := orm.AppOrmer.Engine.TableInfo(&Organization{})
	if err != nil {
		logs.Warn("Table 'organization' does not exist")
		return false
	}
	for _, col := range table.Columns() {
		if col.Name == "password_max_length" || col.Name == "password_min_length" {
			return true
		}
	}
	return false
}

func (*Migrator_1_19504_0_PR_105) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20240314MigrateOrganization -- Set value for organization fields password_max_len/password_min_len",
		Migrate: func(engine *xorm.Engine) error {
			dbType := engine.Dialect().URI().DBType

			if dbType != schemas.POSTGRES && dbType != schemas.MYSQL {
				logs.Warn("You must make migration: Migrator_1_19504_0_PR_105 manually")
				return nil
			}

			tx := engine.NewSession()
			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return err
			}

			organizations := []*Organization{}
			err = tx.Table(new(Organization)).Where("password_max_length IS NULL AND password_min_length IS NULL").Find(&organizations)
			if err != nil {
				return err
			}
			maxLen, err := GetUserTablePasswordMaxLength()
			if err != nil {
				return err
			}
			for _, org := range organizations {
				org.PasswordMaxLength = maxLen
				org.PasswordMinLength = 1
				_, err = tx.Where("owner = ? and name = ?", org.Owner, org.Name).
					Cols("password_max_length", "password_min_length").
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
