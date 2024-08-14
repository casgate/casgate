package object

import (
	"fmt"
	"github.com/casdoor/casdoor/orm"

	"github.com/beego/beego/logs"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
	"github.com/xorm-io/xorm/schemas"
)

type Migrator_1_19505_0_PR_191 struct{}

func (*Migrator_1_19505_0_PR_191) IsMigrationNeeded() bool {
	applicationTable, err := orm.AppOrmer.Engine.TableInfo(&Application{})
	if err != nil {
		logs.Warn("Table 'Application' does not exist")
		return false
	}

	for _, col := range applicationTable.Columns() {
		if col.Name == "user_mapping_strategy" {
			return true
		}
	}

	return false
}

func (*Migrator_1_19505_0_PR_191) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20240515MigrateOrganization -- Set mapping strategy for all",
		Migrate: func(engine *xorm.Engine) error {
			dbType := engine.Dialect().URI().DBType

			if dbType != schemas.POSTGRES && dbType != schemas.MYSQL {
				logs.Warn("You must make migration: Migrator_1_19505_0_PR_191 manually")
				return nil
			}

			tx := engine.NewSession()
			defer tx.Close()

			err := tx.Begin()
			if err != nil {
				return fmt.Errorf("begin transaction: %w", err)
			}

			_, err = tx.Table(new(Application)).Update(map[string]interface{}{"user_mapping_strategy": "all"})
			if err != nil {
				return fmt.Errorf("update application user_mapping_strategy: %w", err)
			}

			_, err = tx.Table(new(Ldap)).Update(map[string]interface{}{"user_mapping_strategy": "all"})
			if err != nil {
				return fmt.Errorf("update ldap user_mapping_strategy: %w", err)
			}

			_, err = tx.Table(new(User)).Update(map[string]interface{}{"mapping_strategy": "all"})
			if err != nil {
				return fmt.Errorf("update mapping_strategy: %w", err)
			}

			return tx.Commit()
		},
	}
	return &migration
}
