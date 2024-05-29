package object

import (
	"fmt"

	"github.com/beego/beego/logs"
	"github.com/xorm-io/xorm"
	"github.com/xorm-io/xorm/migrate"
	"github.com/xorm-io/xorm/schemas"
)

type Migrator_1_19505_0_PR_191 struct{}

func (*Migrator_1_19505_0_PR_191) IsMigrationNeeded() bool {
	roleTable, err := ormer.Engine.TableInfo(&Role{})
	if err != nil {
		logs.Warn("Table 'Role' does not exist")
		return false
	}

	for _, col := range roleTable.Columns() {
		if col.Name == "is_read_only" {
			return true
		}
	}

	return false
}

func (*Migrator_1_19505_0_PR_191) DoMigration() *migrate.Migration {
	migration := migrate.Migration{
		ID: "20240515MigrateOrganization -- Set IsReadOnly to true for all old roles",
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


			_, err = tx.Table(new(Role)).Update(map[string]interface{}{"is_read_only": true})
			if err != nil {
				return fmt.Errorf("update is_read_only: %w", err)
			}

			return tx.Commit()
		},
	}
	return &migration
}
