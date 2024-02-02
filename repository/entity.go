package repository

import (
	"context"

	"github.com/xorm-io/builder"
	"github.com/xorm-io/core"
)

func (r *Repo) UpdateEntitiesFieldValue(ctx context.Context, entityName, fieldName, oldValue, newValue string) error {
	bean := make(map[string]interface{})
	bean[fieldName] = newValue

	_, err := r.trm.GetEngine(ctx).Table(entityName).Where(builder.Eq{fieldName: oldValue}).Update(bean)
	if err != nil {
		return err
	}
	return nil
}

func (r *Repo) updateEntity(ctx context.Context, owner, name string, entity any) (int64, error) {
	query := r.trm.GetEngine(ctx).ID(core.PK{owner, name}).AllCols()
	affected, err := query.Update(entity)
	if err != nil {
		return affected, err
	}

	return affected, nil
}

func (r *Repo) insertEntity(ctx context.Context, entity any) (int64, error) {
	query := r.trm.GetEngine(ctx).AllCols()
	affected, err := query.Insert(entity)
	if err != nil {
		return affected, err
	}

	return affected, nil
}
