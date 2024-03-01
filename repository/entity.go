package repository

import (
	"context"

	"github.com/xorm-io/builder"
	"github.com/xorm-io/core"
)

func (r *Repo) UpdateEntitiesFieldValue(ctx context.Context, entityName, fieldName, newValue string, findConditions map[string]interface{}) error {
	bean := make(map[string]interface{})
	bean[fieldName] = newValue

	whereCond := builder.Eq{}
	for field, value := range findConditions {
		whereCond[field] = value
	}

	_, err := r.trm.GetEngine(ctx).Table(entityName).Where(whereCond).Update(bean)
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
	return query.Insert(entity)
}
