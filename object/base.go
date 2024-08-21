package object

import (
	"fmt"

	"github.com/beego/beego/context"
	"github.com/beego/beego/utils/pagination"
	"github.com/casdoor/casdoor/orm"
	"github.com/xorm-io/builder"
)

// WPaginator wrapped paginator to return default value for null paginator
type WPaginator struct {
	*pagination.Paginator
}

func (p *WPaginator) Offset() int {
	if p.Paginator == nil {
		return -1
	}

	return p.Paginator.Offset()
}

func (p *WPaginator) Nums() interface{} {
	if p.Paginator == nil {
		return nil
	}

	return p.Paginator.Nums()
}

func GetPaginator[T any](
	ctx *context.Context,
	owner, field, value string,
	limit int,
	entity T,
	conditions ...builder.Cond,
) (*WPaginator, error) {
	if limit == -1 {
		return &WPaginator{}, nil
	}

	count, err := getCount(owner, field, value, entity, conditions...)
	if err != nil {
		return nil, fmt.Errorf("getCount: %w", err)
	}
	return &WPaginator{pagination.SetPaginator(ctx, limit, count)}, nil
}

func getCount[T any](owner, field, value string, entity T, conditions ...builder.Cond) (int64, error) {
	session := orm.GetSession(owner, -1, -1, field, value, "", "")
	for _, condition := range conditions {
		session = session.Where(condition)
	}
	return session.Count(entity)
}
