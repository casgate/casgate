package repository

import (
	"context"

	"github.com/casdoor/casdoor/object"
	"github.com/xorm-io/core"
)

func (r *Repo) UpdateTokens(ctx context.Context, tokens []object.User, columns []string) error {
	engine := r.trm.GetEngine(ctx)

	for _, token := range tokens {
		_, err := engine.ID(core.PK{token.Owner, token.Name}).Cols(columns...).Update(&token)
		if err != nil {
			return err
		}
	}

	return nil
}
