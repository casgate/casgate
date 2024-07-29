// Copyright 2023 The Casgate Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package txmanager

import (
	"context"

	"github.com/xorm-io/xorm"
)

// ContextKey is a value for use with context.WithValue.
type ContextKey struct {
	name string
}

var (
	enginedContextKey = &ContextKey{"engined"}
)

type TransactionManager struct {
	engine *xorm.Engine
}

func NewTransactionManager(
	engine *xorm.Engine,
) *TransactionManager {
	return &TransactionManager{
		engine: engine,
	}
}

func (trm *TransactionManager) WithTx(parentCtx context.Context, f func(ctx context.Context) error) error {
	if sess, ok := inTransaction(parentCtx); ok {
		err := f(newContext(parentCtx, sess, true))
		if err != nil {
			// rollback immediately, in case the caller ignores returned error and tries to commit the transaction.
			_ = sess.Close()
		}
		return err
	}
	return trm.txWithNoCheck(parentCtx, f)
}

func (trm *TransactionManager) txWithNoCheck(parentCtx context.Context, f func(ctx context.Context) error) error {
	sess := trm.engine.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}

	if err := f(newContext(parentCtx, sess, true)); err != nil {
		return err
	}

	return sess.Commit()
}

func inTransaction(ctx context.Context) (*xorm.Session, bool) {
	e := getEngine(ctx)
	if e == nil {
		return nil, false
	}

	switch t := e.(type) {
	case *xorm.Engine:
		return nil, false
	case *xorm.Session:
		if t.IsInTx() {
			return t, true
		}
		return nil, false
	default:
		return nil, false
	}
}

// GetEngine will get a db Engine from this context or return an Engine restricted to this context
func (trm *TransactionManager) GetEngine(ctx context.Context) xorm.Interface {
	if e := getEngine(ctx); e != nil {
		return e
	}
	return trm.engine.Context(ctx)
}

// getEngine will get a db Engine from this context or return nil
func getEngine(ctx context.Context) xorm.Interface {
	if engined, ok := ctx.(xorm.Interface); ok {
		return engined
	}
	enginedInterface := ctx.Value(enginedContextKey)
	if enginedInterface != nil {
		return enginedInterface.(xorm.Interface)
	}
	return nil
}
