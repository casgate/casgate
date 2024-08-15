// Copyright 2024 The Casdoor Authors. All Rights Reserved.
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

package logger

import (
	"context"
	"sync"

	"log/slog"
)

const ctxKey = "LOGGER_CTX_KEY"

// InitLoggerCtx init logger's context with storage
func InitLoggerCtx(ctx context.Context) context.Context {
	logCtx := &loggerCtx{
		items: make(map[string]any),
	}
	return context.WithValue(ctx, ctxKey, logCtx)
}

// SetItem store metadata for logger in passed context
func SetItem(ctx context.Context, key string, value any) {
	logCtx, ok := ctx.Value(ctxKey).(*loggerCtx)
	if !ok {
		return
	}

	logCtx.setItem(key, value)
}

// getAttrs return attrs log logger's context
func getAttrs(ctx context.Context) []slog.Attr {
	logCtx, ok := ctx.Value(ctxKey).(*loggerCtx)
	if !ok {
		return nil
	}

	return logCtx.getAttrs()
}

// loggerCtx private storage for logger's context
type loggerCtx struct {
	mu    sync.RWMutex
	items map[string]any
}

func (logCtx *loggerCtx) setItem(key string, value any) {
	logCtx.mu.Lock()
	defer logCtx.mu.Unlock()

	logCtx.items[key] = value
}

func (logCtx *loggerCtx) getAttrs() []slog.Attr {
	logCtx.mu.RLock()
	defer logCtx.mu.RUnlock()

	attrs := make([]slog.Attr, 0, len(logCtx.items))
	for k, v := range logCtx.items {
		attrs = append(attrs, slog.Any(k, v))
	}

	return attrs
}
