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
	"log"
	"log/slog"
	"os"
)

// global usage logging functions

func Debug(ctx context.Context, msg string, args ...any) {
	globalLogger.Debug(ctx, msg, args...)
}

func Info(ctx context.Context, msg string, args ...any) {
	globalLogger.Info(ctx, msg, args...)
}

func Warn(ctx context.Context, msg string, args ...any) {
	globalLogger.Warn(ctx, msg, args...)
}

func Error(ctx context.Context, msg string, args ...any) {
	globalLogger.Error(ctx, msg, args...)
}

// init globalLogger with default slog.log
var globalLogger = &Logger{l: slog.Default()} //nolint: gochecknoglobals // global by design

const defaultLevel = slog.LevelError

type Logger struct {
	l *slog.Logger
}

// InitGlobal init global logger for use as global
func InitGlobal(config *Config) {
	globalLogger = Create(config)
}

// Create create and return new logger
func Create(config *Config) *Logger {
	var levelMapping = map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}

	level, ok := levelMapping[config.Level]
	if !ok {
		log.Printf(
			"Can't init logger with log level from config: %s, will be used default level: error",
			config.Level,
		)

		level = defaultLevel
	}
	logLevel := &slog.LevelVar{}
	logLevel.Set(level)

	logger := &Logger{
		l: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		})),
	}

	return logger
}

func (l *Logger) Debug(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelDebug, msg, args...)
}

func (l *Logger) Info(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelInfo, msg, args...)
}

func (l *Logger) Warn(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelWarn, msg, args...)
}

func (l *Logger) Error(ctx context.Context, msg string, args ...any) {
	l.log(ctx, slog.LevelError, msg, args...)
}

// common log method to log:
// * check if current log level is enabled - to prevent useless workflows around args
func (l *Logger) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	if !l.l.Enabled(ctx, level) {
		return
	}

	l.l.Log(ctx, level, msg, getArgs(ctx, args...)...)
}

// getArgs collects all args to log (include context attrs and passed by client)
func getArgs(ctx context.Context, args ...any) []any {
	attrs := getAttrs(ctx)
	a := make([]any, 0, len(attrs)*2+len(args)) // attrs contains 2 value (key+value)
	for _, attr := range attrs {
		a = append(a, attr.Key, attr.Value.String())
	}
	if len(args) > 0 {
		a = append(a, args...)
	}

	return a
}
