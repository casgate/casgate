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
	"bytes"
	"context"
	"log/slog"
	"testing"
)

func TestInitGlobal(t *testing.T) {
	config := &Config{Level: "info"}
	InitGlobal(config)
	if globalLogger == nil {
		t.Error("Expected globalLogger to be initialized")
	}
}

func TestCreateLogger(t *testing.T) {
	config := &Config{Level: "info"}
	logger := Create(config)
	if logger == nil {
		t.Error("Expected logger to be created")
	}
}

func TestDebugLogLevelSkipped(t *testing.T) {
	tests := []struct {
		loggerLevel    string
		shouldLogDebug bool
	}{
		{loggerLevel: "debug", shouldLogDebug: true},
		{loggerLevel: "info", shouldLogDebug: false},
		{loggerLevel: "warn", shouldLogDebug: false},
		{loggerLevel: "error", shouldLogDebug: false},
	}

	for _, tt := range tests {
		t.Run(tt.loggerLevel, func(t *testing.T) {
			config := &Config{Level: tt.loggerLevel}
			logger := Create(config)
			var buf bytes.Buffer
			logger.l = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			}))

			logger.Debug(context.Background(), "debug")
			logger.Info(context.Background(), "info")
			logger.Warn(context.Background(), "warn")
			logger.Error(context.Background(), "error")

			if tt.shouldLogDebug && bytes.Contains(buf.Bytes(), []byte("debug")) {
				t.Errorf("Unexpected debug log output for level: %s", tt.loggerLevel)
			}
		})
	}
}

func TestGlobalLoggerFunctions(t *testing.T) {
	config := &Config{Level: "debug"}
	InitGlobal(config)

	var buf bytes.Buffer
	globalLogger.l = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	Debug(context.Background(), "debug message")
	if !bytes.Contains(buf.Bytes(), []byte("debug message")) {
		t.Error("Expected debug message to be logged")
	}

	Info(context.Background(), "info message")
	if !bytes.Contains(buf.Bytes(), []byte("info message")) {
		t.Error("Expected info message to be logged")
	}

	Warn(context.Background(), "warn message")
	if !bytes.Contains(buf.Bytes(), []byte("warn message")) {
		t.Error("Expected warn message to be logged")
	}

	Error(context.Background(), "error message")
	if !bytes.Contains(buf.Bytes(), []byte("error message")) {
		t.Error("Expected error message to be logged")
	}
}

func TestLoggerWithContext(t *testing.T) {
	ctx := InitLoggerCtx(context.Background())
	SetItem(ctx, "userID", "1234")

	var buf bytes.Buffer
	globalLogger.l = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	Debug(ctx, "This is a debug message with context", "key", "value", "userID", "1234")

	if !bytes.Contains(buf.Bytes(), []byte(`"userID":"1234"`)) {
		t.Errorf("expected userID to be logged")
	}
	if !bytes.Contains(buf.Bytes(), []byte("This is a debug message with context")) {
		t.Errorf("expected debug message to be logged")
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"key":"value"`)) {
		t.Errorf("expected key-value to be logged with message")
	}
	if bytes.Count(buf.Bytes(), []byte(`"userID"`)) > 1 {
		t.Errorf("same key from arg must overlapp value in context")
	}
}
