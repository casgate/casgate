package logger

import (
	"context"
	"encoding/json"
)

func LogWithInfo(ctx context.Context, msg interface{}, operation OperationName, result OperationResult) {
	logMsg, err := json.Marshal(msg)
	if err != nil {
		Warn(
			ctx,
			"failed to marshal log message",
			"act", operation,
			"r", OperationResultFailure,
		)
	}

	switch result {
	case OperationResultSuccess:
		Info(
			ctx,
			string(logMsg),
			"act", operation,
			"r", result,
		)

	case OperationResultFailure:
		Error(
			ctx,
			string(logMsg),
			"act", operation,
			"r", result,
		)
	}
}
