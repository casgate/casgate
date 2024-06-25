# logger

## Usage

* Initializing global logger

```golang
InitGlobal(loggerConfig)
```

* Initializing storage in context for logger data:

```golang
ctx := InitLoggerCtx(context.Background()) // pass the context from request
```

* Adding values to context storage

```golang
logger.SetItem(ctx, "request_id", 12345)
```

