# logger

## Использование

* Инициализация глобального логгера

```golang
InitGlobal(loggerConfig)
```

* Инициализация контекста с поддержкой хранилища для логгера:

```golang
ctx := InitLoggerCtx(context.Background()) // или передача контекста из запроса
```

* Добавление контекстой информации

```golang
logger.SetItem(ctx, "request_id", 12345)
```

