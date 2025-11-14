package cprovlib

import (
	"github.com/rs/zerolog"
)

// ZerologAdapter адаптер для zerolog.Logger к интерфейсу Logger
type ZerologAdapter struct {
	logger *zerolog.Logger
}

// NewZerologAdapter создает новый адаптер для zerolog
func NewZerologAdapter(logger *zerolog.Logger) Logger {
	if logger == nil {
		return NewDefaultLogger()
	}
	return &ZerologAdapter{logger: logger}
}

// Debug логирует сообщение уровня Debug
func (a *ZerologAdapter) Debug(msg string, keysAndValues ...interface{}) {
	event := a.logger.Debug()
	a.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Info логирует сообщение уровня Info
func (a *ZerologAdapter) Info(msg string, keysAndValues ...interface{}) {
	event := a.logger.Info()
	a.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Warn логирует сообщение уровня Warn
func (a *ZerologAdapter) Warn(msg string, keysAndValues ...interface{}) {
	event := a.logger.Warn()
	a.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// Error логирует сообщение уровня Error
func (a *ZerologAdapter) Error(msg string, keysAndValues ...interface{}) {
	event := a.logger.Error()
	a.addFields(event, keysAndValues...)
	event.Msg(msg)
}

// addFields добавляет поля в событие из пар ключ-значение
// Поддерживает формат: "key1", value1, "key2", value2, ...
func (a *ZerologAdapter) addFields(event *zerolog.Event, keysAndValues ...interface{}) {
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 >= len(keysAndValues) {
			// Нечетное количество аргументов - игнорируем последний
			break
		}

		key, ok := keysAndValues[i].(string)
		if !ok {
			// Ключ не строка - пропускаем
			continue
		}

		value := keysAndValues[i+1]

		// Определяем тип значения и используем соответствующий метод zerolog
		switch v := value.(type) {
		case string:
			event.Str(key, v)
		case int:
			event.Int(key, v)
		case int64:
			event.Int64(key, v)
		case uint:
			event.Uint(key, v)
		case uint64:
			event.Uint64(key, v)
		case float64:
			event.Float64(key, v)
		case bool:
			event.Bool(key, v)
		case error:
			event.AnErr(key, v)
		default:
			// Для других типов используем Interface
			event.Interface(key, v)
		}
	}
}
