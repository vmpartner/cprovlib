package cprovlib

import (
	"log/slog"
)

// Logger минималистичный интерфейс для логирования.
// Позволяет использовать любую библиотеку логирования (zerolog, slog, и т.д.)
type Logger interface {
	Debug(msg string, keysAndValues ...interface{})
	Info(msg string, keysAndValues ...interface{})
	Warn(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
}

// DefaultLogger дефолтная реализация через log/slog
type DefaultLogger struct{}

// NewDefaultLogger создает новый дефолтный логгер
func NewDefaultLogger() Logger {
	return &DefaultLogger{}
}

func (l *DefaultLogger) Debug(msg string, keysAndValues ...interface{}) {
	slog.Debug(msg, keysAndValues...)
}

func (l *DefaultLogger) Info(msg string, keysAndValues ...interface{}) {
	slog.Info(msg, keysAndValues...)
}

func (l *DefaultLogger) Warn(msg string, keysAndValues ...interface{}) {
	slog.Warn(msg, keysAndValues...)
}

func (l *DefaultLogger) Error(msg string, keysAndValues ...interface{}) {
	slog.Error(msg, keysAndValues...)
}
