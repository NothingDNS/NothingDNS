// Package util provides shared utility functions for NothingDNS.
package util

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// LogLevel represents the severity of a log message.
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// String returns the string representation of a log level.
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogFormat represents the output format for log messages.
type LogFormat int

const (
	// TextFormat outputs logs as human-readable text.
	TextFormat LogFormat = iota
	// JSONFormat outputs logs as structured JSON.
	JSONFormat
)

// Fields represents structured log fields.
type Fields map[string]interface{}

// Logger provides structured logging functionality.
type Logger struct {
	level      LogLevel
	format     LogFormat
	output     io.Writer
	fields     Fields
	mu         sync.RWMutex
	timeFormat string
}

// NewLogger creates a new Logger with the specified configuration.
func NewLogger(level LogLevel, format LogFormat, output io.Writer) *Logger {
	if output == nil {
		output = os.Stdout
	}
	return &Logger{
		level:      level,
		format:     format,
		output:     output,
		fields:     make(Fields),
		timeFormat: time.RFC3339,
	}
}

// DefaultLogger returns a logger with sensible defaults.
func DefaultLogger() *Logger {
	return NewLogger(INFO, TextFormat, os.Stdout)
}

// SetLevel sets the minimum log level.
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetFormat sets the log output format.
func (l *Logger) SetFormat(format LogFormat) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.format = format
}

// SetOutput sets the log output destination.
func (l *Logger) SetOutput(output io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = output
}

// WithField returns a new Logger with the specified field added.
func (l *Logger) WithField(key string, value interface{}) *Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	newFields := make(Fields, len(l.fields)+1)
	for k, v := range l.fields {
		newFields[k] = v
	}
	newFields[key] = value

	return &Logger{
		level:      l.level,
		format:     l.format,
		output:     l.output,
		fields:     newFields,
		timeFormat: l.timeFormat,
	}
}

// WithFields returns a new Logger with the specified fields added.
func (l *Logger) WithFields(fields Fields) *Logger {
	l.mu.RLock()
	defer l.mu.RUnlock()

	newFields := make(Fields, len(l.fields)+len(fields))
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}

	return &Logger{
		level:      l.level,
		format:     l.format,
		output:     l.output,
		fields:     newFields,
		timeFormat: l.timeFormat,
	}
}

// log is the internal logging method.
func (l *Logger) log(level LogLevel, msg string, fields ...Fields) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if level < l.level {
		return
	}

	// Merge fields
	allFields := make(Fields, len(l.fields)+1)
	for k, v := range l.fields {
		allFields[k] = v
	}
	for _, f := range fields {
		for k, v := range f {
			allFields[k] = v
		}
	}

	// Add standard fields
	allFields["time"] = time.Now().Format(l.timeFormat)
	allFields["level"] = level.String()
	allFields["msg"] = msg

	var output string
	if l.format == JSONFormat {
		data, err := json.Marshal(allFields)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal log entry: %v\n", err)
			return
		}
		output = string(data)
	} else {
		output = l.formatText(allFields)
	}

	fmt.Fprintln(l.output, output)

	if level == FATAL {
		os.Exit(1)
	}
}

// formatText formats log fields as human-readable text.
func (l *Logger) formatText(fields Fields) string {
	timestamp := fields["time"].(string)
	level := fields["level"].(string)
	msg := fields["msg"].(string)

	result := fmt.Sprintf("[%s] %s: %s", timestamp, level, msg)

	// Add other fields
	for k, v := range fields {
		if k != "time" && k != "level" && k != "msg" {
			result += fmt.Sprintf(" %s=%v", k, v)
		}
	}

	return result
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string) {
	l.log(DEBUG, msg)
}

// Debugf logs a formatted debug message.
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.log(DEBUG, fmt.Sprintf(format, args...))
}

// Info logs an info message.
func (l *Logger) Info(msg string) {
	l.log(INFO, msg)
}

// Infof logs a formatted info message.
func (l *Logger) Infof(format string, args ...interface{}) {
	l.log(INFO, fmt.Sprintf(format, args...))
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string) {
	l.log(WARN, msg)
}

// Warnf logs a formatted warning message.
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.log(WARN, fmt.Sprintf(format, args...))
}

// Error logs an error message.
func (l *Logger) Error(msg string) {
	l.log(ERROR, msg)
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.log(ERROR, fmt.Sprintf(format, args...))
}

// Fatal logs a fatal message and exits.
func (l *Logger) Fatal(msg string) {
	l.log(FATAL, msg)
}

// Fatalf logs a formatted fatal message and exits.
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(FATAL, fmt.Sprintf(format, args...))
}

// Global logger instance for package-level functions.
var defaultLogger = DefaultLogger()

// SetDefaultLogger sets the global default logger.
func SetDefaultLogger(l *Logger) {
	defaultLogger = l
}

// GetDefaultLogger returns the global default logger.
func GetDefaultLogger() *Logger {
	return defaultLogger
}

// Package-level convenience functions.

func Debug(msg string)                          { defaultLogger.Debug(msg) }
func Debugf(format string, args ...interface{}) { defaultLogger.Debugf(format, args...) }
func Info(msg string)                           { defaultLogger.Info(msg) }
func Infof(format string, args ...interface{})  { defaultLogger.Infof(format, args...) }
func Warn(msg string)                           { defaultLogger.Warn(msg) }
func Warnf(format string, args ...interface{})  { defaultLogger.Warnf(format, args...) }
func Error(msg string)                          { defaultLogger.Error(msg) }
func Errorf(format string, args ...interface{}) { defaultLogger.Errorf(format, args...) }
func WithField(key string, value interface{}) *Logger {
	return defaultLogger.WithField(key, value)
}
func WithFields(fields Fields) *Logger {
	return defaultLogger.WithFields(fields)
}
