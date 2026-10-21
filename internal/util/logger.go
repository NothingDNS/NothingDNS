// Package util provides shared utility functions for NothingDNS.
package util

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
//
// Loggers derived with WithField/WithFields share their parent's level,
// format and output (F626): SetLevel, SetFormat or SetOutput on any logger
// of the family — e.g. a SIGHUP or PUT /api/v1/config/logging change on the
// root logger — applies to all of them. Only the fields are per-logger.
type Logger struct {
	*logSink
	fields     Fields
	timeFormat string
}

// logSink is the level/format/output state shared by a logger and every
// logger derived from it.
type logSink struct {
	mu      sync.RWMutex
	level   LogLevel
	format  LogFormat
	output  io.Writer
	writeMu sync.Mutex
}

// NewLogger creates a new Logger with the specified configuration.
func NewLogger(level LogLevel, format LogFormat, output io.Writer) *Logger {
	if output == nil {
		output = os.Stdout
	}
	return &Logger{
		logSink:    &logSink{level: level, format: format, output: output},
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

// Level returns the current minimum log level.
func (l *Logger) Level() LogLevel {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
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
	if output == nil {
		output = os.Stdout
	}
	l.output = output
}

// WithField returns a new Logger with the specified field added.
func (l *Logger) WithField(key string, value interface{}) *Logger {
	newFields := make(Fields, len(l.fields)+1)
	for k, v := range l.fields {
		newFields[k] = v
	}
	newFields[key] = value

	return &Logger{
		logSink:    l.logSink,
		fields:     newFields,
		timeFormat: l.timeFormat,
	}
}

// WithFields returns a new Logger with the specified fields added. A nil
// Logger stays nil so chained level methods keep discarding.
func (l *Logger) WithFields(fields Fields) *Logger {
	if l == nil {
		return nil
	}
	newFields := make(Fields, len(l.fields)+len(fields))
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}

	return &Logger{
		logSink:    l.logSink,
		fields:     newFields,
		timeFormat: l.timeFormat,
	}
}

// log is the internal logging method. A nil Logger discards: logging must
// never take down request processing when a handler was wired without one
// (the zero-value integratedHandler the transport coverage tests boot, and
// any mis-wired build), so all level methods are nil-receiver safe through
// this funnel.
func (l *Logger) log(level LogLevel, msg string, fields ...Fields) {
	if l == nil {
		return
	}
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

	l.writeMu.Lock()
	fmt.Fprintln(l.output, output)
	l.writeMu.Unlock()

	if level == FATAL {
		osExitFn(1)
	}
}

// osExitFn is overridable for tests. Defaults to os.Exit.
var osExitFn = os.Exit

// formatText formats log fields as human-readable text.
func (l *Logger) formatText(fields Fields) string {
	timestamp := fields["time"].(string)
	level := fields["level"].(string)
	msg := fields["msg"].(string)
	// Sanitize the message with the same CR/LF replacement as field values:
	// upstream error strings can carry attacker-controlled newlines that
	// forge fake log entries in the text format.
	msg = sanitizeLogText(msg)

	result := fmt.Sprintf("[%s] %s: %s", timestamp, level, msg)

	// Add other fields
	for k, v := range fields {
		if k != "time" && k != "level" && k != "msg" {
			// Sanitize value to prevent log injection attacks
			// Replace CR/LF with spaces to prevent fake log entries
			val := fmt.Sprintf("%v", v)
			val = sanitizeLogText(val)
			result += fmt.Sprintf(" %s=%s", k, val)
		}
	}

	return result
}

// sanitizeLogText keeps a text-format log entry on one line and free of
// terminal control sequences (F705): CR/LF become spaces, and every other
// control character (C0 other than tab, DEL, C1 including NEL, U+2028/2029)
// is written as \xNN / \uNNNN so an attacker-chosen name cannot forge lines
// or drive the operator's terminal.
func sanitizeLogText(s string) string {
	clean := true
	for _, r := range s {
		if isLogControl(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch {
		case r == '\r' || r == '\n':
			b.WriteByte(' ')
		case r < 0x100 && isLogControl(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		case isLogControl(r):
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isLogControl(r rune) bool {
	return (r < 0x20 && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029
}

// enabled reports whether a message at level would be written. The formatted
// log methods check it before fmt.Sprintf so a suppressed message (the
// per-query Debugf calls at level=info/error) costs no formatting or
// allocation. A nil Logger is never enabled.
func (l *Logger) enabled(level LogLevel) bool {
	if l == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return level >= l.level
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string) {
	l.log(DEBUG, msg)
}

// Debugf logs a formatted debug message.
func (l *Logger) Debugf(format string, args ...interface{}) {
	if !l.enabled(DEBUG) {
		return
	}
	l.log(DEBUG, fmt.Sprintf(format, args...))
}

// Info logs an info message.
func (l *Logger) Info(msg string) {
	l.log(INFO, msg)
}

// Infof logs a formatted info message.
func (l *Logger) Infof(format string, args ...interface{}) {
	if !l.enabled(INFO) {
		return
	}
	l.log(INFO, fmt.Sprintf(format, args...))
}

// Warn logs a warning message.
func (l *Logger) Warn(msg string) {
	l.log(WARN, msg)
}

// Warnf logs a formatted warning message.
func (l *Logger) Warnf(format string, args ...interface{}) {
	if !l.enabled(WARN) {
		return
	}
	l.log(WARN, fmt.Sprintf(format, args...))
}

// Error logs an error message.
func (l *Logger) Error(msg string) {
	l.log(ERROR, msg)
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(format string, args ...interface{}) {
	if !l.enabled(ERROR) {
		return
	}
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

// Global logger instance for package-level functions. It is replaced at
// startup with the configured logger while other goroutines may be logging,
// so it is held in an atomic pointer.
var defaultLogger atomic.Pointer[Logger]

func init() { defaultLogger.Store(DefaultLogger()) }

// SetDefaultLogger sets the global default logger.
func SetDefaultLogger(l *Logger) {
	if l == nil {
		l = DefaultLogger()
	}
	defaultLogger.Store(l)
}

// GetDefaultLogger returns the global default logger.
func GetDefaultLogger() *Logger {
	return defaultLogger.Load()
}

// Package-level convenience functions.

func Debug(msg string)                          { defaultLogger.Load().Debug(msg) }
func Debugf(format string, args ...interface{}) { defaultLogger.Load().Debugf(format, args...) }
func Info(msg string)                           { defaultLogger.Load().Info(msg) }
func Infof(format string, args ...interface{})  { defaultLogger.Load().Infof(format, args...) }
func Warn(msg string)                           { defaultLogger.Load().Warn(msg) }
func Warnf(format string, args ...interface{})  { defaultLogger.Load().Warnf(format, args...) }
func Error(msg string)                          { defaultLogger.Load().Error(msg) }
func Errorf(format string, args ...interface{}) { defaultLogger.Load().Errorf(format, args...) }
func WithField(key string, value interface{}) *Logger {
	return defaultLogger.Load().WithField(key, value)
}
func WithFields(fields Fields) *Logger {
	return defaultLogger.Load().WithFields(fields)
}
