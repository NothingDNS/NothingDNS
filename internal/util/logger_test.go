package util

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARN, "WARN"},
		{ERROR, "ERROR"},
		{FATAL, "FATAL"},
		{LogLevel(99), "UNKNOWN"},
	}

	for _, tc := range tests {
		result := tc.level.String()
		if result != tc.expected {
			t.Errorf("LogLevel(%d).String() = %q, want %q", tc.level, result, tc.expected)
		}
	}
}

func TestLoggerTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	logger.Info("test message")
	output := buf.String()

	if !strings.Contains(output, "INFO") {
		t.Errorf("Expected output to contain 'INFO', got: %s", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected output to contain 'test message', got: %s", output)
	}
}

func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, JSONFormat, &buf)

	logger.Info("test message")
	output := buf.String()

	if !strings.Contains(output, `"level":"INFO"`) {
		t.Errorf("Expected output to contain JSON level, got: %s", output)
	}
	if !strings.Contains(output, `"msg":"test message"`) {
		t.Errorf("Expected output to contain JSON message, got: %s", output)
	}
}

func TestLoggerWithField(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	logger.WithField("key", "value").Info("test")
	output := buf.String()

	if !strings.Contains(output, "key=value") {
		t.Errorf("Expected output to contain 'key=value', got: %s", output)
	}
}

func TestLoggerWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	logger.WithFields(Fields{"a": "1", "b": "2"}).Info("test")
	output := buf.String()

	if !strings.Contains(output, "a=1") && !strings.Contains(output, "b=2") {
		t.Errorf("Expected output to contain fields, got: %s", output)
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(WARN, TextFormat, &buf)

	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	output := buf.String()

	if strings.Contains(output, "debug message") {
		t.Error("Debug message should be filtered out")
	}
	if strings.Contains(output, "info message") {
		t.Error("Info message should be filtered out")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("Warn message should not be filtered out")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Error message should not be filtered out")
	}
}

func TestLoggerFormattedMethods(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	logger.Debugf("debug %s", "test")
	logger.Infof("info %d", 42)
	logger.Warnf("warn %v", true)
	logger.Errorf("error %s %d", "msg", 1)

	output := buf.String()

	if !strings.Contains(output, "debug test") {
		t.Error("Debugf message not found")
	}
	if !strings.Contains(output, "info 42") {
		t.Error("Infof message not found")
	}
	if !strings.Contains(output, "warn true") {
		t.Error("Warnf message not found")
	}
	if !strings.Contains(output, "error msg 1") {
		t.Error("Errorf message not found")
	}
}

func TestDefaultLogger(t *testing.T) {
	// Just verify it doesn't panic
	SetDefaultLogger(DefaultLogger())

	// These should not panic
	Debug("debug")
	Info("info")
	Warn("warn")
	Error("error")

	// Don't test Fatal as it calls os.Exit
}

func TestNewLoggerWithNilOutput(t *testing.T) {
	// When output is nil, it should default to os.Stdout
	logger := NewLogger(INFO, TextFormat, nil)
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
	if logger.output != os.Stdout {
		t.Error("Logger output should default to os.Stdout when nil is passed")
	}
}

func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, TextFormat, &buf)

	// Initially INFO level, debug should be filtered
	logger.Debug("should not appear")
	if buf.Len() > 0 {
		t.Error("Debug should be filtered at INFO level")
	}

	// Change level to DEBUG
	logger.SetLevel(DEBUG)
	logger.Debug("should appear now")
	if !strings.Contains(buf.String(), "should appear now") {
		t.Error("Debug should appear after SetLevel(DEBUG)")
	}
}

func TestLoggerSetFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, TextFormat, &buf)

	logger.Info("text message")
	if !strings.Contains(buf.String(), "[") {
		t.Error("Expected text format with brackets")
	}

	buf.Reset()
	logger.SetFormat(JSONFormat)
	logger.Info("json message")
	if !strings.Contains(buf.String(), `"level":"INFO"`) {
		t.Error("Expected JSON format after SetFormat")
	}
}

func TestLoggerSetOutput(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger := NewLogger(INFO, TextFormat, &buf1)

	logger.Info("to buf1")
	if !strings.Contains(buf1.String(), "to buf1") {
		t.Error("Expected output in buf1")
	}

	logger.SetOutput(&buf2)
	logger.Info("to buf2")
	if !strings.Contains(buf2.String(), "to buf2") {
		t.Error("Expected output in buf2 after SetOutput")
	}
}

func TestLoggerSetOutputNilDefaultsStdout(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, TextFormat, &buf)

	logger.SetOutput(nil)

	if logger.output != os.Stdout {
		t.Error("Logger output should default to os.Stdout when nil is passed to SetOutput")
	}
}

func TestSetDefaultLoggerNilRestoresDefault(t *testing.T) {
	original := GetDefaultLogger()
	defer SetDefaultLogger(original)

	SetDefaultLogger(nil)

	logger := GetDefaultLogger()
	if logger == nil {
		t.Fatal("SetDefaultLogger(nil) left default logger nil")
	}
	if logger.output != os.Stdout {
		t.Error("SetDefaultLogger(nil) should restore a stdout-backed default logger")
	}
}

func TestLoggerWithFieldsNil(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	// WithFields with nil should still work
	logger2 := logger.WithFields(nil)
	logger2.Info("test")
	output := buf.String()
	if !strings.Contains(output, "test") {
		t.Error("Expected output with nil fields")
	}
}

func TestLoggerLogWithAdditionalFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, JSONFormat, &buf)

	// Test the internal log method with additional fields
	logger.Info("message")
	output := buf.String()
	if !strings.Contains(output, `"msg":"message"`) {
		t.Errorf("Expected JSON output with msg field, got: %s", output)
	}
}

func TestGetDefaultLogger(t *testing.T) {
	logger := GetDefaultLogger()
	if logger == nil {
		t.Error("GetDefaultLogger should not return nil")
	}
}

func TestPackageLevelWithField(t *testing.T) {
	logger := WithField("testkey", "testvalue")
	if logger == nil {
		t.Error("WithField should not return nil")
	}
}

func TestPackageLevelWithFields(t *testing.T) {
	logger := WithFields(Fields{"key1": "value1", "key2": "value2"})
	if logger == nil {
		t.Error("WithFields should not return nil")
	}
}

func TestPackageLevelDebugf(t *testing.T) {
	// Set to DEBUG level to ensure output
	SetDefaultLogger(NewLogger(DEBUG, TextFormat, os.Stdout))
	Debugf("debug formatted %s", "message")
	// Should not panic
}

func TestPackageLevelInfof(t *testing.T) {
	SetDefaultLogger(NewLogger(INFO, TextFormat, os.Stdout))
	Infof("info formatted %d", 42)
	// Should not panic
}

func TestPackageLevelWarnf(t *testing.T) {
	SetDefaultLogger(NewLogger(WARN, TextFormat, os.Stdout))
	Warnf("warn formatted %v", true)
	// Should not panic
}

func TestPackageLevelErrorf(t *testing.T) {
	SetDefaultLogger(NewLogger(ERROR, TextFormat, os.Stdout))
	Errorf("error formatted %s", "test")
	// Should not panic
}

// ============================================================================
// Fatal/Fatalf — these do NOT call os.Exit in this implementation
// (they only emit a FATAL-level log line). Cover both branches.
// ============================================================================

func TestLoggerFatal(t *testing.T) {
	// Substitute os.Exit with a panic-style sentinel so the process stays alive.
	prev := osExitFn
	defer func() { osExitFn = prev }()

	called := false
	osExitFn = func(code int) {
		called = true
		// Don't actually exit.
	}

	buf := &bytes.Buffer{}
	l := NewLogger(FATAL, TextFormat, buf)

	l.Fatal("fatal message")

	if !called {
		t.Errorf("Fatal did not invoke osExitFn")
	}
	out := buf.String()
	if !strings.Contains(out, "fatal message") {
		t.Errorf("Fatal did not log message; got %q", out)
	}
	if !strings.Contains(out, "FATAL") {
		t.Errorf("Fatal did not include level; got %q", out)
	}
}

func TestLoggerFatalf(t *testing.T) {
	prev := osExitFn
	defer func() { osExitFn = prev }()

	called := false
	osExitFn = func(code int) { called = true }

	buf := &bytes.Buffer{}
	l := NewLogger(FATAL, TextFormat, buf)

	l.Fatalf("formatted %s %d", "fatal", 42)

	if !called {
		t.Errorf("Fatalf did not invoke osExitFn")
	}
	out := buf.String()
	if !strings.Contains(out, "formatted fatal 42") {
		t.Errorf("Fatalf did not format message; got %q", out)
	}
}

func TestPackageLevelFatal(t *testing.T) {
	SetDefaultLogger(NewLogger(FATAL, TextFormat, os.Stdout))
	// Package-level Fatal/Fatalf helpers are not part of the public API in
	// this implementation — only Logger.Fatal/Fatalf exist. The Logger.Fatal
	// variants are covered above. Keep this hook to ensure SetDefaultLogger
	// accepts a FATAL-level logger without panicking.
	_ = GetDefaultLogger()
}

func TestPackageLevelFatalf(t *testing.T) {
	SetDefaultLogger(NewLogger(FATAL, TextFormat, os.Stdout))
	// See TestPackageLevelFatal.
	_ = GetDefaultLogger()
}

// Log-injection guard: formatText sanitizes field values (CR/LF → spaces),
// but interpolated the raw msg — an upstream error string carrying newlines
// (the established `util.Warnf("...: %v", err)` pattern) forged fake log
// entries in the text format.
func TestWarnfMsgSanitizedInTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, TextFormat, &buf)

	logger.Warnf("upstream query failed: %v", errors.New("boom\nINFO  forged-entry: attacker-controlled"))

	out := buf.String()
	if strings.Contains(out, "\nINFO") {
		t.Fatalf("FAIL: text-format log injection — the raw msg newline produced a forged log line: %q", out)
	}
	if !strings.Contains(out, "upstream query failed") {
		t.Fatalf("FAIL: the legitimate message was lost: %q", out)
	}
}

// The existing field-value sanitization (CR/LF → spaces) must keep holding.
func TestLogFieldsSanitizedInTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, TextFormat, &buf)

	logger.WithField("client", "1.2.3.4\nINFO  forged").Warn("hello")

	out := buf.String()
	if strings.Contains(out, "\nINFO") {
		t.Fatalf("FAIL: field-value log injection — CR/LF survived in a field value: %q", out)
	}
}
