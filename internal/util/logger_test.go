package util

import (
	"bytes"
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
