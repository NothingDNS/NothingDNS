package util

// coverage_extra_test.go adds tests for remaining low-coverage functions in the util package.

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

// ============================================================================
// logger.go: log method - JSON marshal error path (line 176)
// ============================================================================

// unmarshallableType contains a field that cannot be marshaled to JSON.
type unmarshallableType struct {
	Ch chan int
}

func TestLoggerLogJSONMarshalError(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, JSONFormat, &buf)

	// Create a logger with a field that cannot be marshaled to JSON.
	logger2 := logger.WithField("bad", unmarshallableType{Ch: make(chan int)})
	logger2.log(INFO, "should fail marshal")

	// The log method should have written to stderr (we can't capture that easily)
	// but it should NOT have written anything to buf since it returns early.
	if buf.Len() > 0 {
		output := buf.String()
		if strings.Contains(output, "should fail marshal") {
			t.Error("log should have returned early on marshal error, but output was written")
		}
	}
}

// ============================================================================
// logger.go: log method - covering non-FATAL levels thoroughly
// ============================================================================

func TestLoggerLogFatalBranch(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	// Exercise all non-FATAL level paths
	logger.log(ERROR, "error msg")
	if !strings.Contains(buf.String(), "error msg") {
		t.Error("Expected error message in output")
	}

	buf.Reset()
	logger.log(WARN, "warn msg")
	if !strings.Contains(buf.String(), "warn msg") {
		t.Error("Expected warn message in output")
	}

	buf.Reset()
	logger.log(DEBUG, "debug msg")
	if !strings.Contains(buf.String(), "debug msg") {
		t.Error("Expected debug message in output")
	}
}

// ============================================================================
// logger.go: log method - extra fields merged correctly
// ============================================================================

func TestLoggerLogMultipleExtraFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	logger.log(INFO, "multi fields",
		Fields{"a": "1"},
		Fields{"b": "2"},
	)
	output := buf.String()
	if !strings.Contains(output, "a=1") {
		t.Errorf("Expected a=1 in output, got: %s", output)
	}
	if !strings.Contains(output, "b=2") {
		t.Errorf("Expected b=2 in output, got: %s", output)
	}
}

// ============================================================================
// logger.go: log method - JSON output with fields
// ============================================================================

func TestLoggerLogJSONWithLoggerFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, JSONFormat, &buf)

	logger2 := logger.WithField("persistent", "value")
	logger2.log(INFO, "json with fields", Fields{"extra": "data"})
	output := buf.String()

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %s, err: %v", output, err)
	}
	if parsed["persistent"] != "value" {
		t.Errorf("Expected persistent=value, got: %v", parsed["persistent"])
	}
	if parsed["extra"] != "data" {
		t.Errorf("Expected extra=data, got: %v", parsed["extra"])
	}
}

// ============================================================================
// ip.go: ReverseDNS - IPv6 path with full verification
// ============================================================================

func TestReverseDNSIPv6Full(t *testing.T) {
	ip := mustParseIPExtra(t, "2001:db8::1")
	result := ReverseDNS(ip)
	if !strings.HasSuffix(result, ".ip6.arpa") {
		t.Errorf("Expected .ip6.arpa suffix, got: %s", result)
	}
	parts := strings.Split(strings.TrimSuffix(result, ".ip6.arpa"), ".")
	if len(parts) != 32 {
		t.Fatalf("Expected 32 nibbles for IPv6, got %d", len(parts))
	}
	// Last byte is 0x01, so first nibbles (reversed) are 1, 0
	if parts[0] != "1" || parts[1] != "0" {
		t.Errorf("First nibbles should be 1,0, got %s,%s", parts[0], parts[1])
	}
}

func mustParseIPExtra(t *testing.T, s string) net.IP {
	t.Helper()
	ip := ParseIP(s)
	if ip == nil {
		t.Fatalf("Failed to parse IP: %s", s)
	}
	return ip
}
