package util

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// ============================================================================
// UnescapeLabel - empty string
// ============================================================================

func TestUnescapeLabelEmptyString(t *testing.T) {
	result, err := UnescapeLabel("")
	if err != nil {
		t.Errorf("Unexpected error for empty string: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty result, got: %q", result)
	}
}

// ============================================================================
// UnescapeLabel - plain string with no escapes
// ============================================================================

func TestUnescapeLabelPlainString(t *testing.T) {
	result, err := UnescapeLabel("helloworld")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "helloworld" {
		t.Errorf("Expected 'helloworld', got: %q", result)
	}
}

// ============================================================================
// UnescapeLabel - decimal escape exactly 3 digits at string boundary
// (i+3 == len(label) edge case for the i+3 >= len check)
// ============================================================================

func TestUnescapeLabelDecimalEscapeExactBoundary(t *testing.T) {
	// \065 at the very end of the string: i+3 == len(label), so i+3 >= len(label) is false
	// wait: i is index of backslash, so if label="ab\\065", backslash is at index 2,
	// i+3 = 5, len(label) = 6, so 5 >= 6 is false -> passes the check.
	// For the incomplete case, let's test \065 at exact boundary where i+3 == len(label)-1
	result, err := UnescapeLabel("ab\\065")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "abA" {
		t.Errorf("Expected 'abA', got: %q", result)
	}
}

// ============================================================================
// UnescapeLabel - decimal escape incomplete: exactly 2 digits after backslash
// at string end (i+3 >= len(label))
// ============================================================================

func TestUnescapeLabelDecimalEscapeIncomplete2(t *testing.T) {
	// \12 at the end: backslash at i=0, i+3=3, len=3, so 3>=3 is true -> incomplete
	result, err := UnescapeLabel("\\12")
	if err == nil {
		t.Errorf("Expected error for incomplete decimal escape, got: %q", result)
	}
	if err != nil && !strings.Contains(err.Error(), "incomplete decimal escape") {
		t.Errorf("Expected 'incomplete decimal escape' error, got: %v", err)
	}
}

// ============================================================================
// UnescapeLabel - decimal escape incomplete: 1 digit after backslash
// ============================================================================

func TestUnescapeLabelDecimalEscapeIncomplete1(t *testing.T) {
	// \1 at the end: backslash at i=0, i+3=3, len=2, so 3>=2 is true -> incomplete
	result, err := UnescapeLabel("\\1")
	if err == nil {
		t.Errorf("Expected error for incomplete decimal escape, got: %q", result)
	}
	if err != nil && !strings.Contains(err.Error(), "incomplete decimal escape") {
		t.Errorf("Expected 'incomplete decimal escape' error, got: %v", err)
	}
}

// ============================================================================
// UnescapeLabel - decimal escape for high byte value (0xFF = 255)
// ============================================================================

func TestUnescapeLabelHighByteEscape(t *testing.T) {
	result, err := UnescapeLabel("\\255")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "\xff" {
		t.Errorf("Expected 0xFF byte, got: %q", result)
	}
}

// ============================================================================
// UnescapeLabel - decimal escape for null byte
// ============================================================================

func TestUnescapeLabelNullByteEscape(t *testing.T) {
	result, err := UnescapeLabel("\\000")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result != "\x00" {
		t.Errorf("Expected null byte, got: %q", result)
	}
}

// ============================================================================
// UnescapeLabel - backslash followed by unknown character (default branch)
// This exercises the default case where the char after \ is not ., \, ", or digit
// ============================================================================

func TestUnescapeLabelBackslashUnknownChar(t *testing.T) {
	result, err := UnescapeLabel("\\a")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// default branch: writes the backslash character itself (not 'a')
	if result != "\\a" {
		t.Errorf("Expected '\\a', got: %q", result)
	}
}

// ============================================================================
// UnescapeLabel - backslash followed by lowercase letter
// ============================================================================

func TestUnescapeLabelBackslashLowerLetters(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"\\x", "\\x"},
		{"\\n", "\\n"},
		{"\\t", "\\t"},
		{"\\r", "\\r"},
	}
	for _, tt := range tests {
		result, err := UnescapeLabel(tt.input)
		if err != nil {
			t.Errorf("UnescapeLabel(%q) unexpected error: %v", tt.input, err)
		}
		if result != tt.want {
			t.Errorf("UnescapeLabel(%q) = %q, want %q", tt.input, result, tt.want)
		}
	}
}

// ============================================================================
// ReverseDNS - nil IP path (ip.go line 252-253)
// ============================================================================

func TestReverseDNSNilIP(t *testing.T) {
	var ip net.IP = nil
	result := ReverseDNS(ip)
	if result != "" {
		t.Errorf("Expected empty string for nil IP, got: %q", result)
	}
}

// ============================================================================
// ReverseDNS - IPv6 with bytes having both nibbles > 0
// ============================================================================

func TestReverseDNSIPv6WithNonZeroNibbles(t *testing.T) {
	ip := net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	if ip == nil {
		t.Fatal("Failed to parse IPv6 address")
	}
	result := ReverseDNS(ip)
	if !strings.HasSuffix(result, ".ip6.arpa") {
		t.Errorf("Expected .ip6.arpa suffix, got: %s", result)
	}
	// Verify the nibbles are correct for the last byte (0x34)
	// 0x34 = 0011 0100, low nibble = 4, high nibble = 3
	// First two parts (reversed from last byte) should be "4", "3"
	parts := strings.Split(strings.TrimSuffix(result, ".ip6.arpa"), ".")
	if len(parts) != 32 {
		t.Fatalf("Expected 32 nibbles, got %d", len(parts))
	}
	if parts[0] != "4" {
		t.Errorf("First nibble should be 4, got: %s", parts[0])
	}
	if parts[1] != "3" {
		t.Errorf("Second nibble should be 3, got: %s", parts[1])
	}
}

// ============================================================================
// ReverseDNS - IPv4 boundary addresses
// ============================================================================

func TestReverseDNSIPv4Boundary(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{"0.0.0.0", "0.0.0.0.in-addr.arpa"},
		{"255.255.255.255", "255.255.255.255.in-addr.arpa"},
		{"1.2.3.4", "4.3.2.1.in-addr.arpa"},
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		result := ReverseDNS(ip)
		if result != tc.expected {
			t.Errorf("ReverseDNS(%q) = %q, want %q", tc.ip, result, tc.expected)
		}
	}
}

// ============================================================================
// Logger.log - write error path (logger.go line 184)
// ============================================================================

type errorWriter struct{}

func (ew *errorWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("write error")
}

func TestLoggerLogWriteError(t *testing.T) {
	ew := &errorWriter{}
	logger := NewLogger(DEBUG, TextFormat, ew)

	// Should not panic when write fails
	logger.log(INFO, "this should fail to write")

	// With JSON format too
	logger2 := NewLogger(DEBUG, JSONFormat, ew)
	logger2.log(INFO, "json write error")
}

// ============================================================================
// Logger.log - empty message
// ============================================================================

func TestLoggerLogEmptyMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, TextFormat, &buf)

	logger.log(INFO, "")
	output := buf.String()
	if !strings.Contains(output, "INFO") {
		t.Errorf("Expected INFO level in output, got: %s", output)
	}
}

// ============================================================================
// Logger.log - JSON format with no extra fields
// ============================================================================

func TestLoggerLogJSONNoFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, JSONFormat, &buf)

	// Logger with no extra fields, log with no additional fields
	logger.log(INFO, "simple json")
	output := buf.String()
	if !strings.Contains(output, `"msg":"simple json"`) {
		t.Errorf("Expected JSON msg field, got: %s", output)
	}
	if !strings.Contains(output, `"level":"INFO"`) {
		t.Errorf("Expected JSON level field, got: %s", output)
	}
}

// ============================================================================
// signal.go: listen - SIGHUP path with reload function
// We write directly to sigChan to avoid killing the test process.
// ============================================================================

func TestSignalHandlerListenSIGHUP(t *testing.T) {
	s := NewSignalHandler()

	var reloadCalled int32
	s.OnReload(func() {
		atomic.AddInt32(&reloadCalled, 1)
	})

	// Redirect the default logger
	var logBuf bytes.Buffer
	SetDefaultLogger(NewLogger(DEBUG, TextFormat, &logBuf))

	s.Start()

	// Small delay to ensure the listen goroutine is in the select
	time.Sleep(50 * time.Millisecond)

	// Write SIGHUP directly to the signal channel
	s.sigChan <- syscall.SIGHUP

	// Wait for the reload to be processed
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&reloadCalled) != 1 {
		t.Errorf("Expected reload to be called once, got %d", atomic.LoadInt32(&reloadCalled))
	}

	s.Stop()
	SetDefaultLogger(NewLogger(INFO, TextFormat, os.Stdout))
}

// ============================================================================
// signal.go: listen - SIGHUP path without reload function (warning path)
// ============================================================================

func TestSignalHandlerListenSIGHUPNoReload(t *testing.T) {
	s := NewSignalHandler()

	// Don't set any reload function

	// Redirect default logger to capture warning
	var logBuf bytes.Buffer
	SetDefaultLogger(NewLogger(DEBUG, TextFormat, &logBuf))

	s.Start()

	time.Sleep(50 * time.Millisecond)

	// Write SIGHUP directly to the signal channel
	s.sigChan <- syscall.SIGHUP

	time.Sleep(100 * time.Millisecond)

	// Should have logged a warning about no reload function
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "No reload function") {
		t.Errorf("Expected warning about no reload function, got: %s", logOutput)
	}

	s.Stop()
	SetDefaultLogger(NewLogger(INFO, TextFormat, os.Stdout))
}

// ============================================================================
// signal.go: listen - SIGINT path (graceful shutdown)
// ============================================================================

func TestSignalHandlerListenSIGINT(t *testing.T) {
	s := NewSignalHandler()

	var shutdownCalled int32
	s.RegisterShutdown(func() error {
		atomic.AddInt32(&shutdownCalled, 1)
		return nil
	})

	// Redirect default logger
	var logBuf bytes.Buffer
	SetDefaultLogger(NewLogger(DEBUG, TextFormat, &logBuf))

	s.Start()

	time.Sleep(50 * time.Millisecond)

	// Write SIGINT directly to the signal channel
	s.sigChan <- syscall.SIGINT

	// Wait for the shutdown to be processed
	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&shutdownCalled) != 1 {
		t.Errorf("Expected shutdown to be called once, got %d", atomic.LoadInt32(&shutdownCalled))
	}

	// The handler should have stopped
	select {
	case <-s.Done():
		// Expected
	case <-time.After(500 * time.Millisecond):
		t.Error("Signal handler should have stopped after SIGINT")
	}

	SetDefaultLogger(NewLogger(INFO, TextFormat, os.Stdout))
}

// ============================================================================
// signal.go: listen - SIGTERM path (graceful shutdown)
// ============================================================================

func TestSignalHandlerListenSIGTERM(t *testing.T) {
	s := NewSignalHandler()

	var shutdownCalled int32
	s.RegisterShutdown(func() error {
		atomic.AddInt32(&shutdownCalled, 1)
		return nil
	})

	// Redirect default logger
	var logBuf bytes.Buffer
	SetDefaultLogger(NewLogger(DEBUG, TextFormat, &logBuf))

	s.Start()

	time.Sleep(50 * time.Millisecond)

	// Write SIGTERM directly to the signal channel
	s.sigChan <- syscall.SIGTERM

	time.Sleep(100 * time.Millisecond)

	if atomic.LoadInt32(&shutdownCalled) != 1 {
		t.Errorf("Expected shutdown to be called once, got %d", atomic.LoadInt32(&shutdownCalled))
	}

	select {
	case <-s.Done():
		// Expected
	case <-time.After(500 * time.Millisecond):
		t.Error("Signal handler should have stopped after SIGTERM")
	}

	SetDefaultLogger(NewLogger(INFO, TextFormat, os.Stdout))
}

// ============================================================================
// signal.go: listen - context cancelled path (exit via ctx.Done())
// ============================================================================

func TestSignalHandlerListenContextCancel(t *testing.T) {
	s := NewSignalHandler()

	var logBuf bytes.Buffer
	SetDefaultLogger(NewLogger(DEBUG, TextFormat, &logBuf))

	s.Start()
	time.Sleep(50 * time.Millisecond)

	// Cancel the context directly - this triggers the <-s.ctx.Done() path
	s.cancel()

	// Wait for the goroutine to finish
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Expected - goroutine exited
	case <-time.After(1 * time.Second):
		t.Error("listen goroutine should have exited after context cancel")
	}

	SetDefaultLogger(NewLogger(INFO, TextFormat, os.Stdout))
}
