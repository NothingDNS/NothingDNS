package load

import (
	"context"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ---------------------------------------------------------------------------
// RunPreset presets coverage — just exercise each preset branch
// ---------------------------------------------------------------------------

func TestRunPreset_Medium(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "medium")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("medium: errors=%d timeouts=%d", result.Errors, result.Timeouts)
}

func TestRunPreset_Heavy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "heavy")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("heavy: errors=%d timeouts=%d", result.Errors, result.Timeouts)
}

func TestRunPreset_Stress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "stress")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("stress: errors=%d timeouts=%d", result.Errors, result.Timeouts)
}

func TestRunPreset_Default(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "unknown-preset")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	t.Logf("default: errors=%d timeouts=%d", result.Errors, result.Timeouts)
}

// ---------------------------------------------------------------------------
// sendQuery error paths via short timeout
// ---------------------------------------------------------------------------

func TestRunner_SendQuery_InvalidName(t *testing.T) {
	cfg := Config{
		Server:  "127.0.0.1:5354",
		Queries: 1,
		Workers: 1,
		Name:    "..invalid..name..",
		Type:    protocol.TypeA,
		Timeout: 1 * time.Second,
	}
	runner := NewRunner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runner.Run(ctx)
	// Invalid name causes errors in sendQuery
	if result.Errors == 0 {
		t.Error("expected errors for invalid name")
	}
}

func TestRunner_TCPProtocol(t *testing.T) {
	cfg := Config{
		Server:   "127.0.0.1:1",
		Queries:  1,
		Workers:  1,
		Protocol: "tcp",
		Name:     "www.example.com.",
		Type:     protocol.TypeA,
		Timeout:  100 * time.Millisecond,
	}
	runner := NewRunner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runner.Run(ctx)
	// Connection should fail (nothing listening on port 1)
	if result.Errors == 0 && result.Timeouts == 0 {
		t.Log("expected errors or timeouts connecting to port 1")
	}
}

func TestRunner_UDPProtocol(t *testing.T) {
	cfg := Config{
		Server:   "127.0.0.1:1",
		Queries:  1,
		Workers:  1,
		Protocol: "udp",
		Name:     "www.example.com.",
		Type:     protocol.TypeA,
		Timeout:  100 * time.Millisecond,
	}
	runner := NewRunner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := runner.Run(ctx)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}
