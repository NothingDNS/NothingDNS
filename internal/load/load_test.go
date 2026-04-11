package load

import (
	"context"
	"testing"
	"time"
)

func TestRunPreset(t *testing.T) {
	// This test just validates the preset runs without panic
	// Actual load testing requires a running DNS server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "light")

	// With no server running, we expect 100% errors/timeouts
	if result == nil {
		t.Fatal("result was nil")
	}

	t.Logf("Light preset result: Success=%d, Errors=%d, Timeouts=%d",
		result.Success, result.Errors, result.Timeouts)
}

func TestConfigValidation(t *testing.T) {
	cfg := Config{
		Server:   "127.0.0.1:53",
		Queries:  100,
		Workers:  4,
		Timeout:  2 * time.Second,
		Type:     1, // TypeA
		Name:     "www.example.com.",
		Protocol: "tcp",
	}

	runner := NewRunner(cfg)
	if runner == nil {
		t.Fatal("NewRunner returned nil")
	}
}
