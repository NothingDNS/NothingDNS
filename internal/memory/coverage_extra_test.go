package memory

import (
	"testing"
)

// ---------------------------------------------------------------------------
// handleStateChange direct testing
// ---------------------------------------------------------------------------

func TestHandleStateChange_Critical(t *testing.T) {
	ev := &mockEvictor{}
	m := NewMonitor(Config{LimitBytes: 1024}, ev)

	m.handleStateChange(StateNormal, StateCritical, 99.0)

	if ev.clearCalls == 0 {
		t.Error("expected Clear() on Critical transition")
	}
}

func TestHandleStateChange_Warning(t *testing.T) {
	ev := &mockEvictor{}
	m := NewMonitor(Config{LimitBytes: 1024}, ev)

	m.handleStateChange(StateNormal, StateWarning, 85.0)

	if len(ev.evictCalls) != 1 || ev.evictCalls[0] != 50 {
		t.Errorf("expected Evict(50), got %v", ev.evictCalls)
	}
}

func TestHandleStateChange_WarningWithGC(t *testing.T) {
	ev := &mockEvictor{}
	m := NewMonitor(Config{LimitBytes: 1024, GCOnWarning: true}, ev)

	// Should not panic with GC enabled
	m.handleStateChange(StateNormal, StateWarning, 85.0)
}

func TestHandleStateChange_NormalRecovery(t *testing.T) {
	ev := &mockEvictor{}
	m := NewMonitor(Config{LimitBytes: 1024}, ev)

	// Transition from Warning to Normal
	m.handleStateChange(StateWarning, StateNormal, 50.0)
	// No evictor calls expected
	if len(ev.evictCalls) != 0 || ev.clearCalls != 0 {
		t.Error("expected no evictor calls on Normal recovery")
	}
}

func TestHandleStateChange_NormalToNormal(t *testing.T) {
	ev := &mockEvictor{}
	m := NewMonitor(Config{LimitBytes: 1024}, ev)

	// Normal to Normal — no log, no action
	m.handleStateChange(StateNormal, StateNormal, 50.0)
}

func TestHandleStateChange_CriticalNilEvictor(t *testing.T) {
	m := NewMonitor(Config{LimitBytes: 1024}, nil)

	// Should not panic with nil evictor
	m.handleStateChange(StateNormal, StateCritical, 99.0)
}

func TestHandleStateChange_WarningNilEvictor(t *testing.T) {
	m := NewMonitor(Config{LimitBytes: 1024}, nil)

	// Should not panic with nil evictor
	m.handleStateChange(StateNormal, StateWarning, 85.0)
}
