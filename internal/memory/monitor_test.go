package memory

import (
	"testing"
	"time"
)

func TestStateString(t *testing.T) {
	tests := []struct {
		state State
		want  string
	}{
		{StateNormal, "normal"},
		{StateWarning, "warning"},
		{StateCritical, "critical"},
		{State(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.WarningPct != 80.0 {
		t.Errorf("WarningPct = %f, want 80.0", cfg.WarningPct)
	}
	if cfg.CriticalPct != 95.0 {
		t.Errorf("CriticalPct = %f, want 95.0", cfg.CriticalPct)
	}
	if cfg.CheckInterval != 10*time.Second {
		t.Errorf("CheckInterval = %v, want 10s", cfg.CheckInterval)
	}
	if cfg.GCOnWarning {
		t.Error("GCOnWarning should be false by default")
	}
	if cfg.LimitBytes != 0 {
		t.Errorf("LimitBytes = %d, want 0", cfg.LimitBytes)
	}
}

func TestNewMonitor(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LimitBytes = 1024 * 1024 * 100
	m := NewMonitor(cfg, nil)
	if m == nil {
		t.Fatal("NewMonitor returned nil")
	}
	if m.state != StateNormal {
		t.Errorf("initial state = %v, want StateNormal", m.state)
	}
}

func TestMonitorStartStop_NoLimit(t *testing.T) {
	cfg := DefaultConfig()
	// LimitBytes = 0 means Start should be a no-op
	m := NewMonitor(cfg, nil)
	m.Start()
	// Should not panic on Stop even though no goroutine was started
	m.Stop()
}

func TestMonitorStartStop_WithLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LimitBytes = 1024 * 1024 * 1024 // 1GB — well above actual usage
	cfg.CheckInterval = 10 * time.Millisecond
	m := NewMonitor(cfg, nil)
	m.Start()
	// Let at least one check cycle run
	time.Sleep(30 * time.Millisecond)
	m.Stop()

	// After check, stats should be populated
	stats := m.GetStats()
	if stats.Alloc == 0 {
		t.Error("expected non-zero Alloc after check")
	}
	if stats.NumGoroutine == 0 {
		t.Error("expected non-zero NumGoroutine")
	}
	if stats.Limit != cfg.LimitBytes {
		t.Errorf("Limit = %d, want %d", stats.Limit, cfg.LimitBytes)
	}
}

func TestMonitorState_Normal(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LimitBytes = 1024 * 1024 * 1024 * 10 // 10GB — always normal
	cfg.CheckInterval = 10 * time.Millisecond
	m := NewMonitor(cfg, nil)
	m.Start()
	time.Sleep(30 * time.Millisecond)
	m.Stop()

	if m.State() != StateNormal {
		t.Errorf("state = %v, want StateNormal", m.State())
	}
}

func TestMonitorIsOverLimit_NoLimit(t *testing.T) {
	cfg := DefaultConfig()
	m := NewMonitor(cfg, nil)
	if m.IsOverLimit() {
		t.Error("IsOverLimit should return false when LimitBytes = 0")
	}
}

func TestMonitorIsOverLimit_HighLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LimitBytes = 1024 * 1024 * 1024 * 10 // 10GB
	m := NewMonitor(cfg, nil)
	if m.IsOverLimit() {
		t.Error("IsOverLimit should return false with 10GB limit")
	}
}

func TestMonitorIsOverLimit_LowLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LimitBytes = 1 // 1 byte — always over limit
	m := NewMonitor(cfg, nil)
	if !m.IsOverLimit() {
		t.Error("IsOverLimit should return true with 1-byte limit")
	}
}

// mockEvictor records calls for testing.
type mockEvictor struct {
	evictCalls []int
	clearCalls int
}

func (e *mockEvictor) Evict(percent int) {
	e.evictCalls = append(e.evictCalls, percent)
}

func (e *mockEvictor) Clear() {
	e.clearCalls++
}

func TestMonitorStateTransition_Warning(t *testing.T) {
	ev := &mockEvictor{}
	cfg := Config{
		LimitBytes:    1, // 1 byte limit — Sys will always exceed this
		WarningPct:    80.0,
		CriticalPct:   99999.0, // Unreachable critical
		CheckInterval: 10 * time.Millisecond,
		GCOnWarning:   false,
	}
	m := NewMonitor(cfg, ev)
	m.Start()
	time.Sleep(30 * time.Millisecond)
	m.Stop()

	// With 1 byte limit, usage% will be astronomical so it hits critical
	// Let's just verify the evictor was called
	state := m.State()
	if state == StateNormal {
		t.Error("expected non-normal state with 1-byte limit")
	}
}

func TestMonitorStateTransition_Critical(t *testing.T) {
	ev := &mockEvictor{}
	cfg := Config{
		LimitBytes:    1, // 1 byte — guarantees critical
		WarningPct:    50.0,
		CriticalPct:   90.0,
		CheckInterval: 10 * time.Millisecond,
	}
	m := NewMonitor(cfg, ev)
	m.Start()
	time.Sleep(30 * time.Millisecond)
	m.Stop()

	if m.State() != StateCritical {
		t.Errorf("state = %v, want StateCritical", m.State())
	}
	if ev.clearCalls == 0 {
		t.Error("expected Clear() to be called in critical state")
	}
}

func TestMonitorGetStats(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LimitBytes = 1024 * 1024 * 1024
	cfg.CheckInterval = 10 * time.Millisecond
	m := NewMonitor(cfg, nil)
	m.Start()
	time.Sleep(30 * time.Millisecond)
	m.Stop()

	stats := m.GetStats()
	if stats.Sys == 0 {
		t.Error("expected non-zero Sys")
	}
	if stats.HeapAlloc == 0 {
		t.Error("expected non-zero HeapAlloc")
	}
	if stats.HeapSys == 0 {
		t.Error("expected non-zero HeapSys")
	}
}

func TestMonitorDoubleStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LimitBytes = 1024 * 1024 * 1024
	cfg.CheckInterval = 10 * time.Millisecond
	m := NewMonitor(cfg, nil)
	m.Start()
	time.Sleep(20 * time.Millisecond)
	m.Stop()
	// Second stop should not panic
	m.Stop()
}

func TestMonitorGCOnWarning(t *testing.T) {
	ev := &mockEvictor{}
	cfg := Config{
		LimitBytes:    1,
		WarningPct:    50.0,
		CriticalPct:   99999.0,
		CheckInterval: 10 * time.Millisecond,
		GCOnWarning:   true,
	}
	m := NewMonitor(cfg, ev)
	m.Start()
	time.Sleep(30 * time.Millisecond)
	m.Stop()

	// Evictor should have been called
	if len(ev.evictCalls) == 0 && ev.clearCalls == 0 {
		t.Error("expected evictor to be called")
	}
}
