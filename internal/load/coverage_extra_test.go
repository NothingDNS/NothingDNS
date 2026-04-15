package load

import (
	"strings"
	"testing"
	"time"
)

func TestPercent(t *testing.T) {
	tests := []struct {
		num, denom int64
		want       float64
	}{
		{50, 100, 50.0},
		{1, 3, 33.33333333333333},
		{0, 100, 0},
		{100, 0, 0},
		{0, 0, 0},
	}
	for _, tt := range tests {
		got := percent(tt.num, tt.denom)
		if got != tt.want {
			t.Errorf("percent(%d, %d) = %f, want %f", tt.num, tt.denom, got, tt.want)
		}
	}
}

func TestResult_String(t *testing.T) {
	r := &Result{
		Queries:       1000,
		Success:       950,
		Errors:        30,
		Timeouts:      20,
		TotalDuration: 5 * time.Second,
		QPS:           190.5,
		LatencyMin:    1 * time.Millisecond,
		LatencyAvg:    3 * time.Millisecond,
		LatencyP50:    2 * time.Millisecond,
		LatencyP95:    8 * time.Millisecond,
		LatencyP99:    15 * time.Millisecond,
		LatencyMax:    20 * time.Millisecond,
	}

	s := r.String()
	if !strings.Contains(s, "1000") {
		t.Error("String should contain total queries")
	}
	if !strings.Contains(s, "950") {
		t.Error("String should contain success count")
	}
	if !strings.Contains(s, "190.50") {
		t.Error("String should contain QPS")
	}
}

func TestResult_StringZeroQueries(t *testing.T) {
	r := &Result{
		Queries:       0,
		Success:       0,
		Errors:        0,
		Timeouts:      0,
		TotalDuration: time.Second,
		QPS:           0,
	}

	s := r.String()
	if !strings.Contains(s, "0") {
		t.Error("String should contain zeroes")
	}
}

func TestComputeResult_NoLatencies(t *testing.T) {
	r := &Runner{
		cfg:       Config{Queries: 10, Workers: 1},
		latencies: []time.Duration{},
	}
	r.success = 5
	r.errors = 3
	r.timeouts = 2

	result := r.computeResult(time.Second)
	if result.Success != 5 {
		t.Errorf("expected 5 successes, got %d", result.Success)
	}
	if result.Errors != 3 {
		t.Errorf("expected 3 errors, got %d", result.Errors)
	}
	if result.Timeouts != 2 {
		t.Errorf("expected 2 timeouts, got %d", result.Timeouts)
	}
	if result.QPS != 0 {
		t.Errorf("expected 0 QPS with no latencies, got %f", result.QPS)
	}
}

func TestComputeResult_WithLatencies(t *testing.T) {
	r := &Runner{
		cfg: Config{Queries: 10, Workers: 1},
		latencies: []time.Duration{
			10 * time.Millisecond,
			20 * time.Millisecond,
			30 * time.Millisecond,
			40 * time.Millisecond,
			50 * time.Millisecond,
		},
	}
	r.success = 5

	result := r.computeResult(1 * time.Second)
	if result.LatencyMin != 10*time.Millisecond {
		t.Errorf("expected min 10ms, got %v", result.LatencyMin)
	}
	if result.LatencyMax != 50*time.Millisecond {
		t.Errorf("expected max 50ms, got %v", result.LatencyMax)
	}
	if result.LatencyAvg != 30*time.Millisecond {
		t.Errorf("expected avg 30ms, got %v", result.LatencyAvg)
	}
	if result.QPS <= 0 {
		t.Errorf("expected positive QPS, got %f", result.QPS)
	}
}

func TestComputeResult_Percentiles(t *testing.T) {
	latencies := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		latencies[i] = time.Duration(i+1) * time.Millisecond
	}

	r := &Runner{
		cfg:       Config{Queries: 100, Workers: 1},
		latencies: latencies,
	}
	r.success = 100

	result := r.computeResult(time.Second)

	// After sorting: 1ms, 2ms, ..., 100ms
	// P50 = latencies[50] = 51ms
	if result.LatencyP50 != 51*time.Millisecond {
		t.Errorf("expected P50=51ms, got %v", result.LatencyP50)
	}
	// P95 = latencies[int(100*0.95)] = latencies[95] = 96ms
	if result.LatencyP95 != 96*time.Millisecond {
		t.Errorf("expected P95=96ms, got %v", result.LatencyP95)
	}
	// P99 = latencies[int(100*0.99)] = latencies[99] = 100ms
	if result.LatencyP99 != 100*time.Millisecond {
		t.Errorf("expected P99=100ms, got %v", result.LatencyP99)
	}
}

func TestNewRunner(t *testing.T) {
	cfg := Config{
		Server:   "127.0.0.1:53",
		Queries:  100,
		Workers:  5,
		Timeout:  2 * time.Second,
		Name:     "example.com.",
		Type:     1,
		Protocol: "udp",
	}
	r := NewRunner(cfg)
	if r == nil {
		t.Fatal("NewRunner returned nil")
	}
	if cap(r.latencies) != 500 {
		t.Errorf("expected latencies cap 500, got %d", cap(r.latencies))
	}
}

