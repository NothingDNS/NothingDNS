package load

import (
	"context"
	"testing"
	"time"
)

func TestRunnerRunResetsPreviousResults(t *testing.T) {
	// Missing port fails locally during address validation, without any network I/O.
	r := NewRunner(Config{Server: "127.0.0.1", Protocol: "tcp", Queries: 2, Workers: 1, Timeout: time.Second, Name: "example.test", Type: 1})
	for i := 0; i < 3; i++ {
		got := r.Run(context.Background())
		if got.Queries != 2 || got.Errors != 2 || got.Success != 0 || got.Timeouts != 0 {
			t.Fatalf("run %d: %+v", i, got)
		}
	}
	// Exercise a new run with no workers after successful and timed-out samples.
	r.success = 1
	r.timeouts = 1
	r.latencies = append(r.latencies, time.Millisecond)
	r.cfg.Workers = 0
	got := r.Run(context.Background())
	if got.Queries != 0 || got.Errors != 0 || got.Success != 0 || got.Timeouts != 0 || got.LatencyMax != 0 || got.QPS != 0 {
		t.Fatalf("empty run reused previous results: %+v", got)
	}
}
