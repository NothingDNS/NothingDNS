// Round-034 proof: memoryRecorder drain/OnEnd race.
//
// Contract: Tracer.Export and Tracer.DroppedSpans are the documented drain
// API for the in-memory span recorder (the active SpanProcessor when no OTLP
// endpoint is configured — also the tracing.go:55 documented fallback for
// production configs) and are guarded by Tracer.recMu precisely so they can
// be called concurrently with span completion. OnEnd, however, mutates
// r.spans / r.dropped under memoryRecorder.mu — a lock the Export path never
// took — so concurrent draining and span completion were unsynchronized on
// the shared slice and counter (go test -race flagged recorder.go:109).
//
// FIX: drain() and takeDropped() take r.mu themselves; lock order is
// consistently recMu → r.mu, and OnEnd takes only r.mu.
//
// PROOF: concurrent writers (EndSpan → OnEnd) + concurrent drainers
// (Export/DroppedSpans) must be race-free under -race.
// CONTROL: sequential end-then-export on one goroutine keeps working.
package otel

import (
	"context"
	"sync"
	"testing"
)

// ProofRound034RecorderDrainRace: concurrent OnEnd vs Export/DroppedSpans.
// Pre-fix, `go test -race` reported DATA RACE at recorder.go:109
// (r.spans append in OnEnd) against Tracer.Export's unlocked read/nil.
func TestProofRound034RecorderDrainRace(t *testing.T) {
	tr := NewTracer(Config{Enabled: true, SampleRate: 1.0})
	defer tr.Shutdown(context.Background())

	const writers = 4
	const spansPerWriter = 300

	stop := make(chan struct{})
	var drainWG sync.WaitGroup
	for d := 0; d < 2; d++ {
		drainWG.Add(1)
		go func() {
			defer drainWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = tr.Export()
					_ = tr.DroppedSpans()
				}
			}
		}()
	}

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < spansPerWriter; i++ {
				_, span := tr.StartSpan(context.Background(), "round034")
				tr.EndSpan(span, nil)
			}
		}()
	}
	wg.Wait()
	close(stop)
	drainWG.Wait()
}

// Control: sequential end-then-export must keep working (harness sanity —
// this is the behavior tracing_test.go already pins via counts).
func TestProofRound034SequentialDrainControl(t *testing.T) {
	tr := NewTracer(Config{Enabled: true, SampleRate: 1.0})
	defer tr.Shutdown(context.Background())

	_, span := tr.StartSpan(context.Background(), "control")
	tr.EndSpan(span, nil)
	spans := tr.Export()
	if len(spans) != 1 {
		t.Fatalf("CONTROL FAILED: Export() = %d spans, want 1", len(spans))
	}
}
