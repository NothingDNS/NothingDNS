package util

// Regression test for the 2026-10-19 proof-driven round 055: *Logger methods
// dereferenced a nil receiver (log()'s l.mu.RLock), so the first log line of
// a query panicked the request pipeline whenever a handler was wired without
// a logger — the zero-value integratedHandler the transport coverage tests
// boot, and the shape behind the observed "doq handler panic: nil pointer
// dereference". A nil Logger is now a discard logger.

import "testing"

func TestNilLoggerDiscards(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FAIL: nil *Logger panicked: %v", r)
		}
	}()

	var l *Logger
	l.Debug("d")
	l.Debugf("d %d", 1)
	l.Info("i")
	l.Infof("i %d", 1)
	l.Warn("w")
	l.Warnf("w %d", 1)
	l.Error("e")
	l.Errorf("e %d", 1)

	// WithFields on a nil logger stays nil so chained calls keep discarding.
	if got := l.WithFields(Fields{"k": "v"}); got != nil {
		t.Fatalf("FAIL: WithFields on a nil Logger returned %T, want nil", got)
	}
}
