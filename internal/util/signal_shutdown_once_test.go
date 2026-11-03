package util

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestSignalHandlerPerformShutdownRunsCallbacksOnce(t *testing.T) {
	s := NewSignalHandler()

	var calls atomic.Int32
	s.RegisterShutdown(func() error {
		calls.Add(1)
		return nil
	})

	const callers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			<-start
			s.performShutdown()
		}()
	}

	close(start)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("shutdown callback ran %d times, want 1", got)
	}
}
