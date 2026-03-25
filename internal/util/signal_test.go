package util

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestNewSignalHandler(t *testing.T) {
	s := NewSignalHandler()
	if s == nil {
		t.Fatal("NewSignalHandler returned nil")
	}

	if s.ctx == nil {
		t.Error("Context should not be nil")
	}

	if s.sigChan == nil {
		t.Error("sigChan should not be nil")
	}
}

func TestSignalHandlerRegisterShutdown(t *testing.T) {
	s := NewSignalHandler()

	called := false
	s.RegisterShutdown(func() error {
		called = true
		return nil
	})

	if len(s.shutdownFuncs) != 1 {
		t.Errorf("Expected 1 shutdown func, got %d", len(s.shutdownFuncs))
	}

	// Manually trigger shutdown
	s.performShutdown()

	if !called {
		t.Error("Shutdown function was not called")
	}
}

func TestSignalHandlerOnReload(t *testing.T) {
	s := NewSignalHandler()

	called := false
	s.OnReload(func() {
		called = true
	})

	// Manually trigger reload
	s.performReload()

	if !called {
		t.Error("Reload function was not called")
	}
}

func TestSignalHandlerIsShutdown(t *testing.T) {
	s := NewSignalHandler()

	if s.IsShutdown() {
		t.Error("Should not be shutdown initially")
	}

	// Cancel context to simulate shutdown
	s.cancel()

	if !s.IsShutdown() {
		t.Error("Should be shutdown after cancel")
	}
}

func TestSignalHandlerMultipleShutdownFuncs(t *testing.T) {
	s := NewSignalHandler()

	var order []int

	s.RegisterShutdown(func() error {
		order = append(order, 1)
		return nil
	})
	s.RegisterShutdown(func() error {
		order = append(order, 2)
		return nil
	})
	s.RegisterShutdown(func() error {
		order = append(order, 3)
		return nil
	})

	s.performShutdown()

	// Should be called in reverse order (LIFO)
	expected := []int{3, 2, 1}
	if len(order) != len(expected) {
		t.Fatalf("Expected %d calls, got %d", len(expected), len(order))
	}

	for i, v := range order {
		if v != expected[i] {
			t.Errorf("Shutdown order[%d] = %d, expected %d", i, v, expected[i])
		}
	}
}

func TestShutdownNotifier(t *testing.T) {
	n := NewShutdownNotifier()
	if n == nil {
		t.Fatal("NewShutdownNotifier returned nil")
	}

	if n.IsNotified() {
		t.Error("Should not be notified initially")
	}

	n.Notify("test reason")

	if !n.IsNotified() {
		t.Error("Should be notified after Notify()")
	}

	if n.Reason() != "test reason" {
		t.Errorf("Reason() = %q, expected 'test reason'", n.Reason())
	}

	// Multiple Notify calls should be safe
	n.Notify("second call")

	// Reason should be the first one
	if n.Reason() != "test reason" {
		t.Errorf("Reason() after second Notify = %q, expected 'test reason'", n.Reason())
	}
}

func TestShutdownNotifierDone(t *testing.T) {
	n := NewShutdownNotifier()

	select {
	case <-n.Done():
		t.Error("Done channel should not be closed initially")
	default:
		// Good
	}

	n.Notify("done")

	select {
	case <-n.Done():
		// Good
	case <-time.After(100 * time.Millisecond):
		t.Error("Done channel should be closed after Notify()")
	}
}

func TestSignalHandlerContext(t *testing.T) {
	s := NewSignalHandler()

	ctx := s.Context()
	if ctx == nil {
		t.Error("Context() should not return nil")
	}

	select {
	case <-ctx.Done():
		t.Error("Context should not be done initially")
	default:
		// Good
	}

	s.cancel()

	select {
	case <-ctx.Done():
		// Good
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be done after cancel")
	}
}

func TestSignalHandlerGracefulShutdown(t *testing.T) {
	s := NewSignalHandler()

	var called int32
	s.RegisterShutdown(func() error {
		atomic.AddInt32(&called, 1)
		return nil
	})

	// Complete shutdown quickly
	err := s.GracefulShutdown(1 * time.Second)
	if err != nil {
		t.Errorf("GracefulShutdown returned error: %v", err)
	}

	if atomic.LoadInt32(&called) != 1 {
		t.Errorf("Shutdown function called %d times, expected 1", atomic.LoadInt32(&called))
	}
}
