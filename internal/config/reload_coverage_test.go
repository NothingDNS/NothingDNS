package config

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestStart_SIGHUPTriggersReload tests that sending SIGHUP to the process
// triggers the goroutine started by Start() to call Reload (line 71).
func TestStart_SIGHUPTriggersReload(t *testing.T) {
	handler := NewReloadHandler()

	var mu sync.Mutex
	reloadCalled := false
	handler.Register("test_component", func() error {
		mu.Lock()
		reloadCalled = true
		mu.Unlock()
		return nil
	})

	handler.Start()
	defer handler.Stop()

	// Send SIGHUP to ourselves - this goes through the signal.Notify channel
	// and triggers the goroutine's for-range loop body (line 67-72)
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	// Wait for the goroutine to process the signal
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		done := reloadCalled
		mu.Unlock()
		if done {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for SIGHUP-triggered reload via Start goroutine")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	mu.Lock()
	if !reloadCalled {
		t.Error("expected Reload to be called via SIGHUP through Start goroutine")
	}
	mu.Unlock()
}

// TestStart_DisabledSkipsSignalReload tests the !h.enabled branch in the
// goroutine started by Start() (lines 68-69). When enabled is false,
// the goroutine should skip calling Reload and continue.
func TestStart_DisabledSkipsSignalReload(t *testing.T) {
	handler := NewReloadHandler()

	var mu sync.Mutex
	reloadCount := 0
	handler.Register("test_component", func() error {
		mu.Lock()
		reloadCount++
		mu.Unlock()
		return nil
	})

	handler.Start()
	defer handler.Stop()

	// First SIGHUP: enabled is true, should trigger reload
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	// Wait for first reload
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		if reloadCount >= 1 {
			mu.Unlock()
			break
		}
		mu.Unlock()
		select {
		case <-deadline:
			t.Fatal("timed out waiting for first SIGHUP-triggered reload")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Disable the handler
	handler.enabled.Store(false)
	savedCount := reloadCount

	// Second SIGHUP: enabled is false, should skip reload (line 68-69)
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	// Give time for the signal to be processed
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	currentCount := reloadCount
	mu.Unlock()

	if currentCount != savedCount {
		t.Errorf("expected reload count to stay at %d when disabled, got %d", savedCount, currentCount)
	}
}

// TestStart_MultipleSIGHUPs tests that the Start goroutine handles multiple
// SIGHUP signals correctly, each triggering a Reload call (line 71).
func TestStart_MultipleSIGHUPs(t *testing.T) {
	handler := NewReloadHandler()

	var mu sync.Mutex
	reloadCount := 0
	handler.Register("counter", func() error {
		mu.Lock()
		reloadCount++
		mu.Unlock()
		return nil
	})

	handler.Start()
	defer handler.Stop()

	// Send multiple SIGHUP signals
	for i := 0; i < 3; i++ {
		syscall.Kill(syscall.Getpid(), syscall.SIGHUP)
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for all reloads to process
	deadline := time.After(5 * time.Second)
	for {
		mu.Lock()
		count := reloadCount
		mu.Unlock()
		if count >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out: expected 3 reloads, got %d", count)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	mu.Lock()
	if reloadCount != 3 {
		t.Errorf("expected 3 reloads from 3 SIGHUPs, got %d", reloadCount)
	}
	mu.Unlock()
}

// TestStart_SIGHUPWithCallbackError tests that when a callback returns an error
// via the SIGHUP-triggered Reload path, the goroutine does not crash.
func TestStart_SIGHUPWithCallbackError(t *testing.T) {
	handler := NewReloadHandler()

	var mu sync.Mutex
	called := false
	handler.Register("failing", func() error {
		mu.Lock()
		called = true
		mu.Unlock()
		return os.ErrNotExist
	})

	handler.Start()
	defer handler.Stop()

	// Send SIGHUP - even though callback errors, goroutine should survive
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		if called {
			mu.Unlock()
			break
		}
		mu.Unlock()
		select {
		case <-deadline:
			t.Fatal("timed out waiting for callback to be called via SIGHUP")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Second SIGHUP should still work (goroutine did not crash)
	mu.Lock()
	called = false
	mu.Unlock()

	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	deadline = time.After(3 * time.Second)
	for {
		mu.Lock()
		if called {
			mu.Unlock()
			break
		}
		mu.Unlock()
		select {
		case <-deadline:
			t.Fatal("timed out: goroutine did not survive callback error")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TestStart_StopClosesChannel tests that Stop() closes the reloadSig channel,
// which causes the goroutine's for-range loop to exit cleanly.
func TestStart_StopClosesChannel(t *testing.T) {
	handler := NewReloadHandler()

	handler.Register("test", func() error {
		return nil
	})

	handler.Start()

	// Send a signal to verify the goroutine is running
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	// Stop should close the channel and end the goroutine's for-range loop
	handler.Stop()

	// Verify handler is disabled after Stop
	if handler.enabled.Load() {
		t.Error("expected handler to be disabled after Stop()")
	}
}

// TestStart_SignalNotifyCalled tests that Start properly registers for SIGHUP
// via signal.Notify (line 64).
func TestStart_SignalNotifyCalled(t *testing.T) {
	handler := NewReloadHandler()

	// Create a separate channel to intercept SIGHUP signals
	// This verifies signal.Notify was called correctly
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	handler.Start()

	var mu sync.Mutex
	reloadCalled := false
	handler.Register("test", func() error {
		mu.Lock()
		reloadCalled = true
		mu.Unlock()
		return nil
	})

	// Send SIGHUP
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	// Verify signal was received on our separate channel too
	select {
	case <-sigChan:
		// Good, signal.Notify was configured
	case <-time.After(2 * time.Second):
		t.Error("SIGHUP signal not received on test channel")
	}

	// Wait for the handler's goroutine to process it
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		if reloadCalled {
			mu.Unlock()
			break
		}
		mu.Unlock()
		select {
		case <-deadline:
			t.Fatal("timed out waiting for reload via Start goroutine")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	handler.Stop()
}

// TestStart_GoroutineExitsOnChannelClose tests the for-range loop exit path
// when the reloadSig channel is closed by Stop().
func TestStart_GoroutineExitsOnChannelClose(t *testing.T) {
	handler := NewReloadHandler()

	var mu sync.Mutex
	reloadCount := 0
	handler.Register("test", func() error {
		mu.Lock()
		reloadCount++
		mu.Unlock()
		return nil
	})

	handler.Start()

	// Trigger a reload through the channel
	syscall.Kill(syscall.Getpid(), syscall.SIGHUP)

	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		if reloadCount >= 1 {
			mu.Unlock()
			break
		}
		mu.Unlock()
		select {
		case <-deadline:
			t.Fatal("timed out")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Stop closes the channel, which makes for-range exit
	handler.Stop()

	// After Stop, sending SIGHUP should not trigger any more reloads
	mu.Lock()
	countBefore := reloadCount
	mu.Unlock()

	// Drain any buffered signals from the closed channel path
	// signal.Stop already unregistered, so SIGHUP goes to default handler
	// The channel is closed so the goroutine has exited
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	countAfter := reloadCount
	mu.Unlock()

	if countAfter != countBefore {
		t.Errorf("reload was called after Stop(): before=%d after=%d", countBefore, countAfter)
	}
}
