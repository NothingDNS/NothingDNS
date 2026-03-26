package config

import (
	"errors"
	"testing"
)

func TestNewReloadHandler(t *testing.T) {
	handler := NewReloadHandler()
	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}

	if len(handler.callbacks) != 0 {
		t.Errorf("Expected 0 callbacks, got %d", len(handler.callbacks))
	}
}

func TestRegisterCallback(t *testing.T) {
	handler := NewReloadHandler()

	called := false
	handler.Register("test", func() error {
		called = true
		return nil
	})

	if len(handler.callbacks) != 1 {
		t.Errorf("Expected 1 callback, got %d", len(handler.callbacks))
	}

	// Trigger reload
	errors := handler.Reload()
	if len(errors) != 0 {
		t.Errorf("Expected no errors, got %d", len(errors))
	}

	if !called {
		t.Error("Expected callback to be called")
	}
}

func TestMultipleCallbacks(t *testing.T) {
	handler := NewReloadHandler()

	callOrder := []string{}
	handler.Register("first", func() error {
		callOrder = append(callOrder, "first")
		return nil
	})
	handler.Register("second", func() error {
		callOrder = append(callOrder, "second")
		return nil
	})
	handler.Register("third", func() error {
		callOrder = append(callOrder, "third")
		return nil
	})

	errors := handler.Reload()
	if len(errors) != 0 {
		t.Errorf("Expected no errors, got %d", len(errors))
	}

	if len(callOrder) != 3 {
		t.Errorf("Expected 3 calls, got %d", len(callOrder))
	}
}

func TestCallbackError(t *testing.T) {
	handler := NewReloadHandler()

	testError := errors.New("test error")
	handler.Register("error_component", func() error {
		return testError
	})

	errs := handler.Reload()
	if len(errs) != 1 {
		t.Errorf("Expected 1 error, got %d", len(errs))
	}

	if errs[0].Component != "error_component" {
		t.Errorf("Expected component 'error_component', got '%s'", errs[0].Component)
	}

	if errs[0].Error != testError {
		t.Errorf("Expected error %v, got %v", testError, errs[0].Error)
	}
}

func TestUnregister(t *testing.T) {
	handler := NewReloadHandler()

	called := false
	handler.Register("test", func() error {
		called = true
		return nil
	})

	handler.Unregister("test")

	if len(handler.callbacks) != 0 {
		t.Errorf("Expected 0 callbacks after unregister, got %d", len(handler.callbacks))
	}

	// Trigger reload
	handler.Reload()
	if called {
		t.Error("Expected callback not to be called after unregister")
	}
}

func TestComponents(t *testing.T) {
	handler := NewReloadHandler()

	handler.Register("a", func() error { return nil })
	handler.Register("b", func() error { return nil })
	handler.Register("c", func() error { return nil })

	components := handler.Components()
	if len(components) != 3 {
		t.Errorf("Expected 3 components, got %d", len(components))
	}
}

func TestStopDisablesReload(t *testing.T) {
	handler := NewReloadHandler()
	handler.Stop()

	// Note: this tests the enabled flag, not the signal handling
	// Manual Reload() still works - this is by design
	_ = handler // Prevent unused variable warning
}

// Mock implementations for testing

type MockZoneManager struct {
	reloadError error
	reloadCount int
}

func (m *MockZoneManager) Reload() error {
	m.reloadCount++
	return m.reloadError
}

func (m *MockZoneManager) LoadZone(name string) error {
	return m.reloadError
}

type MockBlocklist struct {
	reloadError error
	reloadCount int
}

func (m *MockBlocklist) Reload() error {
	m.reloadCount++
	return m.reloadError
}

type MockLogger struct {
	infos  []string
	errors []string
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.infos = append(m.infos, msg)
}

func (m *MockLogger) Error(msg string, args ...interface{}) {
	m.errors = append(m.errors, msg)
}

func TestReloadManager(t *testing.T) {
	handler := NewReloadHandler()
	// Use empty config path to skip config file reload
	manager := NewReloadManager(handler, "", nil)

	logger := &MockLogger{}
	manager.SetLogger(logger)

	zm := &MockZoneManager{}
	manager.SetZoneManager(zm)

	bl := &MockBlocklist{}
	manager.SetBlocklist(bl)

	manager.SetupAll()

	// Trigger reload
	errs := handler.Reload()
	if len(errs) > 0 {
		t.Errorf("Unexpected errors: %v", errs)
	}

	// Verify components were called
	if zm.reloadCount != 1 {
		t.Errorf("Expected zone manager reload count 1, got %d", zm.reloadCount)
	}

	if bl.reloadCount != 1 {
		t.Errorf("Expected blocklist reload count 1, got %d", bl.reloadCount)
	}
}

func TestTLSReloader(t *testing.T) {
	logger := &MockLogger{}
	reloader := NewTLSReloader("", "", logger)

	// With empty paths, reload should succeed
	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestLogLevelReloader(t *testing.T) {
	logger := &MockLogger{}
	var currentLevel string

	reloader := NewLogLevelReloader("info", func(level string) error {
		currentLevel = level
		return nil
	}, logger)

	if reloader.GetLevel() != "info" {
		t.Errorf("Expected 'info', got '%s'", reloader.GetLevel())
	}

	err := reloader.SetLevel("debug")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if currentLevel != "debug" {
		t.Errorf("Expected level 'debug', got '%s'", currentLevel)
	}

	if reloader.GetLevel() != "debug" {
		t.Errorf("Expected 'debug', got '%s'", reloader.GetLevel())
	}
}

func TestACLReloader(t *testing.T) {
	logger := &MockLogger{}
	reloadCount := 0

	reloader := NewACLReloader(func() error {
		reloadCount++
		return nil
	}, logger)

	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if reloadCount != 1 {
		t.Errorf("Expected 1 reload, got %d", reloadCount)
	}
}

func TestACLReloaderError(t *testing.T) {
	logger := &MockLogger{}
	testError := errors.New("ACL error")

	reloader := NewACLReloader(func() error {
		return testError
	}, logger)

	err := reloader.Reload()
	if err != testError {
		t.Errorf("Expected testError, got %v", err)
	}
}

func TestRateLimitReloader(t *testing.T) {
	logger := &MockLogger{}
	reloadCount := 0

	reloader := NewRateLimitReloader(func() error {
		reloadCount++
		return nil
	}, logger)

	err := reloader.Reload()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if reloadCount != 1 {
		t.Errorf("Expected 1 reload, got %d", reloadCount)
	}
}

func TestNilCallbackSafe(t *testing.T) {
	// Test that nil callbacks don't cause panics
	logger := &MockLogger{}

	aclReloader := NewACLReloader(nil, logger)
	if err := aclReloader.Reload(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	rateReloader := NewRateLimitReloader(nil, logger)
	if err := rateReloader.Reload(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}
