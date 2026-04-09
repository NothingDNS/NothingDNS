package config

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/nothingdns/nothingdns/internal/util"
)

// ReloadHandler manages configuration hot-reload via SIGHUP
type ReloadHandler struct {
	mu        sync.RWMutex
	callbacks map[string]ReloadCallback
	reloadSig chan os.Signal
	enabled   atomic.Bool
	wg        sync.WaitGroup
}

// ReloadCallback is called on configuration reload
type ReloadCallback func() error

// ReloadPriority determines callback execution order
type ReloadPriority int

const (
	PriorityFirst   ReloadPriority = 0
	PriorityHigh    ReloadPriority = 10
	PriorityNormal  ReloadPriority = 50
	PriorityLow     ReloadPriority = 100
	PriorityLast    ReloadPriority = 1000
)

// ReloadError records an error during reload
type ReloadError struct {
	Component string
	Error     error
}

// Unwrap returns the underlying error for errors.Is/errors.As support.
func (e *ReloadError) Unwrap() error {
	return e.Error
}

// NewReloadHandler creates a new reload handler
func NewReloadHandler() *ReloadHandler {
	h := &ReloadHandler{
		callbacks: make(map[string]ReloadCallback),
		reloadSig: make(chan os.Signal, 1),
	}
	h.enabled.Store(true)
	return h
}

// Register registers a reload callback for a component
func (h *ReloadHandler) Register(component string, cb ReloadCallback) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.callbacks[component] = cb
}

// Unregister removes a reload callback
func (h *ReloadHandler) Unregister(component string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.callbacks, component)
}

// Start starts listening for reload signals
func (h *ReloadHandler) Start() {
	signal.Notify(h.reloadSig, syscall.SIGHUP)

	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				util.Errorf("panic in reload handler: %v", r)
			}
		}()
		for range h.reloadSig {
			if !h.enabled.Load() {
				continue
			}
			h.Reload()
		}
	}()
}

// Stop stops listening for reload signals
func (h *ReloadHandler) Stop() {
	h.enabled.Store(false)
	signal.Stop(h.reloadSig)
	close(h.reloadSig)
	h.wg.Wait()
}

// Reload triggers a manual reload
func (h *ReloadHandler) Reload() []ReloadError {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var errors []ReloadError

	// Execute callbacks in priority order
	// For simplicity, we execute in map order
	// A more sophisticated implementation would sort by priority
	for component, cb := range h.callbacks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					errors = append(errors, ReloadError{
						Component: component,
						Error:     fmt.Errorf("panic in %s reload callback: %v", component, r),
					})
				}
			}()
			if err := cb(); err != nil {
				errors = append(errors, ReloadError{
					Component: component,
					Error:     err,
				})
			}
		}()
	}

	return errors
}

// Component returns registered components
func (h *ReloadHandler) Components() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	components := make([]string, 0, len(h.callbacks))
	for c := range h.callbacks {
		components = append(components, c)
	}
	return components
}

// ReloadManager provides typed reload methods
type ReloadManager struct {
	handler    *ReloadHandler
	configPath string
	config     atomic.Pointer[Config]
	zoneManager  ZoneReloader
	blocklist    BlocklistReloader
	logger       Logger
}

// ZoneReloader interface for zone hot reload
type ZoneReloader interface {
	Reload() error
	LoadZone(name string) error
}

// BlocklistReloader interface for blocklist hot reload
type BlocklistReloader interface {
	Reload() error
}

// Logger interface for logging
type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// NewReloadManager creates a reload manager
func NewReloadManager(handler *ReloadHandler, configPath string, cfg *Config) *ReloadManager {
	m := &ReloadManager{
		handler:    handler,
		configPath: configPath,
	}
	m.config.Store(cfg)
	return m
}

// SetZoneManager sets the zone manager
func (m *ReloadManager) SetZoneManager(zm ZoneReloader) {
	m.zoneManager = zm
}

// SetBlocklist sets the blocklist
func (m *ReloadManager) SetBlocklist(bl BlocklistReloader) {
	m.blocklist = bl
}

// SetLogger sets the logger
func (m *ReloadManager) SetLogger(log Logger) {
	m.logger = log
}

// SetupAll registers all standard reload callbacks
func (m *ReloadManager) SetupAll() {
	m.handler.Register("config", m.reloadConfig)
	m.handler.Register("zones", m.reloadZones)
	m.handler.Register("blocklist", m.reloadBlocklist)
	m.handler.Register("logging", m.reloadLogging)
}

func (m *ReloadManager) reloadConfig() error {
	if m.configPath == "" {
		return nil
	}

	// Read config file
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("Failed to read config file", "error", err)
		}
		return err
	}

	// Parse configuration
	newCfg, err := UnmarshalYAML(string(data))
	if err != nil {
		if m.logger != nil {
			m.logger.Error("Failed to parse config", "error", err)
		}
		return err
	}

	// Validate
	if errors := newCfg.Validate(); len(errors) > 0 {
		if m.logger != nil {
			m.logger.Error("Config validation failed", "errors", errors)
		}
		return fmt.Errorf("config validation failed")
	}

	// Update config atomically
	m.config.Store(newCfg)

	if m.logger != nil {
		m.logger.Info("Configuration reloaded")
	}

	return nil
}

func (m *ReloadManager) reloadZones() error {
	if m.zoneManager == nil {
		return nil
	}

	if err := m.zoneManager.Reload(); err != nil {
		if m.logger != nil {
			m.logger.Error("Failed to reload zones", "error", err)
		}
		return err
	}

	if m.logger != nil {
		m.logger.Info("Zones reloaded")
	}

	return nil
}

func (m *ReloadManager) reloadBlocklist() error {
	if m.blocklist == nil {
		return nil
	}

	if err := m.blocklist.Reload(); err != nil {
		if m.logger != nil {
			m.logger.Error("Failed to reload blocklist", "error", err)
		}
		return err
	}

	if m.logger != nil {
		m.logger.Info("Blocklist reloaded")
	}

	return nil
}

func (m *ReloadManager) reloadLogging() error {
	if m.logger != nil {
		m.logger.Info("Logging configuration reloaded")
	}
	return nil
}

// TLSReloader handles TLS certificate hot reload
type TLSReloader struct {
	certFile string
	keyFile  string
	logger   Logger
}

// NewTLSReloader creates a TLS reloader
func NewTLSReloader(certFile, keyFile string, logger Logger) *TLSReloader {
	return &TLSReloader{
		certFile: certFile,
		keyFile:  keyFile,
		logger:   logger,
	}
}

// Reload reloads TLS certificates
func (r *TLSReloader) Reload() error {
	// Verify files exist and are readable
	if r.certFile != "" {
		if _, err := os.Stat(r.certFile); err != nil {
			return err
		}
	}
	if r.keyFile != "" {
		if _, err := os.Stat(r.keyFile); err != nil {
			return err
		}
	}

	if r.logger != nil {
		r.logger.Info("TLS certificates will be reloaded on next connection")
	}

	return nil
}

// LogLevelReloader handles log level hot reload
type LogLevelReloader struct {
	mu           sync.RWMutex
	currentLevel string
	callback     func(level string) error
	logger       Logger
}

// NewLogLevelReloader creates a log level reloader
func NewLogLevelReloader(initialLevel string, cb func(level string) error, logger Logger) *LogLevelReloader {
	return &LogLevelReloader{
		currentLevel: initialLevel,
		callback:     cb,
		logger:       logger,
	}
}

// SetLevel sets the log level
func (r *LogLevelReloader) SetLevel(level string) error {
	if r.callback != nil {
		if err := r.callback(level); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.currentLevel = level
	r.mu.Unlock()
	if r.logger != nil {
		r.logger.Info("Log level changed", "level", level)
	}
	return nil
}

// GetLevel returns the current log level
func (r *LogLevelReloader) GetLevel() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentLevel
}

// Reload reloads the log level from config
func (r *LogLevelReloader) Reload(newLevel string) error {
	return r.SetLevel(newLevel)
}

// ACLReloader handles ACL hot reload
type ACLReloader struct {
	callback func() error
	logger   Logger
}

// NewACLReloader creates an ACL reloader
func NewACLReloader(cb func() error, logger Logger) *ACLReloader {
	return &ACLReloader{
		callback: cb,
		logger:   logger,
	}
}

// Reload reloads ACL rules
func (r *ACLReloader) Reload() error {
	if r.callback == nil {
		return nil
	}

	if err := r.callback(); err != nil {
		if r.logger != nil {
			r.logger.Error("Failed to reload ACL", "error", err)
		}
		return err
	}

	if r.logger != nil {
		r.logger.Info("ACL rules reloaded")
	}

	return nil
}

// RateLimitReloader handles rate limit hot reload
type RateLimitReloader struct {
	callback func() error
	logger   Logger
}

// NewRateLimitReloader creates a rate limit reloader
func NewRateLimitReloader(cb func() error, logger Logger) *RateLimitReloader {
	return &RateLimitReloader{
		callback: cb,
		logger:   logger,
	}
}

// Reload reloads rate limit configuration
func (r *RateLimitReloader) Reload() error {
	if r.callback == nil {
		return nil
	}

	if err := r.callback(); err != nil {
		if r.logger != nil {
			r.logger.Error("Failed to reload rate limits", "error", err)
		}
		return err
	}

	if r.logger != nil {
		r.logger.Info("Rate limits reloaded")
	}

	return nil
}
