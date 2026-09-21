package config

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/nothingdns/nothingdns/internal/util"
)

const maxReloadConfigFileSize = 4 << 20

// ReloadHandler manages configuration hot-reload via SIGHUP
type ReloadHandler struct {
	mu        sync.RWMutex
	callbacks map[string]ReloadCallback
	reloadSig chan os.Signal
	enabled   atomic.Bool
	wg        sync.WaitGroup
	stopOnce  sync.Once // guards Stop() against close-of-closed panic
}

// ReloadCallback is called on configuration reload. The newly-loaded
// *Config is passed in so every callback sees the same fresh config —
// previously each callback had to re-fetch config independently, risking
// stale reads if a concurrent reload swapped the atomic between callbacks.
type ReloadCallback func(newCfg *Config) error

// ReloadPriority determines callback execution order
type ReloadPriority int

const (
	PriorityFirst  ReloadPriority = 0
	PriorityHigh   ReloadPriority = 10
	PriorityNormal ReloadPriority = 50
	PriorityLow    ReloadPriority = 100
	PriorityLast   ReloadPriority = 1000
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
func (h *ReloadHandler) Start(configPath string) {
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
			h.reloadFromPath(configPath)
		}
	}()
}

// reloadFromPath loads the config from path, then dispatches it to all
// registered callbacks via Reload. If the config fails to load or validate,
// the reload is aborted and the error is logged — stale callbacks never run.
func (h *ReloadHandler) reloadFromPath(configPath string) {
	if configPath == "" {
		return
	}
	data, err := readReloadConfigFile(configPath)
	if err != nil {
		util.Errorf("reload: failed to read config %s: %v", configPath, err)
		return
	}
	newCfg, err := UnmarshalYAML(string(data))
	if err != nil {
		util.Errorf("reload: failed to parse config: %v", err)
		return
	}
	if errs := newCfg.Validate(); len(errs) > 0 {
		util.Errorf("reload: config validation failed: %v", errs)
		return
	}
	h.Reload(newCfg)
}

func readReloadConfigFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxReloadConfigFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxReloadConfigFileSize {
		return nil, fmt.Errorf("config file exceeds %d bytes", maxReloadConfigFileSize)
	}
	return data, nil
}

// Stop stops listening for reload signals. Idempotent — a second
// call returns without re-closing h.reloadSig (which would panic
// with "close of closed channel"). Daemon shutdown paths sometimes
// call Stop twice (an explicit teardown plus a deferred safety
// net in test setup); without the sync.Once guard the second
// close took the process down.
func (h *ReloadHandler) Stop() {
	closed := false
	h.stopOnce.Do(func() {
		h.enabled.Store(false)
		signal.Stop(h.reloadSig)
		close(h.reloadSig)
		closed = true
	})
	if !closed {
		return
	}
	h.wg.Wait()
}

// Reload triggers a manual reload. The newCfg is passed to every callback
// so they all see the same freshly-loaded config snapshot.
//
// Callbacks are executed in priority order (lowest ReloadPriority value
// first), with ties broken by component name for determinism. The
// "config" callback is registered at PriorityFirst so that every other
// callback (zones, blocklist, logging) reads the freshly-stored config
// snapshot. Without this ordering, Go's non-deterministic map iteration
// could let zones/blocklist reload before the new config is stored,
// causing them to operate with stale data.
func (h *ReloadHandler) Reload(newCfg *Config) []ReloadError {
	h.mu.RLock()
	type entry struct {
		priority ReloadPriority
		name     string
		cb       ReloadCallback
	}
	entries := make([]entry, 0, len(h.callbacks))
	for name, cb := range h.callbacks {
		entries = append(entries, entry{
			priority: PriorityFor(name),
			name:     name,
			cb:       cb,
		})
	}
	h.mu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].priority != entries[j].priority {
			return entries[i].priority < entries[j].priority
		}
		return entries[i].name < entries[j].name
	})

	var errors []ReloadError
	for _, e := range entries {
		func(component string, cb ReloadCallback) {
			defer func() {
				if r := recover(); r != nil {
					errors = append(errors, ReloadError{
						Component: component,
						Error:     fmt.Errorf("panic in %s reload callback: %v", component, r),
					})
				}
			}()
			if err := cb(newCfg); err != nil {
				errors = append(errors, ReloadError{
					Component: component,
					Error:     err,
				})
			}
		}(e.name, e.cb)
	}

	return errors
}

// PriorityFor returns the reload priority for a given component name.
// The "config" component is PriorityFirst because every other callback
// reads the freshly-stored config snapshot. Unknown components default
// to PriorityNormal.
func PriorityFor(name string) ReloadPriority {
	switch name {
	case "config":
		return PriorityFirst
	case "logging":
		return PriorityLast
	default:
		return PriorityNormal
	}
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
	handler     *ReloadHandler
	configPath  string
	config      atomic.Pointer[Config]
	zoneManager ZoneReloader
	blocklist   BlocklistReloader
	logger      Logger
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

func (m *ReloadManager) reloadConfig(newCfg *Config) error {
	// Config was already loaded and validated by ReloadHandler.reloadFromPath.
	// Store it atomically so subsequent reads by the server pick up the new value.
	m.config.Store(newCfg)

	if m.logger != nil {
		m.logger.Info("Configuration reloaded")
	}

	return nil
}

func (m *ReloadManager) reloadZones(_ *Config) error {
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

func (m *ReloadManager) reloadBlocklist(_ *Config) error {
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

func (m *ReloadManager) reloadLogging(newCfg *Config) error {
	_ = newCfg // available for future use (e.g. dynamic log level changes)
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
	if r.certFile == "" && r.keyFile == "" {
		return nil
	}
	if r.certFile == "" || r.keyFile == "" {
		return fmt.Errorf("both certificate and key files are required")
	}
	if _, err := tls.LoadX509KeyPair(r.certFile, r.keyFile); err != nil {
		return err
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
