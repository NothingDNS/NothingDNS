// Package memory provides runtime memory monitoring and OOM protection.
package memory

import (
	"context"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// State represents the current memory pressure level.
type State int

const (
	// StateNormal means memory usage is within normal bounds.
	StateNormal State = iota
	// StateWarning means memory usage is approaching the limit.
	StateWarning
	// StateCritical means memory usage is near the limit.
	StateCritical
)

func (s State) String() string {
	switch s {
	case StateNormal:
		return "normal"
	case StateWarning:
		return "warning"
	case StateCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Stats holds current memory statistics.
type Stats struct {
	// Alloc is bytes of allocated heap objects.
	Alloc uint64
	// Sys is total bytes of memory obtained from the OS.
	Sys uint64
	// HeapAlloc is bytes of allocated heap objects.
	HeapAlloc uint64
	// HeapSys is bytes of heap memory obtained from the OS.
	HeapSys uint64
	// StackInuse is bytes in stack spans.
	StackInuse uint64
	// NumGC is number of completed GC cycles.
	NumGC uint32
	// NumGoroutine is the current number of goroutines.
	NumGoroutine int
	// Limit is the configured memory limit in bytes (0 = unlimited).
	Limit uint64
	// State is the current memory pressure state.
	State State
}

// Evictor is called when memory pressure is detected to free memory.
type Evictor interface {
	Evict(percent int) // Evict approximately percent% of cached data
	Clear()            // Clear all cached data
}

// Config holds memory monitor configuration.
type Config struct {
	// LimitBytes is the maximum memory in bytes the process should use.
	// 0 means no limit (monitoring only).
	LimitBytes uint64

	// WarningPct is the percentage of limit that triggers warning state (default 80).
	WarningPct float64

	// CriticalPct is the percentage of limit that triggers critical state (default 95).
	CriticalPct float64

	// CheckInterval is how often to check memory usage (default 10s).
	CheckInterval time.Duration

	// GCOnWarning triggers a GC cycle when entering warning state.
	GCOnWarning bool
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		WarningPct:    80.0,
		CriticalPct:   95.0,
		CheckInterval: 10 * time.Second,
		GCOnWarning:   false,
	}
}

// Monitor watches memory usage and triggers evictions when needed.
type Monitor struct {
	config  Config
	evictor Evictor

	mu    sync.RWMutex
	state State
	stats Stats

	enabled atomic.Bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// NewMonitor creates a new memory monitor.
func NewMonitor(config Config, evictor Evictor) *Monitor {
	return &Monitor{
		config:  config,
		evictor: evictor,
		state:   StateNormal,
	}
}

// Start begins monitoring memory usage.
func (m *Monitor) Start() {
	if m.config.LimitBytes == 0 {
		return // No limit configured
	}
	m.enabled.Store(true)

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.wg.Add(1)
	go m.run(ctx)
}

// Stop stops the memory monitor.
func (m *Monitor) Stop() {
	if m.cancel != nil {
		m.cancel()
		m.wg.Wait()
	}
}

// State returns the current memory pressure state.
func (m *Monitor) State() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// GetStats returns current memory statistics.
func (m *Monitor) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// IsOverLimit returns true if memory usage is above the configured limit.
func (m *Monitor) IsOverLimit() bool {
	if m.config.LimitBytes == 0 {
		return false
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.Sys > m.config.LimitBytes
}

// run is the main monitoring loop.
func (m *Monitor) run(ctx context.Context) {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	// Do an initial check
	m.check()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check()
		}
	}
}

// check reads memory stats and takes action if needed.
func (m *Monitor) check() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	stats := Stats{
		Alloc:        ms.Alloc,
		Sys:          ms.Sys,
		HeapAlloc:    ms.HeapAlloc,
		HeapSys:      ms.HeapSys,
		StackInuse:   ms.StackInuse,
		NumGC:        ms.NumGC,
		NumGoroutine: runtime.NumGoroutine(),
		Limit:        m.config.LimitBytes,
	}

	// Determine state based on Sys (total memory from OS)
	var newState State
	usagePct := float64(ms.Sys) / float64(m.config.LimitBytes) * 100

	switch {
	case usagePct >= m.config.CriticalPct:
		newState = StateCritical
	case usagePct >= m.config.WarningPct:
		newState = StateWarning
	default:
		newState = StateNormal
	}

	stats.State = newState

	m.mu.Lock()
	oldState := m.state
	m.state = newState
	m.stats = stats
	m.mu.Unlock()

	// Take action on state transitions
	if newState != oldState {
		m.handleStateChange(oldState, newState, usagePct)
	}
}

func (m *Monitor) handleStateChange(oldState, newState State, usagePct float64) {
	switch newState {
	case StateCritical:
		log.Printf("memory: CRITICAL - usage %.1f%% of limit (%d/%d bytes), clearing caches",
			usagePct, m.stats.Sys, m.config.LimitBytes)
		if m.evictor != nil {
			m.evictor.Clear()
		}
		runtime.GC()

	case StateWarning:
		log.Printf("memory: WARNING - usage %.1f%% of limit (%d/%d bytes), evicting 50%% of cache",
			usagePct, m.stats.Sys, m.config.LimitBytes)
		if m.evictor != nil {
			m.evictor.Evict(50)
		}
		if m.config.GCOnWarning {
			runtime.GC()
		}

	case StateNormal:
		if oldState != StateNormal {
			log.Printf("memory: returned to normal - usage %.1f%%", usagePct)
		}
	}
}
