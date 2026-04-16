package upstream

import (
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// circuitBreaker.shouldAllow — all states
// ---------------------------------------------------------------------------

func TestCircuitBreaker_ShouldAllow_Closed(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true when closed")
	}
}

func TestCircuitBreaker_ShouldAllow_HalfOpen(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbHalfOpen,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true when half-open")
	}
}

func TestCircuitBreaker_ShouldAllow_Open_WithinTimeout(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
		lastFailure:  time.Now(), // recent failure
	}
	if cb.shouldAllow() {
		t.Error("expected shouldAllow=false when open and within timeout")
	}
}

func TestCircuitBreaker_ShouldAllow_Open_AfterTimeout(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failureLimit: 3,
		resetTimeout: 50 * time.Millisecond,
		lastFailure:  time.Now().Add(-100 * time.Millisecond), // expired
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true after reset timeout expired")
	}

	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()

	if state != cbHalfOpen {
		t.Error("expected state to transition to half-open after timeout")
	}
}

func TestCircuitBreaker_ShouldAllow_UnknownState(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbState(99), // unknown state
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true for unknown state (default)")
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.recordSuccess
// ---------------------------------------------------------------------------

func TestCircuitBreaker_RecordSuccess(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failures:     5,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordSuccess()

	cb.mu.Lock()
	failures := cb.failures
	state := cb.state
	cb.mu.Unlock()

	if failures != 0 {
		t.Errorf("expected failures=0 after recordSuccess, got %d", failures)
	}
	if state != cbClosed {
		t.Errorf("expected state=cbClosed after recordSuccess, got %d", state)
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.recordFailure transitions
// ---------------------------------------------------------------------------

func TestCircuitBreaker_RecordFailure_BelowLimit(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failures:     0,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordFailure()

	cb.mu.Lock()
	failures := cb.failures
	state := cb.state
	cb.mu.Unlock()

	if failures != 1 {
		t.Errorf("expected failures=1, got %d", failures)
	}
	if state != cbClosed {
		t.Errorf("expected state=cbClosed (below limit), got %d", state)
	}
}

func TestCircuitBreaker_RecordFailure_TripsOpen(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failures:     2,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordFailure()

	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()

	if state != cbOpen {
		t.Error("expected circuit breaker to be open after reaching failure limit")
	}
}

// ---------------------------------------------------------------------------
// tcpPool.put — overflow connection
// ---------------------------------------------------------------------------

func TestTCPPool_Put_OverflowConnection(t *testing.T) {
	// Create a pool
	pool := &tcpConnPool{
		maxIdle: 2,
		maxTotal: 5,
	}

	// Create a connection that belongs to a different pool
	otherPool := &tcpConnPool{}
	conn := &tcpConn{
		pool:  otherPool,
		conn:  &net.TCPConn{},
	}

	// put should close the overflow connection
	pool.put(conn)
	// Should not panic and should not add to idle
	if len(pool.idle) != 0 {
		t.Errorf("expected 0 idle conns, got %d", len(pool.idle))
	}
}

func TestTCPPool_Put_PoolClosed(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:   2,
		maxTotal: 5,
		closed:    true,
		active:    1,
	}

	conn := &tcpConn{
		pool:  pool,
		conn:  &net.TCPConn{},
	}
	conn.inUse.Store(true)

	pool.put(conn)

	if pool.active != 0 {
		t.Errorf("expected active=0 after put to closed pool, got %d", pool.active)
	}
}

func TestTCPPool_Put_TooManyIdle(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:   1,
		maxTotal: 5,
		idle:      make([]*tcpConn, 1),
		active:    2,
	}
	pool.idle[0] = &tcpConn{pool: pool}

	conn := &tcpConn{
		pool:  pool,
		conn:  &net.TCPConn{},
	}
	conn.inUse.Store(true)

	pool.put(conn)

	// Should close the connection because idle is full
	if len(pool.idle) != 1 {
		t.Errorf("expected 1 idle conn (max), got %d", len(pool.idle))
	}
	if pool.active != 1 {
		t.Errorf("expected active=1 after closing excess, got %d", pool.active)
	}
}

func TestTCPPool_Put_Success(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:   5,
		maxTotal: 10,
		idle:      []*tcpConn{},
		active:    1,
	}

	conn := &tcpConn{
		pool:  pool,
		conn:  &net.TCPConn{},
	}
	conn.inUse.Store(true)

	pool.put(conn)

	if len(pool.idle) != 1 {
		t.Errorf("expected 1 idle conn, got %d", len(pool.idle))
	}
	if conn.inUse.Load() {
		t.Error("expected inUse=false after put")
	}
}
