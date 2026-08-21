package upstream

import (
	"errors"
	"net"
	"testing"
	"time"
)

// ============================================================================
// tcpConnPool.get — branch coverage
//
// get() is the upstream hot path for TCP reuse. Branches: closed pool,
// idle reuse (valid, idle-timeout evict, deadline-probe errors on both
// the probe and the reset), overflow direct dial when maxTotal is
// reached, fresh dial, and dial failure decrementing active. Complements
// the existing put/closeAll tests in coverage_test.go.
// ============================================================================

// deadlineErrConn makes SetReadDeadline fail on selected calls so the two
// deadline-error branches of get()'s idle loop are reachable:
//   - failOnCall 1 → the time.Now() probe fails (first branch)
//   - failOnCall 2 → the time.Time{} reset fails (second branch; probe ok)
type deadlineErrConn struct {
	net.Conn
	calls       int
	failOnCall  int
	failWith    error
	gotDeadline []time.Time
}

func (c *deadlineErrConn) SetReadDeadline(t time.Time) error {
	c.calls++
	c.gotDeadline = append(c.gotDeadline, t)
	if c.calls == c.failOnCall {
		return c.failWith
	}
	return nil
}

// errCloseConn reports the underlying Close error so closeConnLocked
// failures can be asserted.
type errCloseConn struct {
	net.Conn
	closeErr error
}

func (c *errCloseConn) Close() error {
	_ = c.Conn.Close()
	return c.closeErr
}

func TestTCPPoolGet_ClosedPool(t *testing.T) {
	pool := &tcpConnPool{closed: true}
	if _, err := pool.get(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("get() on closed pool = %v, want net.ErrClosed", err)
	}
}

func TestTCPPoolGet_IdleReuseValid(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	pool := &tcpConnPool{maxIdle: 2, maxTotal: 4, idleTimeout: time.Minute}
	idle := &tcpConn{pool: pool, conn: clientConn, lastUsedAt: time.Now()}
	pool.idle = append(pool.idle, idle)

	got, err := pool.get()
	if err != nil {
		t.Fatalf("get(): %v", err)
	}
	if got != idle {
		t.Fatalf("get() returned a different conn than the idle one")
	}
	if !got.inUse.Load() {
		t.Error("reused conn not marked inUse")
	}
	if len(pool.idle) != 0 {
		t.Errorf("idle list = %d, want 0", len(pool.idle))
	}
}

func TestTCPPoolGet_IdleTimeoutEvicted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	pool := newTCPConnPool(ln.Addr().String(), 2, 4, time.Millisecond, 2*time.Second)
	// lastUsedAt far in the past: the idle conn must be evicted (not
	// reused), and get() falls through to a fresh dial to the listener.
	stale := &tcpConn{pool: pool, conn: clientConn, lastUsedAt: time.Now().Add(-time.Hour)}
	pool.idle = append(pool.idle, stale)
	pool.active = 1

	got, err := pool.get()
	if err != nil {
		t.Fatalf("get(): %v", err)
	}
	defer got.close()
	if got == stale {
		t.Fatal("stale idle conn was reused instead of evicted")
	}
	if len(pool.idle) != 0 {
		t.Errorf("idle list = %d after eviction, want 0", len(pool.idle))
	}
}

func TestTCPPoolGet_IdleProbeDeadlineError(t *testing.T) {
	probeErr := errors.New("probe deadline failed")
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	pool := &tcpConnPool{maxIdle: 2, maxTotal: 4, idleTimeout: time.Minute}
	conn := &deadlineErrConn{Conn: clientConn, failOnCall: 1, failWith: probeErr}
	pool.idle = append(pool.idle, &tcpConn{pool: pool, conn: conn, lastUsedAt: time.Now()})

	got, err := pool.get()
	if !errors.Is(err, probeErr) {
		t.Fatalf("get() = (%v, %v), want probe error", got, err)
	}
	if len(pool.idle) != 0 {
		t.Errorf("broken idle conn not removed: %d left", len(pool.idle))
	}
}

func TestTCPPoolGet_IdleResetDeadlineError(t *testing.T) {
	resetErr := errors.New("reset deadline failed")
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	pool := &tcpConnPool{maxIdle: 2, maxTotal: 4, idleTimeout: time.Minute}
	// Probe (call 1) succeeds, reset (call 2) fails.
	conn := &deadlineErrConn{Conn: clientConn, failOnCall: 2, failWith: resetErr}
	pool.idle = append(pool.idle, &tcpConn{pool: pool, conn: conn, lastUsedAt: time.Now()})

	got, err := pool.get()
	if !errors.Is(err, resetErr) {
		t.Fatalf("get() = (%v, %v), want reset error", got, err)
	}
	if len(pool.idle) != 0 {
		t.Errorf("broken idle conn not removed: %d left", len(pool.idle))
	}
}

func TestTCPPoolGet_FreshDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	pool := newTCPConnPool(ln.Addr().String(), 2, 4, time.Minute, 2*time.Second)

	got, err := pool.get()
	if err != nil {
		t.Fatalf("get(): %v", err)
	}
	defer got.close()
	if got.pool != pool {
		t.Error("fresh conn not attached to pool")
	}
	if pool.active != 1 {
		t.Errorf("active = %d, want 1", pool.active)
	}
}

func TestTCPPoolGet_DialFailureRollsBackActive(t *testing.T) {
	// Port with nothing listening: dial fails fast with ECONNREFUSED.
	pool := newTCPConnPool("127.0.0.1:1", 2, 4, time.Minute, 2*time.Second)

	got, err := pool.get()
	if err == nil {
		got.close()
		t.Fatal("expected dial error to closed port")
	}
	if pool.active != 0 {
		t.Errorf("active = %d after dial failure, want 0", pool.active)
	}
}

func TestTCPPoolGet_OverflowDirectDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Pool at capacity: get() must still succeed via an unpooled direct
	// connection (pool field nil) rather than blocking or failing.
	pool := newTCPConnPool(ln.Addr().String(), 2, 1, time.Minute, 2*time.Second)
	pool.active = 1 // at maxTotal

	got, err := pool.get()
	if err != nil {
		t.Fatalf("get(): %v", err)
	}
	defer got.close()
	if got.pool != nil {
		t.Error("overflow conn must not reference the pool")
	}
	if pool.active != 1 {
		t.Errorf("active = %d, overflow must not change it", pool.active)
	}
}

func TestNewTCPConnPoolDefaults(t *testing.T) {
	// Zero/negative inputs fall back to documented defaults.
	pool := newTCPConnPool("127.0.0.1:53", 0, -1, 0, 0)
	if pool.maxIdle != 4 {
		t.Errorf("maxIdle = %d, want default 4", pool.maxIdle)
	}
	if pool.maxTotal != 64 {
		t.Errorf("maxTotal = %d, want default 64", pool.maxTotal)
	}
	if pool.idleTimeout != 30*time.Second {
		t.Errorf("idleTimeout = %v, want default 30s", pool.idleTimeout)
	}
	if pool.dialTimeout != 0 {
		t.Errorf("dialTimeout = %v, want preserved 0", pool.dialTimeout)
	}

	// Positive inputs pass through untouched.
	pool2 := newTCPConnPool("127.0.0.1:53", 3, 9, 5*time.Second, time.Second)
	if pool2.maxIdle != 3 || pool2.maxTotal != 9 || pool2.idleTimeout != 5*time.Second || pool2.dialTimeout != time.Second {
		t.Errorf("explicit values not preserved: %+v", pool2)
	}
}
