package upstream

// Round-16 regression test for the pooled-connection liveness check in
// tcpConnPool.get().
//
// Before the fix, get()'s so-called liveness check was:
//
//	// Check if connection is still alive with a zero-read deadline
//	c.conn.SetReadDeadline(time.Now())
//	c.conn.SetReadDeadline(time.Time{})
//
// SetReadDeadline only ARMS a deadline; it performs no I/O, so it could never
// observe a peer that had closed the connection. An upstream that closed an
// idle pooled connection therefore had that same dead connection handed
// straight back out; the query on it failed, and queryTCPBuf's deferred
// markFailure() then recorded a failure against a perfectly healthy upstream.
// Enough consecutive stale connections flip Server.IsHealthy() false and pull
// a working upstream out of rotation.
//
// The fix probes with a non-blocking MSG_PEEK|MSG_DONTWAIT recv(2) in
// tcppool_liveness_unix.go. This test drives the real production get()
// against a real TCP listener, so the pre-fix failure was a genuine
// production-path defect rather than a harness artifact.

import (
	"net"
	"testing"
	"time"
)

// newLivenessTestListener starts a TCP listener that accepts connections and
// hands each to the returned channel.
func newLivenessTestListener(t *testing.T) (net.Listener, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	return ln, accepted
}

// waitForPeerClose blocks until a read on conn shows the peer has closed it,
// confirming the FIN is visible to this end. Bounded so it cannot hang.
//
// The deadline must be in the FUTURE: Go checks an already-expired deadline
// in prepareRead and returns os.ErrDeadlineExceeded without ever polling, so
// an expired deadline cannot observe a pending FIN at all.
func waitForPeerClose(t *testing.T, conn net.Conn) {
	t.Helper()
	overall := time.Now().Add(3 * time.Second)
	for time.Now().Before(overall) {
		if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("set probe deadline: %v", err)
		}
		var b [1]byte
		_, err := conn.Read(b[:])
		if err == nil {
			continue // data raced in; keep probing
		}
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			continue // nothing readable yet; FIN not delivered
		}
		_ = conn.SetReadDeadline(time.Time{})
		return // io.EOF / ECONNRESET: peer close is observable
	}
	_ = conn.SetReadDeadline(time.Time{})
	t.Fatalf("harness setup: peer close never became observable")
}

// TestTCPPoolGet_StalePooledConnNotReused is the CLAIM: once the upstream has
// closed an idle pooled connection, get() must not hand that same connection
// back out.
func TestTCPPoolGet_StalePooledConnNotReused(t *testing.T) {
	ln, accepted := newLivenessTestListener(t)
	defer ln.Close()

	pool := newTCPConnPool(ln.Addr().String(), 2, 4, time.Minute, 2*time.Second)

	first, err := pool.get()
	if err != nil {
		t.Fatalf("first get(): %v", err)
	}
	serverSide := <-accepted
	if err := pool.put(first); err != nil {
		t.Fatalf("put(): %v", err)
	}
	if len(pool.idle) != 1 {
		t.Fatalf("harness setup: idle = %d, want 1", len(pool.idle))
	}

	// The upstream closes the idle connection, as real DNS/TCP servers do.
	serverSide.Close()
	waitForPeerClose(t, first.conn)

	second, err := pool.get()
	if err != nil {
		t.Fatalf("second get(): %v", err)
	}
	defer second.close()

	if second == first {
		t.Fatalf("get() returned the connection the upstream had already closed; " +
			"a dead pooled connection is handed back and the query on it fails, " +
			"marking a healthy upstream unhealthy")
	}
}

// TestTCPPoolGet_LivePooledConnReused is the CONTROL: while the upstream keeps
// the connection open, get() must still reuse it. Without this, a change that
// never reuses connections would trivially satisfy the claim above.
func TestTCPPoolGet_LivePooledConnReused(t *testing.T) {
	ln, accepted := newLivenessTestListener(t)
	defer ln.Close()

	pool := newTCPConnPool(ln.Addr().String(), 2, 4, time.Minute, 2*time.Second)

	first, err := pool.get()
	if err != nil {
		t.Fatalf("first get(): %v", err)
	}
	serverSide := <-accepted
	defer serverSide.Close()
	if err := pool.put(first); err != nil {
		t.Fatalf("put(): %v", err)
	}

	second, err := pool.get()
	if err != nil {
		t.Fatalf("second get(): %v", err)
	}
	defer second.close()

	if second != first {
		t.Fatalf("get() did not reuse a live pooled connection")
	}
}
