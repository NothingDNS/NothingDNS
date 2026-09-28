// Round-027 proof: the DoT (DNS-over-TLS) server accept loop self-deadlocks
// on the shutdown path because it holds ipConnMu while calling a helper that
// re-acquires the same non-reentrant sync.Mutex.
//
// BUG (internal/server/tls.go, Serve):
//
//	if !connSent {
//	    s.ipConnMu.Lock()          // acquire #1
//	    s.decrementIPConn(ip)      // internally: s.ipConnMu.Lock()  -> acquire #2 (SAME goroutine)
//	    s.ipConnMu.Unlock()        // never reached
//	    ...
//	}
//
// decrementIPConn (tls.go:396) begins with `s.ipConnMu.Lock(); defer Unlock()`.
// sync.Mutex is NOT reentrant, so acquire #2 on a mutex already held by the
// same goroutine blocks forever. The accept-loop goroutine wedges PERMANENTLY
// while still holding ipConnMu.
//
// IMPACT — the deadlock is not confined to one goroutine:
//   - Every DoT worker that finishes a connection calls decrementIPConn
//     (tls.go:389) and blocks on the mutex the deadlocked accept loop holds.
//   - The accept loop never returns from Serve, so connChan is never closed and
//     `s.wg.Wait()` (the graceful-shutdown barrier) is never reached. Stop() does
//     not complete the drain, and the DoT server leaks its worker goroutines.
//
// REACHABILITY: Serve's `select { case connChan <- conn: ... case <-s.ctx.Done(): }`
// takes the ctx.Done() branch whenever Stop() cancels the context while a
// connection is being accepted — an ordinary restart/config-reload/drain. connChan
// has capacity workers*2, so a connection is routinely accepted at the same
// moment the context is cancelled.
//
// SHUTDOWN SEQUENCE (why the order in these tests matters):
// Serve() only leaves its accept loop when Accept() returns an error with a
// cancelled context; Stop() provides both by cancelling the context AND closing
// the listener. It then closes connChan and waits on s.wg.Wait(), which returns
// only once every worker has finished its current connection. So a test must
// (a) Stop() first, then (b) close its client connections, so the worker can
// drain and Serve can return. Calling Stop() while a client connection is still
// open is a legitimate in-flight drain, not a bug, and the tests model it
// explicitly rather than deadlocking on it.
package server

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// shutdownGrace is the ceiling for Serve() to return after Stop() plus closing
// the client connections. The unfixed code never returns.
const shutdownGrace = 5 * time.Second

// newDeadlockTLSServer builds a 1-worker DoT server. A single worker keeps the
// accept loop as the only goroutine parked in the shutdown select, and a tiny
// connChan makes filling it cheap and deterministic.
func newDeadlockTLSServer(t *testing.T) *TLSServer {
	t.Helper()
	cert := generateTestTLSCert2(t)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		w.Write(&protocol.Message{Header: protocol.Header{ID: req.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}})
	})

	srv := NewTLSServerWithWorkers("127.0.0.1:0", handler, tlsConfig, 1)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	return srv
}

// occupyWorker opens one fully-handshaked TLS connection and leaves it idle.
// The server's single worker picks it up, completes the handshake, then blocks
// in handleMessage waiting for a query that never arrives — so the worker stays
// busy and cannot drain connChan. Used to keep connChan full so the accept
// loop parks in the shutdown select.
func occupyWorker(t *testing.T, srv *TLSServer) net.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial worker-occupying conn: %v", err)
	}
	return c
}

// fillBacklog opens plain-TCP connections the server accepts but never
// handshakes. tls.Listener.Accept returns the *tls.Conn immediately (the TLS
// handshake is lazy), so these dials complete instantly and let the accept loop
// reach `select { case connChan <- conn: ... case <-ctx.Done(): }`. With the
// single worker busy and connChan (capacity workers*2 == 2) full, the next
// accepted connection parks the accept loop in that select, where cancelling the
// context deterministically takes the ctx.Done() (connSent==false) branch.
func fillBacklog(t *testing.T, srv *TLSServer, n int) []net.Conn {
	t.Helper()
	conns := make([]net.Conn, 0, n)
	for i := 0; i < n; i++ {
		c, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatalf("dial backlog conn %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	return conns
}

// stopAndDrain runs the real production shutdown (Stop) and then closes the
// client connections, so the in-flight worker can finish and Serve's wg.Wait()
// can return. Returns the Serve error, or fails the test on timeout.
func stopAndDrain(t *testing.T, srv *TLSServer, serveDone <-chan error, conns []net.Conn) {
	t.Helper()

	// (a) Cancel the context and close the listener. With connChan full, the
	//     accept loop is parked in the select and takes the ctx.Done() branch.
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// (b) Let the worker drain its in-flight connection so wg.Wait() completes.
	for _, c := range conns {
		_ = c.Close()
	}

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned error: %v", err)
		}
	case <-time.After(shutdownGrace):
		t.Fatalf("FAIL: Serve() did not return within %v of Stop()+close — the accept "+
			"loop self-deadlocked holding s.ipConnMu, so connChan is never closed and "+
			"s.wg.Wait() is never reached (tls.go Serve() holds s.ipConnMu and then calls "+
			"s.decrementIPConn(), which re-locks the same non-reentrant sync.Mutex).",
			shutdownGrace)
	}
}

// assertIPConnMutexFree checks no goroutine is deadlocked holding ipConnMu.
func assertIPConnMutexFree(t *testing.T, srv *TLSServer) {
	t.Helper()
	acquired := make(chan struct{})
	go func() {
		// Defers run in reverse order: unlock before signalling completion.
		defer close(acquired)
		srv.ipConnMu.Lock()
		defer srv.ipConnMu.Unlock()
	}()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatalf("FAIL: ipConnMu is still locked after Serve returned — " +
			"a goroutine is deadlocked holding the per-IP connection mutex")
	}
}

// CLAIM: Serve() deadlocks on the shutdown path (reentrant ipConnMu lock).
func TestTLSServerServe_ShutdownDoesNotDeadlock(t *testing.T) {
	srv := newDeadlockTLSServer(t)

	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve() }()
	waitForAcceptLoop(t, srv)

	// 1. Occupy the single worker so it cannot drain connChan.
	workerConn := occupyWorker(t, srv)
	time.Sleep(150 * time.Millisecond)

	// 2. Fill connChan (capacity workers*2 == 2) with accepted connections.
	backlog := fillBacklog(t, srv, 2)
	waitForAcceptLoop(t, srv)

	// 3. One more accepted connection parks the accept loop in the shutdown
	//    select: connChan is full, so the send case is not ready.
	parked := fillBacklog(t, srv, 1)
	time.Sleep(100 * time.Millisecond)

	// 4. Real shutdown: Stop() cancels ctx (parked select takes ctx.Done(),
	//    connSent==false) and closes the listener. Then close the client
	//    connections so the worker can drain and Serve can return.
	all := append([]net.Conn{workerConn}, backlog...)
	all = append(all, parked...)
	stopAndDrain(t, srv, serveDone, all)

	assertIPConnMutexFree(t, srv)
}

// CONTROL: the accepted-and-served path (connSent == true) shuts down
// normally. This must pass both before AND after the fix; it guards the
// harness and proves the defect is specific to the !connSent shutdown branch.
func TestTLSServerServe_ServedConnDoesNotDeadlock_Control(t *testing.T) {
	srv := newDeadlockTLSServer(t)

	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve() }()
	waitForAcceptLoop(t, srv)

	conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Send one real query over the served connection; the handler must reply.
	query, _ := protocol.NewQuery(0x1234, "control.example.com.", protocol.TypeA)
	buf := make([]byte, 512)
	n, err := query.Pack(buf[2:])
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	buf[0] = byte(n >> 8)
	buf[1] = byte(n)
	if _, err := conn.Write(buf[:n+2]); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	respLenBuf := make([]byte, 2)
	if _, err := readFullWithDeadline(conn, respLenBuf); err != nil {
		t.Fatalf("read length: %v", err)
	}

	// Shutdown must still complete cleanly after a served connection.
	stopAndDrain(t, srv, serveDone, []net.Conn{conn})
}

// waitForAcceptLoop blocks until the listener is accepting, so the accept loop
// is running before the test opens its connections.
func waitForAcceptLoop(t *testing.T, srv *TLSServer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", srv.Addr().String(), 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("server never started accepting")
}

// readFullWithDeadline reads len(p) bytes, honouring the conn read deadline.
func readFullWithDeadline(c net.Conn, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := c.Read(p[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
