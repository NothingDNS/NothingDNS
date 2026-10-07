// Regression tests for campaign phase 2 task P2-A2 (F412–F415): secondary
// SOA refresh/retry/expire timers, the IXFR serial decision under the zone
// lock, the XoT shared zones-map lock, and the XoT TLS 1.3 / ALPN floor.

package transfer

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// p2Timer / p2Clock: a fake clock for SlaveManager.SetClock. Every armed
// timer is published on armed; tests fire timers by calling f themselves.
type p2Timer struct {
	d       time.Duration
	f       func()
	stopped atomic.Bool
}

type p2Clock struct {
	mu    sync.Mutex
	now   time.Time
	armed chan *p2Timer
}

func newP2Clock() *p2Clock {
	return &p2Clock{now: time.Unix(1_000_000, 0), armed: make(chan *p2Timer, 256)}
}

func (c *p2Clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *p2Clock) set(t time.Time) { c.mu.Lock(); c.now = t; c.mu.Unlock() }

func (c *p2Clock) AfterFunc(d time.Duration, f func()) func() bool {
	tm := &p2Timer{d: d, f: f}
	c.armed <- tm
	return func() bool { return !tm.stopped.Swap(true) }
}

// next returns the next armed timer. The timeout only bounds a failing test;
// it is never a synchronization point.
func (c *p2Clock) next(t *testing.T) *p2Timer {
	t.Helper()
	select {
	case tm := <-c.armed:
		return tm
	case <-time.After(10 * time.Second):
		t.Fatal("no SOA timer was armed")
		return nil
	}
}

// none asserts that no further timer has been armed.
func (c *p2Clock) none(t *testing.T) {
	t.Helper()
	select {
	case tm := <-c.armed:
		t.Fatalf("unexpected timer armed (%v)", tm.d)
	default:
	}
}

// p2Master is a loopback master whose behavior can be switched: mode > 0
// serves a full AXFR with that serial (SOA refresh 3600, retry 600, expire
// 86400), mode 0 refuses.
type p2Master struct {
	*r31Master
	mode  atomic.Int32
	conns atomic.Int32
	stop  func() int
}

func newP2Master(t *testing.T, serial int32) *p2Master {
	m := &p2Master{r31Master: newR31Master(t)}
	m.mode.Store(serial)
	m.stop = m.serve(func(c net.Conn) {
		m.conns.Add(1)
		if s := m.mode.Load(); s > 0 {
			r31ServeAXFR(uint32(s))(c)
			return
		}
		r31Refuse(c)
	})
	t.Cleanup(func() { m.stop() })
	return m
}

func newP2Slave(t *testing.T, m *r31Master, clk *p2Clock, mutate func(*SlaveZoneConfig)) (*SlaveManager, *SlaveZone) {
	t.Helper()
	sm := NewSlaveManager(nil)
	sm.SetClock(clk.Now, clk.AfterFunc)
	cfg := r31Config(m.ln.Addr().String())
	if mutate != nil {
		mutate(&cfg)
	}
	if err := sm.AddSlaveZone(cfg); err != nil {
		t.Fatalf("AddSlaveZone: %v", err)
	}
	t.Cleanup(sm.Stop)
	return sm, sm.GetSlaveZone("example.com.")
}

// p2NoSlaveGoroutines asserts no goroutine is running code of sm (matched by
// its receiver pointer in the stack trace).
func p2NoSlaveGoroutines(t *testing.T, sm *SlaveManager) {
	t.Helper()
	ptr := fmt.Sprintf("%p", sm)
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	for _, g := range strings.Split(string(buf[:n]), "\n\n") {
		if strings.Contains(g, "transfer.(*SlaveManager)") && strings.Contains(g, ptr) {
			t.Fatalf("SlaveManager goroutine still running after Stop:\n%s", g)
		}
	}
}

// F412: REFRESH after a successful load, RETRY after a failed refresh,
// EXPIRE stops the zone from being servable, Stop cancels the pending timer.
func TestSlaveManager_SOARefreshRetryExpire(t *testing.T) {
	m := newP2Master(t, 1)
	clk := newP2Clock()
	sm, sz := newP2Slave(t, m.r31Master, clk, nil)

	t1 := clk.next(t)
	if t1.d != time.Hour || !sz.IsServable() || sz.GetLastSerial() != 1 {
		t.Fatalf("after load: timer=%v servable=%v serial=%d, want 1h/true/1", t1.d, sz.IsServable(), sz.GetLastSerial())
	}
	loaded := clk.Now()
	if want := loaded.Add(86400 * time.Second); !sz.ExpiresAt().Equal(want) {
		t.Fatalf("ExpiresAt=%v, want %v", sz.ExpiresAt(), want)
	}

	m.mode.Store(2)
	clk.set(loaded.Add(time.Hour))
	t1.f()
	t2 := clk.next(t)
	if t2.d != time.Hour || sz.GetLastSerial() != 2 || m.conns.Load() != 2 {
		t.Fatalf("refresh: timer=%v serial=%d conns=%d, want 1h/2/2", t2.d, sz.GetLastSerial(), m.conns.Load())
	}
	lastOK := clk.Now()

	m.mode.Store(0)
	clk.set(lastOK.Add(time.Hour))
	t2.f()
	t3 := clk.next(t)
	if t3.d != 10*time.Minute {
		t.Fatalf("failed refresh armed %v, want the SOA RETRY 10m", t3.d)
	}
	t3.f()
	t4 := clk.next(t)
	if t4.d != 10*time.Minute || m.conns.Load() != 4 {
		t.Fatalf("retry: timer=%v conns=%d, want 10m/4", t4.d, m.conns.Load())
	}

	clk.set(lastOK.Add(86400*time.Second - time.Nanosecond))
	if !sz.IsServable() || sz.Expired() {
		t.Fatal("zone unservable before EXPIRE elapsed")
	}
	clk.set(lastOK.Add(86400 * time.Second))
	if sz.IsServable() || !sz.Expired() {
		t.Fatal("zone still servable after EXPIRE elapsed without a refresh")
	}

	// A successful refresh after expiry makes it servable again.
	m.mode.Store(3)
	t4.f()
	t5 := clk.next(t)
	if t5.d != time.Hour || !sz.IsServable() || sz.GetLastSerial() != 3 {
		t.Fatalf("recovery: timer=%v servable=%v serial=%d", t5.d, sz.IsServable(), sz.GetLastSerial())
	}

	sm.Stop()
	if !t5.stopped.Load() {
		t.Fatal("Stop left the pending refresh timer armed")
	}
	before := m.conns.Load()
	t5.f() // a timer that fires after Stop must not start a transfer
	clk.none(t)
	if m.conns.Load() != before {
		t.Fatal("timer fired after Stop contacted the master")
	}
	p2NoSlaveGoroutines(t, sm)
}

// F412: a NOTIFY-triggered transfer replaces the pending timer; the replaced
// timer's late callback is a no-op; a timer firing while a transfer is in
// flight folds into one follow-up run (single owner, F204).
func TestSlaveManager_SOATimersCooperateWithNotify(t *testing.T) {
	m := newR31Master(t)
	clk := newP2Clock()
	sm := NewSlaveManager(nil)
	sm.SetClock(clk.Now, clk.AfterFunc)
	if err := sm.AddSlaveZone(r31Config(m.ln.Addr().String())); err != nil {
		t.Fatal(err)
	}
	r31ServeAXFR(1)(<-m.accepted)
	t1 := clk.next(t)

	// NOTIFY: transfer runs, re-arms REFRESH, cancels t1.
	sm.handleNotify(&NOTIFYRequest{ZoneName: "example.com.", Serial: 2})
	r31ServeAXFR(2)(<-m.accepted)
	t2 := clk.next(t)
	if !t1.stopped.Load() || t2.d != time.Hour {
		t.Fatalf("NOTIFY run: old stopped=%v new=%v", t1.stopped.Load(), t2.d)
	}
	t1.f() // stale callback (already replaced)
	clk.none(t)

	// t2 fires while a NOTIFY transfer holds the zone: one follow-up run.
	sm.handleNotify(&NOTIFYRequest{ZoneName: "example.com.", Serial: 3})
	held := <-m.accepted
	t2.f()
	r31ServeAXFR(3)(held)
	r31ServeAXFR(3)(<-m.accepted) // the coalesced follow-up
	t3 := clk.next(t)
	stop := m.serve(r31Refuse)
	sm.Stop()
	if n := stop(); n != 4 {
		t.Fatalf("master saw %d transfers, want 4 (load, NOTIFY, NOTIFY+coalesced timer)", n)
	}
	clk.none(t)
	if !t3.stopped.Load() || sz(sm).GetLastSerial() != 3 {
		t.Fatalf("after Stop: timer stopped=%v serial=%d", t3.stopped.Load(), sz(sm).GetLastSerial())
	}
	p2NoSlaveGoroutines(t, sm)
}

func sz(sm *SlaveManager) *SlaveZone { return sm.GetSlaveZone("example.com.") }

// F412: a never-loaded zone retries on RetryInterval and gives up after
// MaxRetries; a loaded zone defers to REFRESH instead of stopping; removing a
// zone cancels its timer; absurd SOA timers are clamped.
func TestSlaveManager_SOATimerEdges(t *testing.T) {
	t.Run("never loaded uses RetryInterval and MaxRetries", func(t *testing.T) {
		m := newP2Master(t, 0)
		clk := newP2Clock()
		_, z := newP2Slave(t, m.r31Master, clk, func(c *SlaveZoneConfig) { c.RetryInterval = 7 * time.Minute; c.MaxRetries = 1 })
		tm := clk.next(t)
		if tm.d != 7*time.Minute || z.IsServable() {
			t.Fatalf("retry=%v servable=%v", tm.d, z.IsServable())
		}
		tm.f()
		// The second failure exceeds MaxRetries: no timer for a zone with
		// nothing to serve. Wait for the run via the master, then for the
		// owner to finish (claim succeeds only once it released).
		for m.conns.Load() != 2 {
			runtime.Gosched()
		}
		for {
			z.mu.RLock()
			busy := z.transferring
			z.mu.RUnlock()
			if !busy {
				break
			}
			runtime.Gosched()
		}
		clk.none(t)
	})
	t.Run("loaded zone defers to REFRESH after MaxRetries", func(t *testing.T) {
		m := newP2Master(t, 1)
		clk := newP2Clock()
		_, z := newP2Slave(t, m.r31Master, clk, func(c *SlaveZoneConfig) { c.MaxRetries = 1 })
		t1 := clk.next(t)
		m.mode.Store(0)
		t1.f()
		t2 := clk.next(t)
		t2.f()
		t3 := clk.next(t)
		if t2.d != 10*time.Minute || t3.d != time.Hour || !z.IsServable() {
			t.Fatalf("retry=%v next=%v, want 10m then 1h", t2.d, t3.d)
		}
	})
	t.Run("RemoveSlaveZone cancels the timer", func(t *testing.T) {
		m := newP2Master(t, 1)
		clk := newP2Clock()
		sm, _ := newP2Slave(t, m.r31Master, clk, nil)
		t1 := clk.next(t)
		sm.RemoveSlaveZone("example.com.")
		if !t1.stopped.Load() {
			t.Fatal("removed zone kept its timer")
		}
		t1.f()
		clk.none(t)
		if m.conns.Load() != 1 {
			t.Fatal("removed zone's timer contacted the master")
		}
	})
	t.Run("clamped SOA timers", func(t *testing.T) {
		z := zone.NewZone("example.com.")
		z.SOA = &zone.SOARecord{Refresh: 0, Retry: 0, Expire: 0}
		got, ok := zoneSOATimers(z)
		if !ok || got.refresh != slaveMinRefresh || got.retry != slaveMinRetry || got.expire != slaveMinRefresh+slaveMinRetry {
			t.Fatalf("zero SOA timers -> %+v", got)
		}
		z.SOA = &zone.SOARecord{Refresh: 0xFFFFFFFF, Retry: 0xFFFFFFFF, Expire: 60}
		got, _ = zoneSOATimers(z)
		if got.refresh != slaveMaxRefresh || got.retry != slaveMaxRetry || got.expire != slaveMaxRefresh+slaveMaxRetry {
			t.Fatalf("huge SOA timers -> %+v", got)
		}
		if _, ok := zoneSOATimers(zone.NewZone("x.")); ok {
			t.Fatal("zone without SOA produced timers")
		}
	})
	t.Run("AddSlaveZone after Stop", func(t *testing.T) {
		sm := NewSlaveManager(nil)
		sm.Stop()
		if err := sm.AddSlaveZone(r31Config("127.0.0.1:1")); err == nil {
			t.Fatal("stopped manager accepted a zone")
		}
	})
}

// p2WaitGoroutine polls stacks (no sleeps) until the already-started
// goroutine whose stack contains marker is parked in RLock (true) or has
// finished (false).
func p2WaitGoroutine(t *testing.T, marker string, extra ...string) bool {
	t.Helper()
	buf := make([]byte, 1<<20)
	for i := 0; i < 4000000; i++ {
		n := runtime.Stack(buf, true)
		found := false
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if !strings.Contains(g, marker) {
				continue
			}
			found = true
			parked := strings.Contains(g, "RLock")
			for _, e := range extra {
				parked = parked && strings.Contains(g, e)
			}
			if parked {
				return true
			}
		}
		if !found {
			return false
		}
		runtime.Gosched()
	}
	t.Fatalf("goroutine %s neither parked nor finished", marker)
	return false
}

func p2IXFRRequest(clientSerial uint32) *protocol.Message {
	q, _ := protocol.NewQuestion("example.com.", protocol.TypeIXFR, protocol.ClassIN)
	origin, _ := protocol.ParseName("example.com.")
	return &protocol.Message{
		Header:    protocol.Header{ID: 7, Flags: protocol.NewQueryFlags(), QDCount: 1, NSCount: 1},
		Questions: []*protocol.Question{q},
		Authorities: []*protocol.ResourceRecord{{Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN,
			Data: &protocol.RDataSOA{MName: origin, RName: origin, Serial: clientSerial}}},
	}
}

func p2Summary(recs []*protocol.ResourceRecord) string {
	var parts []string
	for _, rr := range recs {
		if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
			parts = append(parts, "SOA("+strconv.FormatUint(uint64(soa.Serial), 10)+")")
		} else {
			parts = append(parts, rr.Name.String())
		}
	}
	return strings.Join(parts, " ")
}

// p2GatedIXFR holds the zone write lock, runs HandleIXFR with clientSerial,
// waits until it is parked on the zone lock (or done), applies a serial-2
// update and returns whether it parked plus the answer.
func p2GatedIXFR(t *testing.T, clientSerial uint32) (bool, string) {
	t.Helper()
	z := xotRegZone()
	srv := NewIXFRServer(NewAXFRServer(map[string]*zone.Zone{"example.com.": z}, WithAllowList([]string{"127.0.0.0/8"})))
	z.Lock()
	done := make(chan string, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		recs, err := srv.HandleIXFR(p2IXFRRequest(clientSerial), net.ParseIP("127.0.0.1"))
		if err != nil {
			t.Errorf("HandleIXFR: %v", err)
		}
		done <- p2Summary(recs)
	}()
	<-started
	parked := p2WaitGoroutine(t, "p2GatedIXFR.func", "HandleIXFR")
	ns := *z.SOA
	ns.Serial = 2
	z.SOA = &ns
	delete(z.Records, "www.example.com.")
	z.Records["new.example.com."] = []zone.Record{{Name: "new.example.com.", Type: "A", TTL: 300, RData: "192.0.2.2"}}
	z.Unlock()
	return parked, <-done
}

// F413: HandleIXFR decided on z.SOA.Serial without the zone lock and could
// tell a client "current" from a zone mid-update.
func TestIXFRServer_SerialDecisionUnderZoneLock(t *testing.T) {
	for _, tc := range []struct {
		client uint32
		want   string
	}{
		{1, "SOA(2) new.example.com. SOA(2)"}, // was current; update -> AXFR (no journal)
		{2, "SOA(2)"},                         // current after the update
		{5, "SOA(2) new.example.com. SOA(2)"}, // client ahead -> AXFR
	} {
		parked, got := p2GatedIXFR(t, tc.client)
		if !parked || got != tc.want {
			t.Fatalf("client=%d: parked=%v answer=%q, want parked and %q", tc.client, parked, got, tc.want)
		}
	}
}

func p2ReadAnswers(conn net.Conn) int {
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return -1
	}
	body := make([]byte, binary.BigEndian.Uint16(p[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return -1
	}
	m, err := protocol.UnpackMessage(body)
	if err != nil {
		return -1
	}
	return len(m.Answers)
}

// F414: the XoT server must lock the shared zones map with its owner's lock.
func TestXoTServer_SharedZonesMu(t *testing.T) {
	var ownerMu sync.RWMutex
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 7, 1)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")
	srv.SetZonesMu(&ownerMu)
	srv.SetZonesMu(nil) // ignored
	if srv.zonesLock() != &ownerMu {
		t.Fatal("SetZonesMu did not install the owner's lock")
	}

	// Gated: the owner holds its write lock; the transfer must wait for it.
	conn := xotDial(t, srv.Addr(), pair)
	ownerMu.Lock()
	xotSendFrame(t, conn, xotTransferQuery(2, "example.com.", protocol.TypeAXFR))
	got := make(chan int, 1)
	go func() { got <- p2ReadAnswers(conn) }()
	buf := make([]byte, 1<<20)
	for parked := false; !parked; {
		select {
		case n := <-got:
			t.Fatalf("answered (%d) under the owner's write lock", n)
		default:
		}
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "handleAXFRRequest") && strings.Contains(g, "RLock") {
				parked = true
			}
		}
		runtime.Gosched()
	}
	zones["other.example."] = newXoTTestZone("other.example.", 1, 0)
	ownerMu.Unlock()
	if n := <-got; n != 3 {
		t.Fatalf("answers=%d, want 3", n)
	}

	// Concurrent owner mutations under the shared lock vs XoT AXFR/IXFR
	// lookups: clean under -race.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ownerMu.Lock()
			if i%2 == 0 {
				zones["churn.example."] = newXoTTestZone("churn.example.", 1, 0)
			} else {
				delete(zones, "churn.example.")
			}
			ownerMu.Unlock()
		}
	}()
	c2 := xotDial(t, srv.Addr(), pair)
	for i := 0; i < 20; i++ {
		qt := uint16(protocol.TypeAXFR)
		if i%2 == 1 {
			qt = protocol.TypeIXFR
		}
		xotSendFrame(t, c2, xotTransferQuery(uint16(10+i), "example.com.", qt))
		if n := p2ReadAnswers(c2); n != 3 {
			t.Fatalf("transfer %d: answers=%d", i, n)
		}
	}
	close(stop)
	wg.Wait()
}

func p2Handshake(t *testing.T, addr string, pair tls.Certificate, maxVer uint16, alpn []string) (tls.ConnectionState, error) {
	t.Helper()
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: maxVer, NextProtos: alpn})
	err = c.Handshake()
	return c.ConnectionState(), err
}

// F415: XoT requires TLS 1.3 (RFC 9103 §5.1) and negotiates ALPN "dot"
// (§7.1), even when min_tls_version asks for 1.2.
func TestXoTServer_RequiresTLS13AndDotALPN(t *testing.T) {
	cfg, err := buildXoTTLSConfig(&XoTConfig{MinTLSVersion: 12})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "dot" {
		t.Fatalf("min_tls_version 12: MinVersion=%#x NextProtos=%v", cfg.MinVersion, cfg.NextProtos)
	}

	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 1, 0)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")
	if _, err := p2Handshake(t, srv.Addr(), pair, tls.VersionTLS12, nil); err == nil {
		t.Fatal("TLS 1.2-only client completed an XoT handshake")
	}
	st, err := p2Handshake(t, srv.Addr(), pair, tls.VersionTLS13, []string{"dot"})
	if err != nil || st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "dot" {
		t.Fatalf("TLS 1.3 + dot: err=%v version=%#x alpn=%q", err, st.Version, st.NegotiatedProtocol)
	}
	// A client without ALPN is still served (ALPN is offered, not demanded).
	if st, err := p2Handshake(t, srv.Addr(), pair, tls.VersionTLS13, nil); err != nil || st.NegotiatedProtocol != "" {
		t.Fatalf("TLS 1.3 without ALPN: err=%v alpn=%q", err, st.NegotiatedProtocol)
	}
	// A client demanding a different protocol is rejected.
	if _, err := p2Handshake(t, srv.Addr(), pair, tls.VersionTLS13, []string{"h2"}); err == nil {
		t.Fatal("client offering only h2 completed the handshake")
	}
}
