package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// Regressions for the cmd/nothingdns zone wiring round (F447–F449).

// zwClock is an injectable SlaveManager clock whose timers never fire.
type zwClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *zwClock) Now() time.Time                              { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *zwClock) set(t time.Time)                             { c.mu.Lock(); c.now = t; c.mu.Unlock() }
func (c *zwClock) AfterFunc(time.Duration, func()) func() bool { return func() bool { return true } }

// F447: a slave zone past its SOA EXPIRE (RFC 1035 §4.3.5) is no longer
// served; a successful refresh makes it servable again without a rebuild.
func TestSlaveZone_ExpiredZoneNotServed(t *testing.T) {
	m := newSlaveServingMaster(t, slaveServingZone(2, "192.0.2.2"))
	h := newServingSlave(t, m.addr)
	h.config.Resolution.AuthoritativeOnly = true
	awaitSlaveSerial(t, h, 2)
	sm := h.transfer.SlaveManager
	sz := sm.GetSlaveZone("example.com.")
	exp := sz.ExpiresAt()
	clk := &zwClock{now: exp.Add(-time.Second)}
	sm.SetClock(clk.Now, clk.AfterFunc)

	if got, want := slaveServingAnswer(h, "www.example.com."), "rcode=NOERROR aa=true 192.0.2.2"; got != want {
		t.Fatalf("before expiry: got %q, want %q", got, want)
	}
	clk.set(exp)
	for _, q := range []string{"www.example.com.", "alias.example.com."} {
		if got, want := slaveServingAnswer(h, q), "rcode=REFUSED aa=false"; got != want {
			t.Fatalf("F447 expired zone %s: got %q, want %q", q, got, want)
		}
	}
	if _, ok := h.zoneProvider.GetZone("example.com."); ok {
		t.Fatal("F447: expired zone still routed")
	}

	m.axfr.AddZone(slaveServingZone(3, "192.0.2.3"))
	if rc := sendNotifyIntake(t, h, "127.0.0.1", 3); rc != protocol.RcodeSuccess {
		t.Fatalf("NOTIFY rcode=%d", rc)
	}
	awaitSlaveSerial(t, h, 3)
	if got, want := slaveServingAnswer(h, "www.example.com."), "rcode=NOERROR aa=true 192.0.2.3"; got != want {
		t.Fatalf("after refresh: got %q, want %q", got, want)
	}
}

func zwXoTFixture(t *testing.T) (*integratedHandler, string) {
	t.Helper()
	cert, key := generateSelfSignedCert(t)
	cfg := config.DefaultConfig()
	cfg.Storage.DataDir = t.TempDir()
	cfg.Server.UDPBind = []string{ephemeralPort(t)}
	cfg.Server.TCPBind = []string{ephemeralPort(t)}
	cfg.Server.TLS.Enabled = false
	cfg.Server.QUIC.Enabled = false
	cfg.Server.XoT = config.XoTConfig{Enabled: true, Bind: ephemeralPort(t), CertFile: cert, KeyFile: key, AllowedNetworks: []string{"127.0.0.1/32"}}
	h := newTestHandler()
	h.zones["example.com."] = xfrTSIGZone(0)
	logger := newDiscardLogger()
	tm, err := NewTransferManager(cfg, h.zones, &h.zonesMu, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tm.Stop)
	srvs, err := startServers(cfg, h, tm, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srvs.stopAll(logger) })
	return h, srvs.xot.Addr()
}

// zwXoTAXFR sends an AXFR over XoT and returns a channel yielding the number
// of answers up to the closing SOA (-1 on error).
func zwXoTAXFR(t *testing.T, addr string) <-chan int {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // loopback test server
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	q, _ := protocol.NewQuestion("example.com.", protocol.TypeAXFR, protocol.ClassIN)
	msg := &protocol.Message{Header: protocol.Header{ID: 1, Flags: protocol.NewQueryFlags(), QDCount: 1}, Questions: []*protocol.Question{q}}
	buf := make([]byte, 2+65535)
	n, err := msg.Pack(buf[2:])
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(buf[:2], uint16(n))
	if _, err := conn.Write(buf[:2+n]); err != nil {
		t.Fatal(err)
	}
	out := make(chan int, 1)
	go func() {
		total, soas := 0, 0
		for soas < 2 {
			var p [2]byte
			if _, err := io.ReadFull(conn, p[:]); err != nil {
				out <- -1
				return
			}
			body := make([]byte, binary.BigEndian.Uint16(p[:]))
			if _, err := io.ReadFull(conn, body); err != nil {
				out <- -1
				return
			}
			m, err := protocol.UnpackMessage(body)
			if err != nil || len(m.Answers) == 0 {
				out <- -1
				return
			}
			for _, rr := range m.Answers {
				if rr.Type == protocol.TypeSOA {
					soas++
				}
			}
			total += len(m.Answers)
		}
		out <- total
	}()
	return out
}

// F448: the XoT server started by startServers reads the handler's zones map
// under handler.zonesMu (the lock every writer of the map holds). Gated: the
// test holds the write lock and waits until the XoT handler is parked on it.
func TestStartXoT_SharesHandlerZonesLock(t *testing.T) {
	h, addr := zwXoTFixture(t)
	if n := <-zwXoTAXFR(t, addr); n != 5 {
		t.Fatalf("control XoT AXFR answers=%d, want 5", n)
	}
	h.zonesMu.Lock()
	got := zwXoTAXFR(t, addr)
	parked, early := false, -2
	buf := make([]byte, 1<<20)
	for i := 0; i < 4000000 && !parked && early == -2; i++ {
		select {
		case n := <-got:
			early = n
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
	h.zones["other.example."] = zone.NewZone("other.example.")
	h.zonesMu.Unlock()
	if early != -2 || !parked {
		t.Fatalf("F448: XoT AXFR answered while handler.zonesMu was write-held (parked=%v answered=%d)", parked, early)
	}
	if n := <-got; n != 5 {
		t.Fatalf("XoT AXFR after release answers=%d, want 5", n)
	}
}

// F449: zones that exist only in the zone manager (API/Raft create, snapshot
// install) are transferable under the same allow_list as config zones, and
// leave the transfer map when deleted.
func TestManagerZones_TransferableLikeConfigZones(t *testing.T) {
	h, m := zoneDelBoot(t)
	soa := &zone.SOARecord{Name: "api.test.", TTL: 300, MName: "ns1.api.test.", RName: "admin.api.test.", Serial: 7, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	if err := m.CreateZone("api.test.", 300, soa, []zone.NSRecord{{Name: "api.test.", TTL: 300, NSDName: "ns1.api.test."}}); err != nil {
		t.Fatal(err)
	}
	snap, err := zone.ParseFile("snap.test.", strings.NewReader(fmt.Sprintf(zoneDelZone, "snap.test.", 9, "192.0.2.11")))
	if err != nil {
		t.Fatal(err)
	}
	m.LoadZone(snap, "")
	m.NotifyMutated("snap.test.")

	if got := zoneDelAXFR(h, "api.test."); got != "rcode=NOERROR soa=7" {
		t.Fatalf("F449: AXFR of API-created zone = %q", got)
	}
	if got := zoneDelAXFR(h, "snap.test."); got != "rcode=NOERROR soa=9 www=192.0.2.11" {
		t.Fatalf("F449: AXFR of snapshot-installed zone = %q", got)
	}
	w := &zoneDelMultiWriter{client: newCaptureWriter("198.51.100.9", "tcp").client}
	q, _ := protocol.NewQuery(8, "api.test.", protocol.TypeAXFR)
	h.ServeDNS(w, q)
	if len(w.msgs) == 0 || w.msgs[0].Header.Flags.RCODE != protocol.RcodeRefused {
		t.Fatal("F449: API zone transferable from outside transfer.allow_list")
	}
	if err := m.DeleteZone("api.test."); err != nil {
		t.Fatal(err)
	}
	if got := zoneDelAXFR(h, "api.test."); !strings.HasPrefix(got, "rcode=REFUSED") {
		t.Fatalf("AXFR of deleted API zone = %q", got)
	}
}
