// Regression tests for XoT (RFC 9103) server defects F222–F226 (audit round
// R35) and the shared IXFR journal-tail check (F225, also ixfr.go).

package transfer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// xotRegWaitStack polls goroutine stacks (no sleeps) until one contains all
// of the given substrings, or stop reports true.
func xotRegWaitStack(t *testing.T, stop func() bool, subs ...string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for i := 0; i < 2000000; i++ {
		if stop != nil && stop() {
			return
		}
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			ok := true
			for _, s := range subs {
				if !strings.Contains(g, s) {
					ok = false
					break
				}
			}
			if ok {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("no goroutine reached %v", subs)
}

func xotRegZone() *zone.Zone {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", TTL: 3600, MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", Type: "A", TTL: 300, RData: "192.0.2.1"}}
	return z
}

func xotRegGenerate(s *XoTServer, z *zone.Zone, ixfr bool) ([]*protocol.ResourceRecord, error) {
	if ixfr {
		return s.generateIXFRRecords(z, 0xFFFFFFF0) // older client, no journal -> full AXFR
	}
	return s.generateAXFRRecords(z)
}

// F222: the XoT AXFR (and IXFR→AXFR fallback) generator must frame the
// records with the SOA of the same zone state. Gated: the update holds the
// zone write lock until the transfer goroutine is parked on the read lock.
func TestXoTServer_SnapshotConsistentWithConcurrentUpdate(t *testing.T) {
	for _, ixfr := range []bool{false, true} {
		z := xotRegZone()
		z.Lock()
		done := make(chan []*protocol.ResourceRecord, 1)
		go func() {
			recs, err := xotRegGenerate(&XoTServer{}, z, ixfr)
			if err != nil {
				t.Error(err)
			}
			done <- recs
		}()
		xotRegWaitStack(t, nil, "xotRegGenerate", "RLock")
		ns := *z.SOA
		ns.Serial = 2
		z.SOA = &ns
		delete(z.Records, "www.example.com.")
		z.Records["new.example.com."] = []zone.Record{{Name: "new.example.com.", Type: "A", TTL: 300, RData: "192.0.2.2"}}
		z.Unlock()
		recs := <-done
		if len(recs) != 3 {
			t.Fatalf("ixfr=%v: %d records, want 3", ixfr, len(recs))
		}
		serial := recs[0].Data.(*protocol.RDataSOA).Serial
		owner := recs[1].Name.String()
		if !(serial == 1 && owner == "www.example.com.") && !(serial == 2 && owner == "new.example.com.") {
			t.Fatalf("ixfr=%v: torn snapshot: SOA serial %d framing %s", ixfr, serial, owner)
		}
	}
}

type xotRegCapture struct {
	net.Conn
	buf bytes.Buffer
}

func (c *xotRegCapture) Write(p []byte) (int, error)        { return c.buf.Write(p) }
func (c *xotRegCapture) SetWriteDeadline(_ time.Time) error { return nil }

// F223: 50 records per message overflowed the 16-bit length prefix for
// zones with large records; chunking must also respect 65535 bytes.
func TestXoTServer_AXFRChunksRespectMessageSizeLimit(t *testing.T) {
	z := xotRegZone()
	big := strings.TrimSpace(strings.Repeat(`"`+strings.Repeat("y", 250)+`" `, 6)) // ~1.5 KB TXT
	for i := 0; i < 60; i++ {
		name := fmt.Sprintf("t%d.example.com.", i)
		z.Records[name] = []zone.Record{{Name: name, Type: "TXT", TTL: 300, RData: big}}
	}
	s := &XoTServer{}
	recs, err := s.generateAXFRRecords(z)
	if err != nil {
		t.Fatal(err)
	}
	c := &xotRegCapture{}
	if err := s.sendAXFRResponse(c, recs, 0x1234); err != nil {
		t.Fatalf("sendAXFRResponse: %v", err)
	}
	total := 0
	data := c.buf.Bytes()
	for len(data) >= 2 {
		l := int(binary.BigEndian.Uint16(data))
		m, err := protocol.UnpackMessage(data[2 : 2+l])
		if err != nil {
			t.Fatalf("unpack: %v", err)
		}
		total += len(m.Answers)
		data = data[2+l:]
	}
	if total != len(recs) {
		t.Fatalf("streamed %d records, want %d", total, len(recs))
	}
}

// F224: Serve must accept the production bind form "host:port"
// (server.xot.bind, default ":853"); it used to append ListenPort and fail
// with "too many colons", so XoT could never start.
func TestXoTServer_ServeAcceptsHostPortBind(t *testing.T) {
	certFile, keyFile, pair := newXoTCertFiles(t, t.TempDir())
	srv, err := NewXoTServer(map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 1, 2)}, &XoTConfig{
		CertFile: certFile, KeyFile: keyFile, ListenPort: 853, AllowedNetworks: []string{"127.0.0.1/32"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	if err := srv.Serve("127.0.0.1:0"); err != nil {
		t.Fatalf("Serve(127.0.0.1:0): %v", err)
	}
	if srv.Addr() != srv.listener.Addr().String() {
		t.Fatalf("Addr() = %q, listener on %q", srv.Addr(), srv.listener.Addr())
	}
	go srv.AcceptLoop()
	conn := xotDial(t, srv.Addr(), pair)
	xotSendFrame(t, conn, xotTransferQuery(3, "example.com.", protocol.TypeAXFR))
	if m := xotReadFrame(t, conn); len(m.Answers) != 4 {
		t.Fatalf("AXFR answers = %d, want 4", len(m.Answers))
	}
}

type xotRegJournal struct{ entries []*IXFRJournalEntry }

func (j *xotRegJournal) SaveEntry(_ string, e *IXFRJournalEntry) error {
	j.entries = append(j.entries, e)
	return nil
}
func (j *xotRegJournal) LoadEntries(string) ([]*IXFRJournalEntry, error) { return j.entries, nil }
func (j *xotRegJournal) Truncate(string, int) error                      { return nil }

// F225: when the zone serial moved past the journal tail through a change
// that was not journalled, IXFR (XoT and TCP) must answer a full AXFR
// instead of a delta that stops at the tail but is framed with the current
// SOA (which would mark the secondary current while missing changes).
func TestIXFR_JournalTailBehindZoneFallsBackToAXFR(t *testing.T) {
	mk := func(serialNow uint32) (*zone.Zone, []*IXFRJournalEntry) {
		z := xotRegZone()
		z.SOA.Serial = serialNow
		add := func(n string) []zone.RecordChange {
			return []zone.RecordChange{{Name: n, Type: protocol.TypeA, TTL: 300, RData: "192.0.2.9"}}
		}
		return z, []*IXFRJournalEntry{
			{OldSerial: 1, Serial: 2, Added: add("a.example.com.")},
			{OldSerial: 2, Serial: 3, Added: add("b.example.com.")},
		}
	}
	isIncremental := func(recs []*protocol.ResourceRecord) bool {
		return len(recs) > 1 && recs[1].Type == protocol.TypeSOA
	}
	for _, tc := range []struct {
		zoneSerial  uint32
		incremental bool
	}{{3, true}, {4, false}} {
		z, entries := mk(tc.zoneSerial)
		recs, err := (&XoTServer{journalStore: &xotRegJournal{entries: entries}}).generateIXFRRecords(z, 2)
		if err != nil {
			t.Fatal(err)
		}
		if isIncremental(recs) != tc.incremental {
			t.Errorf("XoT zone=%d: incremental=%v, want %v", tc.zoneSerial, isIncremental(recs), tc.incremental)
		}

		z2, entries2 := mk(tc.zoneSerial)
		is := NewIXFRServer(NewAXFRServer(map[string]*zone.Zone{"example.com.": z2}, WithAllowList([]string{"127.0.0.0/8"})))
		for _, e := range entries2 {
			is.RecordChange("example.com.", e.OldSerial, e.Serial, e.Added, e.Deleted)
		}
		origin, _ := protocol.ParseName("example.com.")
		req := &protocol.Message{
			Header:    protocol.Header{ID: 9, QDCount: 1},
			Questions: []*protocol.Question{{Name: origin, QType: protocol.TypeIXFR, QClass: protocol.ClassIN}},
			Authorities: []*protocol.ResourceRecord{{Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN,
				Data: &protocol.RDataSOA{MName: origin, RName: origin, Serial: 2}}},
		}
		recs, _, err = is.HandleIXFRWithKey(req, net.ParseIP("127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		if isIncremental(recs) != tc.incremental {
			t.Errorf("IXFR zone=%d: incremental=%v, want %v", tc.zoneSerial, isIncremental(recs), tc.incremental)
		}
	}
}

// F226: Close must tear down live connections: it used to wait for clients
// to disconnect while still serving zone data on their connections.
func TestXoTServer_CloseTearsDownLiveConnections(t *testing.T) {
	zones := map[string]*zone.Zone{"example.com.": newXoTTestZone("example.com.", 1, 3)}
	srv, pair := startXoTTestServer(t, zones, "127.0.0.1/32")
	conn := xotDial(t, srv.Addr(), pair)
	xotSendFrame(t, conn, xotTransferQuery(1, "example.com.", protocol.TypeAXFR))
	if m := xotReadFrame(t, conn); len(m.Answers) != 5 {
		t.Fatalf("pre-Close answers = %d", len(m.Answers))
	}

	var closed atomic.Bool
	errCh := make(chan error, 1)
	go func() { err := srv.Close(); closed.Store(true); errCh <- err }()
	xotRegWaitStack(t, closed.Load, "XoTServer).Close", "sync.(*WaitGroup).Wait")

	buf := make([]byte, 2+512)
	n, _ := xotTransferQuery(2, "example.com.", protocol.TypeAXFR).Pack(buf[2:])
	binary.BigEndian.PutUint16(buf, uint16(n))
	_, _ = conn.Write(buf[:2+n])
	var prefix [2]byte
	_, rerr := io.ReadFull(conn, prefix[:])
	_ = conn.Close() // lets an unfixed Close return
	if err := <-errCh; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if rerr == nil {
		t.Fatal("server answered a transfer on a live connection after Close")
	}
}
