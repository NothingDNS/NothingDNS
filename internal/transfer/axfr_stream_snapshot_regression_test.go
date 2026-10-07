package transfer

import (
	"io"
	"net"
	"runtime"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func axfrRegName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func axfrRegSOA(t *testing.T, owner string, serial uint32) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{Name: axfrRegName(t, owner), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 3600,
		Data: &protocol.RDataSOA{MName: axfrRegName(t, "ns1.example.com."), RName: axfrRegName(t, "admin.example.com."),
			Serial: serial, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}}
}

func axfrRegA(t *testing.T, owner string) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{Name: axfrRegName(t, owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 66}}}
}

// axfrRegMaster is a loopback master that answers one transfer request with
// the given messages (one answer slice per message), then closes.
func axfrRegMaster(t *testing.T, msgs [][]*protocol.ResourceRecord) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var lb [2]byte
		if _, err := io.ReadFull(conn, lb[:]); err != nil {
			return
		}
		buf := make([]byte, int(lb[0])<<8|int(lb[1]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		req, err := protocol.UnpackMessage(buf)
		if err != nil {
			return
		}
		for _, answers := range msgs {
			resp := &protocol.Message{Header: protocol.Header{ID: req.Header.ID, Flags: protocol.Flags{QR: true, AA: true}},
				Questions: req.Questions, Answers: answers}
			out := make([]byte, 65535)
			n, err := resp.Pack(out)
			if err != nil {
				return
			}
			if _, err := conn.Write(append([]byte{byte(n >> 8), byte(n)}, out[:n]...)); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

// TestAXFRClient_RejectsOutOfZoneAndMalformedStreams covers F217 (a master
// injecting records outside the requested zone) and F218 (RFC 5936 SOA
// framing: open with the apex SOA, close with the same SOA, nothing after).
func TestAXFRClient_RejectsOutOfZoneAndMalformedStreams(t *testing.T) {
	const z = "example.com."
	type RR = *protocol.ResourceRecord
	recs, err := NewAXFRClient(axfrRegMaster(t, [][]RR{{axfrRegSOA(t, z, 5), axfrRegA(t, "www."+z)}, {axfrRegSOA(t, "EXAMPLE.com.", 5)}})).Transfer(z, nil)
	if err != nil || len(recs) != 3 {
		t.Fatalf("well-formed AXFR: records=%d err=%v", len(recs), err)
	}
	for _, c := range []struct {
		name string
		msgs [][]RR
	}{
		{"F217 out-of-zone owner", [][]RR{{axfrRegSOA(t, z, 5), axfrRegA(t, "www.victim.net."), axfrRegSOA(t, z, 5)}}},
		{"F217 string-suffix owner", [][]RR{{axfrRegSOA(t, z, 5), axfrRegA(t, "www.badexample.com."), axfrRegSOA(t, z, 5)}}},
		{"F217 SOA of another zone", [][]RR{{axfrRegSOA(t, "other.org.", 5), axfrRegA(t, "www."+z), axfrRegSOA(t, "other.org.", 5)}}},
		{"F218 serial mismatch", [][]RR{{axfrRegSOA(t, z, 5), axfrRegA(t, "www."+z), axfrRegSOA(t, z, 9)}}},
		{"F218 record after closing SOA", [][]RR{{axfrRegSOA(t, z, 5), axfrRegA(t, "www."+z), axfrRegSOA(t, z, 5), axfrRegA(t, "late."+z)}}},
		{"F218 first record not SOA", [][]RR{{axfrRegA(t, "www."+z), axfrRegSOA(t, z, 5), axfrRegSOA(t, z, 5)}}},
	} {
		if recs, err := NewAXFRClient(axfrRegMaster(t, c.msgs)).Transfer(z, nil); err == nil {
			t.Errorf("%s: accepted %d records, want error", c.name, len(recs))
		}
	}
	// The slave tries IXFR first; its AXFR-style answer must be held to the
	// same zone boundary.
	if recs, err := NewIXFRClient(axfrRegMaster(t, [][]RR{{axfrRegSOA(t, z, 6), axfrRegA(t, "www.victim.net."), axfrRegSOA(t, z, 6)}})).Transfer(z, 5, nil); err == nil {
		t.Errorf("F217 IXFR out-of-zone: accepted %d records, want error", len(recs))
	}
}

// TestAXFRServer_SnapshotConsistentWithConcurrentUpdate covers F219: the SOA
// framing the stream must come from the same zone snapshot as its records.
// Gated: the update holds the zone write lock until the AXFR goroutine is
// parked on the zone lock inside generateAXFRRecords.
func TestAXFRServer_SnapshotConsistentWithConcurrentUpdate(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", TTL: 3600, MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", Type: "A", TTL: 300, RData: "192.0.2.1"}}
	srv := NewAXFRServer(map[string]*zone.Zone{"example.com.": z}, WithAllowList([]string{"127.0.0.0/8"}))
	req := &protocol.Message{Header: protocol.Header{ID: 7, QDCount: 1},
		Questions: []*protocol.Question{{Name: axfrRegName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}}}

	z.Lock()
	type result struct {
		recs []*protocol.ResourceRecord
		err  error
	}
	done := make(chan result, 1)
	go func() {
		recs, _, err := srv.HandleAXFR(req, net.ParseIP("127.0.0.1"))
		done <- result{recs, err}
	}()
	parked := false
	buf := make([]byte, 1<<20)
	for i := 0; i < 2000000 && !parked; i++ {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "generateAXFRRecords") && strings.Contains(g, "RLock") {
				parked = true
				break
			}
		}
		runtime.Gosched()
	}
	if !parked {
		z.Unlock()
		t.Fatal("AXFR goroutine never parked on the zone lock")
	}
	newSOA := *z.SOA
	newSOA.Serial = 2
	z.SOA = &newSOA
	delete(z.Records, "www.example.com.")
	z.Records["new.example.com."] = []zone.Record{{Name: "new.example.com.", Type: "A", TTL: 300, RData: "192.0.2.2"}}
	z.Unlock()

	r := <-done
	if r.err != nil {
		t.Fatalf("HandleAXFR: %v", r.err)
	}
	if len(r.recs) != 3 {
		t.Fatalf("records=%d, want 3", len(r.recs))
	}
	serial := r.recs[0].Data.(*protocol.RDataSOA).Serial
	owner := r.recs[1].Name.String()
	if !((serial == 1 && owner == "www.example.com.") || (serial == 2 && owner == "new.example.com.")) {
		t.Fatalf("torn snapshot: SOA serial %d framing %s", serial, owner)
	}
}
