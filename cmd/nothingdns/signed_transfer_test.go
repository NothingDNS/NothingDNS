package main

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A zone signed online is transferred signed: AXFR carries DNSKEY, an RRSIG
// per authoritative RRset (none for delegation NS/glue) and a closed NSEC
// chain; an IXFR that would be a diff sends the full signed zone; an
// unsigned zone transfers as before (F751).

func xfrSignedAXFR(t *testing.T, addr string) []*protocol.ResourceRecord {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	q, _ := protocol.NewQuery(7, "example.com.", protocol.TypeAXFR)
	buf := make([]byte, 512)
	n, _ := q.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf, uint16(n))
	if _, err := c.Write(buf[:n+2]); err != nil {
		t.Fatal(err)
	}
	var all []*protocol.ResourceRecord
	soas := 0
	for soas < 2 {
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			t.Fatalf("read: %v (after %d records)", err, len(all))
		}
		body := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, body); err != nil {
			t.Fatal(err)
		}
		m, err := protocol.UnpackMessage(body)
		if err != nil {
			t.Fatal(err)
		}
		if m.Header.Flags.RCODE != 0 {
			t.Fatalf("AXFR rcode %d", m.Header.Flags.RCODE)
		}
		for _, rr := range m.Answers {
			all = append(all, rr)
			if rr.Type == protocol.TypeSOA {
				soas++
			}
		}
	}
	return all
}

func xfrCount(rrs []*protocol.ResourceRecord, typ uint16) int {
	n := 0
	for _, rr := range rrs {
		if rr.Type == typ {
			n++
		}
	}
	return n
}

func xfrSignedMaster(t *testing.T, signed bool) string {
	h := newTestHandler()
	z := xfrTSIGZone(2)
	z.Records["child.example.com."] = []zone.Record{{Name: "child.example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns.child.example.com."}}
	z.Records["ns.child.example.com."] = []zone.Record{{Name: "ns.child.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.99"}}
	h.zones["example.com."] = z
	h.RebuildZoneTree()
	if signed {
		h.zoneSigners = map[string]*dnssec.Signer{"example.com.": dnssecRegSigner(t, "example.com.")}
	}
	h.transfer.AXFRServer = transfer.NewAXFRServer(map[string]*zone.Zone{"example.com.": z}, transfer.WithAllowList([]string{"127.0.0.0/8"}))
	h.transfer.IXFRServer = transfer.NewIXFRServer(h.transfer.AXFRServer)
	h.transfer.IXFRServer.RecordChange("example.com.", 1, 2,
		[]zone.RecordChange{{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.2"}},
		[]zone.RecordChange{{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1"}})
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", h, 1)
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	return srv.Addr().String()
}

func xfrIXFRFrom(t *testing.T, addr string, serial uint32) []*protocol.ResourceRecord {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	q, _ := protocol.NewQuery(9, "example.com.", protocol.TypeIXFR)
	soa, _ := protocol.NewResourceRecord("example.com.", protocol.TypeSOA, protocol.ClassIN, 300,
		&protocol.RDataSOA{MName: xfrName(t, "ns1.example.com."), RName: xfrName(t, "admin.example.com."), Serial: serial})
	q.Authorities = append(q.Authorities, soa)
	q.Header.NSCount = 1
	buf := make([]byte, 1024)
	n, err := q.Pack(buf[2:])
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(buf, uint16(n))
	if _, err := c.Write(buf[:n+2]); err != nil {
		t.Fatal(err)
	}
	var all []*protocol.ResourceRecord
	for {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return all
		}
		body := make([]byte, binary.BigEndian.Uint16(lb[:]))
		if _, err := io.ReadFull(c, body); err != nil {
			return all
		}
		m, err := protocol.UnpackMessage(body)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, m.Answers...)
	}
}

func xfrName(t *testing.T, s string) *protocol.Name {
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestSignedZoneTransfersSigned(t *testing.T) {
	addr := xfrSignedMaster(t, true)
	rrs := xfrSignedAXFR(t, addr)
	// Framing: SOA ... SOA, no other SOA, SOA signed.
	if rrs[0].Type != protocol.TypeSOA || rrs[len(rrs)-1].Type != protocol.TypeSOA || xfrCount(rrs, protocol.TypeSOA) != 2 {
		t.Fatal("stream not framed by exactly two SOAs")
	}
	covered := map[string]bool{}
	nsecNext := map[string]string{}
	owners := map[string]bool{}
	for _, rr := range rrs {
		owner := strings.ToLower(rr.Name.String())
		switch d := rr.Data.(type) {
		case *protocol.RDataRRSIG:
			covered[owner+"/"+typeToString(d.TypeCovered)] = true
		case *protocol.RDataNSEC:
			nsecNext[owner] = strings.ToLower(d.NextDomain.String())
		default:
			owners[owner] = true
		}
	}
	for _, want := range []string{"example.com./SOA", "example.com./NS", "example.com./DNSKEY", "www.example.com./A", "ns1.example.com./A"} {
		if !covered[want] {
			t.Fatalf("no RRSIG for %s", want)
		}
	}
	for _, unsigned := range []string{"child.example.com./NS", "ns.child.example.com./A"} {
		if covered[unsigned] {
			t.Fatalf("delegation data %s signed", unsigned)
		}
	}
	// NSEC chain is one closed ring.
	start, cur, steps := "example.com.", "example.com.", 0
	for {
		next, ok := nsecNext[cur]
		if !ok {
			t.Fatalf("NSEC chain broken at %s (%v)", cur, nsecNext)
		}
		cur, steps = next, steps+1
		if cur == start || steps > len(nsecNext) {
			break
		}
	}
	if cur != start || steps != len(nsecNext) {
		t.Fatalf("NSEC chain not a ring: %d steps, %d NSECs", steps, len(nsecNext))
	}

	// IXFR from an old serial: the full signed zone; from the current one: SOA only.
	if full := xfrIXFRFrom(t, addr, 1); xfrCount(full, protocol.TypeDNSKEY) == 0 || xfrCount(full, protocol.TypeRRSIG) == 0 {
		t.Fatalf("IXFR of a signed zone: %d records, no signatures", len(full))
	}
	if cur := xfrIXFRFrom(t, addr, 2); len(cur) != 1 || cur[0].Type != protocol.TypeSOA {
		t.Fatalf("up-to-date IXFR: %d records", len(cur))
	}

	// An unsigned zone transfers unsigned, as before.
	plain := xfrSignedAXFR(t, xfrSignedMaster(t, false))
	if xfrCount(plain, protocol.TypeRRSIG) != 0 || xfrCount(plain, protocol.TypeDNSKEY) != 0 {
		t.Fatal("unsigned zone transferred with DNSSEC records")
	}
}
