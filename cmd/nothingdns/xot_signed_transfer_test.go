package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// A zone signed online is transferred signed over XoT too (RFC 9103
// listener), like AXFR over TCP (F751): DNSKEY, RRSIGs and the NSEC chain,
// and an IXFR sends the full signed zone instead of an unsigned diff (F869).

func xotSignedXfr(t *testing.T, addr string, qtype uint16) []*protocol.ResourceRecord {
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	q, _ := protocol.NewQuery(7, "example.com.", qtype)
	if qtype == protocol.TypeIXFR {
		soa, _ := protocol.NewResourceRecord("example.com.", protocol.TypeSOA, protocol.ClassIN, 300,
			&protocol.RDataSOA{MName: xfrName(t, "ns1.example.com."), RName: xfrName(t, "admin.example.com."), Serial: 1})
		q.Authorities = append(q.Authorities, soa)
		q.Header.NSCount = 1
	}
	buf := make([]byte, 1024)
	n, _ := q.Pack(buf[2:])
	binary.BigEndian.PutUint16(buf, uint16(n))
	if _, err := c.Write(buf[:n+2]); err != nil {
		t.Fatal(err)
	}
	var all []*protocol.ResourceRecord
	for {
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
		// A full-zone stream (AXFR, or the IXFR a signed zone answers
		// with) ends at its second SOA.
		if len(all) > 1 && all[len(all)-1].Type == protocol.TypeSOA && xfrCount(all, protocol.TypeSOA) == 2 && all[1].Type != protocol.TypeSOA {
			return all
		}
	}
}

func TestXoTTransfersOnlineSignedZoneSigned(t *testing.T) {
	h, addr := zwXoTFixture(t)
	h.zoneSignersMu.Lock()
	h.zoneSigners = map[string]*dnssec.Signer{"example.com.": dnssecRegSigner(t, "example.com.")}
	h.zoneSignersMu.Unlock()
	for _, qt := range []uint16{protocol.TypeAXFR, protocol.TypeIXFR} {
		rrs := xotSignedXfr(t, addr, qt)
		if xfrCount(rrs, protocol.TypeSOA) < 2 {
			t.Fatalf("%s over XoT incomplete: %d records", typeToString(qt), len(rrs))
		}
		if xfrCount(rrs, protocol.TypeDNSKEY) == 0 || xfrCount(rrs, protocol.TypeRRSIG) == 0 || xfrCount(rrs, protocol.TypeNSEC) == 0 {
			t.Fatalf("%s over XoT unsigned: DNSKEY=%d RRSIG=%d NSEC=%d", typeToString(qt),
				xfrCount(rrs, protocol.TypeDNSKEY), xfrCount(rrs, protocol.TypeRRSIG), xfrCount(rrs, protocol.TypeNSEC))
		}
	}
}
