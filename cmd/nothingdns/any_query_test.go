package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func anyTestHandler(t *testing.T) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	addZoneRecords(t, h, "example.com", []zone.Record{
		{Name: "example.com", Type: "SOA", TTL: 3600, Class: "IN",
			RData: "ns1.example.com. admin.example.com. 1 3600 600 86400 300"},
		{Name: "www.example.com", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.10"},
		{Name: "www.example.com", Type: "AAAA", TTL: 300, Class: "IN", RData: "2001:db8::10"},
		{Name: "www.example.com", Type: "TXT", TTL: 300, Class: "IN", RData: "\"hello\""},
	})
	return h
}

// TestANY_OverTCPReturnsAllRecords is the regression for an ANY query being
// answered as NODATA. The zone lookup matched the query type against the
// record type as a string, so QTYPE=ANY matched nothing on an exact name and
// the handler fell through to "name exists, no records of this type" — an
// authoritative NOERROR/empty answer with the SOA, which tells the client the
// name is empty and invites it to cache that for the SOA minimum.
func TestANY_OverTCPReturnsAllRecords(t *testing.T) {
	h := anyTestHandler(t)
	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeANY))

	resp := w.msg
	if resp == nil {
		t.Fatal("no response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) != 3 {
		t.Fatalf("ANY returned %d answer records, want 3 (A, AAAA, TXT)", len(resp.Answers))
	}
	seen := map[uint16]bool{}
	for _, rr := range resp.Answers {
		seen[rr.Type] = true
	}
	for _, want := range []uint16{protocol.TypeA, protocol.TypeAAAA, protocol.TypeTXT} {
		if !seen[want] {
			t.Errorf("ANY response is missing type %d", want)
		}
	}
	if len(resp.Authorities) != 0 {
		t.Errorf("ANY response carries %d authority records; a positive answer needs none",
			len(resp.Authorities))
	}
}

// TestANY_OverUDPStaysTruncated pins the RFC 8482 anti-amplification
// behaviour: ANY over UDP is answered with TC=1 and no records, so the fix
// above cannot become an amplification vector. RFC 6891 §7 also requires the
// OPT record to survive into that truncated response.
func TestANY_OverUDPStaysTruncated(t *testing.T) {
	h := anyTestHandler(t)
	req := newTestQuery(t, "www.example.com.", protocol.TypeANY)
	req.SetEDNS0(1232, false)

	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, req)

	resp := w.msg
	if resp == nil {
		t.Fatal("no response")
	}
	if !resp.Header.Flags.TC {
		t.Error("TC not set on an ANY query over UDP (RFC 8482)")
	}
	if len(resp.Answers) != 0 {
		t.Errorf("ANY over UDP returned %d records; it must force a TCP retry instead",
			len(resp.Answers))
	}
	if resp.GetOPT() == nil {
		t.Error("truncated response to an EDNS requestor has no OPT record (RFC 6891 §7)")
	}
}

func TestANY_NonExistentNameStillNXDOMAIN(t *testing.T) {
	h := anyTestHandler(t)
	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, newTestQuery(t, "nothing.example.com.", protocol.TypeANY))

	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("ANY for a missing name should be NXDOMAIN, got %+v", w.msg)
	}
}
