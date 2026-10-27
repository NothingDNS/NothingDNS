package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// An ANY answer from a signed zone carries one RRSIG per RRset, exact or
// wildcard; signing the mixed answer as one RRset failed and left it unsigned
// (F745).

func anySignedHandler(t *testing.T) *integratedHandler {
	h := newTestHandler()
	addZoneRecords(t, h, "signed.test.", []zone.Record{
		{Name: "signed.test.", Type: "SOA", TTL: 300, RData: "ns1.signed.test. h.signed.test. 1 3600 600 604800 300"},
		{Name: "signed.test.", Type: "NS", TTL: 300, RData: "ns1.signed.test."},
		{Name: "multi.signed.test.", Type: "A", TTL: 300, RData: "192.0.2.1"},
		{Name: "multi.signed.test.", Type: "TXT", TTL: 300, RData: "\"hello\""},
		{Name: "multi.signed.test.", Type: "MX", TTL: 300, RData: "10 mail.signed.test."},
	})
	h.zoneSigners = map[string]*dnssec.Signer{"signed.test.": dnssecRegSigner(t, "signed.test.")}
	return h
}

func anySignedAsk(t *testing.T, h *integratedHandler, qt uint16) *protocol.Message {
	q := newTestQuery(t, "multi.signed.test.", qt)
	q.SetEDNS0(4096, true)
	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, q)
	if w.msg == nil {
		t.Fatal("no response")
	}
	return w.msg
}

func anySignedSigs(m *protocol.Message) map[uint16]*protocol.RDataRRSIG {
	out := map[uint16]*protocol.RDataRRSIG{}
	for _, rr := range m.Answers {
		if s, ok := rr.Data.(*protocol.RDataRRSIG); ok {
			out[s.TypeCovered] = s
		}
	}
	return out
}

func TestSignedANYAnswerSignsEachRRset(t *testing.T) {
	h := anySignedHandler(t)
	zsk := h.zoneSigners["signed.test."].GetActiveZSKs()[0]
	sigs := anySignedSigs(anySignedAsk(t, h, protocol.TypeANY))
	for _, typ := range []uint16{protocol.TypeA, protocol.TypeTXT, protocol.TypeMX} {
		s := sigs[typ]
		if s == nil || s.KeyTag != zsk.KeyTag || s.Labels != 3 || s.SignerName.String() != "signed.test." {
			t.Fatalf("RRSIG for %s = %+v", typeToString(typ), s)
		}
	}
	// Wildcard ANY: one RRSIG per type, owner = QNAME, labels = wildcard's.
	addZoneRecords(t, h, "wc.test.", []zone.Record{
		{Name: "wc.test.", Type: "SOA", TTL: 300, RData: "ns1.wc.test. h.wc.test. 1 3600 600 604800 300"},
		{Name: "*.wc.test.", Type: "A", TTL: 300, RData: "192.0.2.5"},
		{Name: "*.wc.test.", Type: "TXT", TTL: 300, RData: "\"wild\""},
	})
	h.zoneSigners["wc.test."] = dnssecRegSigner(t, "wc.test.")
	q := newTestQuery(t, "x.wc.test.", protocol.TypeANY)
	q.SetEDNS0(4096, true)
	w := newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, q)
	ws := anySignedSigs(w.msg)
	if len(ws) != 2 || ws[protocol.TypeA] == nil || ws[protocol.TypeTXT] == nil || ws[protocol.TypeA].Labels != 2 {
		t.Fatalf("wildcard ANY RRSIGs = %+v", ws)
	}
	for _, rr := range w.msg.Answers {
		if rr.Type == protocol.TypeRRSIG && rr.Name.String() != "x.wc.test." {
			t.Fatalf("wildcard RRSIG owner %s", rr.Name)
		}
	}
	// DO=0: no RRSIGs.
	q = newTestQuery(t, "multi.signed.test.", protocol.TypeANY)
	w = newCaptureWriter("192.0.2.100", "tcp")
	h.ServeDNS(w, q)
	if dnssecRegCount(w.msg.Answers, protocol.TypeRRSIG) != 0 || len(w.msg.Answers) != 3 {
		t.Fatalf("DO=0 ANY: %d answers", len(w.msg.Answers))
	}
}
