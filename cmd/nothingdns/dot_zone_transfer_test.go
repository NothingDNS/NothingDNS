package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func newDoTTransferTestHandler() *integratedHandler {
	h := newTestHandler()
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Name: "example.com.", MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 2}
	z.Records["example.com."] = []zone.Record{
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2 3600 600 86400 300"},
		{Name: "example.com.", TTL: 300, Class: "IN", Type: "NS", RData: "ns1.example.com."},
	}
	zones := map[string]*zone.Zone{"example.com.": z}
	h.transfer.AXFRServer = transfer.NewAXFRServer(zones, transfer.WithAllowList([]string{"10.0.0.0/8"}))
	h.transfer.IXFRServer = transfer.NewIXFRServer(h.transfer.AXFRServer)
	return h
}

func TestDoTZoneTransfersUseStreamPath(t *testing.T) {
	t.Run("AXFR", func(t *testing.T) {
		h := newDoTTransferTestHandler()
		w := newCaptureWriter("10.0.0.1", "dot")
		q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeAXFR, QClass: protocol.ClassIN}
		h.handleAXFR(w, newTestQuery(t, "example.com.", protocol.TypeAXFR), q)
		if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
			t.Fatalf("authorized DoT AXFR failed: %#v", w.msg)
		}
	})

	t.Run("IXFR fallback", func(t *testing.T) {
		h := newDoTTransferTestHandler()
		w := newCaptureWriter("10.0.0.1", "dot")
		q := &protocol.Question{Name: mustParseName(t, "example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN}
		msg := newTestQuery(t, "example.com.", protocol.TypeIXFR)
		msg.Authorities = []*protocol.ResourceRecord{{
			Name: mustParseName(t, "example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataSOA{Serial: 1, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")},
		}}
		h.handleIXFR(w, msg, q)
		if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeSuccess {
			t.Fatalf("authorized DoT IXFR failed: %#v", w.msg)
		}
	})
}

func TestZoneTransferRejectsDatagramTransports(t *testing.T) {
	for _, name := range []string{"udp", "doq", "doh"} {
		if isZoneTransferStreamProtocol(name) {
			t.Errorf("%s unexpectedly accepted as a multi-message transfer stream", name)
		}
	}
	for _, name := range []string{"tcp", "dot"} {
		if !isZoneTransferStreamProtocol(name) {
			t.Errorf("%s unexpectedly rejected as a transfer stream", name)
		}
	}
}
