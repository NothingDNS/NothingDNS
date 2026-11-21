package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// A zone signed online and carrying ZONEMD is transferred with a ZONEMD
// whose digest covers the signed stream (RFC 8976 §3.3.1, §3.5): a
// secondary that verifies ZONEMD accepts it (F868).

func xfrZONEMDMaster(t *testing.T, signed bool) string {
	h := newTestHandler()
	z := xfrTSIGZone(2)
	md, err := zone.ComputeZoneMD(z, zone.ZONEMDSHA384)
	if err != nil {
		t.Fatal(err)
	}
	z.ZONEMD = md
	h.zones["example.com."] = z
	h.RebuildZoneTree()
	if signed {
		h.zoneSigners = map[string]*dnssec.Signer{"example.com.": dnssecRegSigner(t, "example.com.")}
	}
	h.transfer.AXFRServer = transfer.NewAXFRServer(map[string]*zone.Zone{"example.com.": z}, transfer.WithAllowList([]string{"127.0.0.0/8"}))
	h.transfer.IXFRServer = transfer.NewIXFRServer(h.transfer.AXFRServer)
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", h, 1)
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	return srv.Addr().String()
}

// xfrZONEMDCheck recomputes ZONEMD over a received AXFR stream as a secondary does.
func xfrZONEMDCheck(t *testing.T, rrs []*protocol.ResourceRecord) (streamed, recomputed []byte, rrsigs int) {
	var b strings.Builder
	for _, rr := range rrs[:len(rrs)-1] { // without the closing SOA
		if md, ok := rr.Data.(*protocol.RDataZONEMD); ok {
			streamed = md.Digest
		}
		if rr.Type == protocol.TypeRRSIG {
			rrsigs++
		}
		fmt.Fprintf(&b, "%s %d IN %s %s\n", rr.Name.String(), rr.TTL, typeToString(rr.Type), rr.Data.String())
	}
	z, err := zone.ParseFile("received.zone", strings.NewReader(b.String()))
	if err != nil {
		t.Fatalf("parse received stream: %v", err)
	}
	md, err := zone.ComputeZoneMD(z, zone.ZONEMDSHA384)
	if err != nil {
		t.Fatal(err)
	}
	return streamed, md.Hash, rrsigs
}

func TestSignedAXFRZONEMDCoversSignatures(t *testing.T) {
	for _, signed := range []bool{false, true} {
		rrs := xfrSignedAXFR(t, xfrZONEMDMaster(t, signed))
		streamed, recomputed, sigs := xfrZONEMDCheck(t, rrs)
		if signed && sigs == 0 {
			t.Fatal("stream not signed")
		}
		if streamed == nil || !bytes.Equal(streamed, recomputed) {
			t.Fatalf("signed=%v: streamed ZONEMD %x, digest of the stream %x", signed, streamed, recomputed)
		}
	}
}
