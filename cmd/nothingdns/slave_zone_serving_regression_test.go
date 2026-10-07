package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// X12 regressions (F397, F398): zone data transferred into a slave zone must
// be served authoritatively. Slave zones live only in the SlaveManager; before
// X12 they were not a zone-provider source (every query for a secondary's
// zone fell through to upstream/SERVFAIL) and the CNAME stage only searched
// the static zones map.

type slaveServingMaster struct {
	axfr *transfer.AXFRServer
	addr string
}

func newSlaveServingMaster(t *testing.T, z *zone.Zone) *slaveServingMaster {
	t.Helper()
	mh := newTestHandler()
	mh.transfer.AXFRServer = transfer.NewAXFRServer(map[string]*zone.Zone{"example.com.": z}, transfer.WithAllowList([]string{"127.0.0.0/8"}))
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", mh, 1)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	return &slaveServingMaster{axfr: mh.transfer.AXFRServer, addr: srv.Addr().String()}
}

func slaveServingZone(serial uint32, www string) *zone.Zone {
	z := xfrTSIGZone(0)
	z.SOA.Serial = serial
	z.Records["www.example.com."] = []zone.Record{{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: www}}
	z.Records["alias.example.com."] = []zone.Record{{Name: "alias.example.com.", TTL: 300, Class: "IN", Type: "CNAME", RData: "www.example.com."}}
	return z
}

// newServingSlave builds a slave handler the way main.go does: transfer
// components wired, routing built by RebuildZoneTree (main.go + mutation hook).
func newServingSlave(t *testing.T, master string) *integratedHandler {
	t.Helper()
	h := newNotifyIntakeSlave(t, fmt.Sprintf("storage:\n  data_dir: %s\nslave_zones:\n  - zone_name: example.com.\n    transfer_type: axfr\n    masters:\n      - %s\n", t.TempDir(), master),
		map[string]*zone.Zone{})
	h.RebuildZoneTree()
	return h
}

// awaitSlaveSerial bounds the wait for a transfer the test expects to complete.
func awaitSlaveSerial(t *testing.T, h *integratedHandler, serial uint32) {
	t.Helper()
	sz := h.transfer.SlaveManager.GetSlaveZone("example.com.")
	deadline := time.Now().Add(10 * time.Second)
	for sz.GetLastSerial() != serial {
		if time.Now().After(deadline) {
			t.Fatalf("slave zone never reached serial %d (at %d)", serial, sz.GetLastSerial())
		}
		time.Sleep(time.Millisecond)
	}
}

func slaveServingAnswer(h *integratedHandler, qname string) string {
	w := newCaptureWriter("127.0.0.1", "udp")
	q, _ := protocol.NewQuery(7, qname, protocol.TypeA)
	h.ServeDNS(w, q)
	if w.msg == nil {
		return "no response"
	}
	s := fmt.Sprintf("rcode=%s aa=%v", protocol.RcodeString(int(w.msg.Header.Flags.RCODE)), w.msg.Header.Flags.AA)
	for _, rr := range w.msg.Answers {
		s += " " + rr.Data.String()
	}
	return s
}

func TestSlaveZone_ServedAfterTransfer(t *testing.T) {
	m := newSlaveServingMaster(t, slaveServingZone(2, "192.0.2.2"))
	h := newServingSlave(t, m.addr)
	awaitSlaveSerial(t, h, 2)

	if got, want := slaveServingAnswer(h, "www.example.com."), "rcode=NOERROR aa=true 192.0.2.2"; got != want {
		t.Fatalf("F397 transferred data: got %q, want %q", got, want)
	}
	if got, want := slaveServingAnswer(h, "nope.example.com."), "rcode=NXDOMAIN aa=true"; got != want {
		t.Fatalf("F397 in-zone NXDOMAIN: got %q, want %q", got, want)
	}
	if got, want := slaveServingAnswer(h, "alias.example.com."), "rcode=NOERROR aa=true www.example.com. 192.0.2.2"; got != want {
		t.Fatalf("F398 in-zone CNAME: got %q, want %q", got, want)
	}

	// A cached (e.g. pre-transfer upstream) answer must not shadow zone data.
	stale, _ := protocol.NewQuery(7, "www.example.com.", protocol.TypeA)
	stale.Header.Flags.QR = true
	stale.Answers = []*protocol.ResourceRecord{{Name: mustParseName(t, "www.example.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{203, 0, 113, 9}}}}
	h.cache.Set(cache.MakeKey("www.example.com.", protocol.TypeA, false), stale, 300)

	// NOTIFY from the master → new transfer → new data visible without a rebuild.
	m.axfr.AddZone(slaveServingZone(3, "192.0.2.3"))
	if rc := sendNotifyIntake(t, h, "127.0.0.1", 3); rc != protocol.RcodeSuccess {
		t.Fatalf("NOTIFY rcode=%s", protocol.RcodeString(int(rc)))
	}
	awaitSlaveSerial(t, h, 3)
	if got, want := slaveServingAnswer(h, "www.example.com."), "rcode=NOERROR aa=true 192.0.2.3"; got != want {
		t.Fatalf("after re-transfer: got %q, want %q", got, want)
	}

	// SIGHUP zone reload rebuilds routing; slave zones must survive it.
	applyConfiguredZoneFiles(h, zone.NewManager(), map[string]string{}, nil, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if got, want := slaveServingAnswer(h, "www.example.com."), "rcode=NOERROR aa=true 192.0.2.3"; got != want {
		t.Fatalf("after zone reload: got %q, want %q", got, want)
	}
}

func TestSlaveZone_NotServedBeforeFirstTransfer(t *testing.T) {
	sm := transfer.NewSlaveManager(nil)
	t.Cleanup(sm.Stop)
	// Port 1 on loopback refuses; the zone stays without SOA (never transferred).
	if err := sm.AddSlaveZone(transfer.SlaveZoneConfig{ZoneName: "example.com.", Masters: []string{"127.0.0.1:1"}, TransferType: "axfr"}); err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()
	h.transfer.SlaveManager = sm
	h.RebuildZoneTree()
	if m := h.zoneProvider.FindZones("www.example.com."); len(m) != 0 {
		t.Fatalf("untransferred slave zone routed: %v", m)
	}
	if got := slaveServingAnswer(h, "www.example.com."); got == "rcode=NXDOMAIN aa=true" {
		t.Fatalf("empty slave zone answered authoritatively: %q", got)
	}
}
