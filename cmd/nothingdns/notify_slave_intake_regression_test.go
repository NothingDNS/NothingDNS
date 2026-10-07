package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// X10 regressions (F387, F388): a NOTIFY for a configured slave zone must be
// authorized by that zone's masters (RFC 1996 §3.10), not by
// transfer.allow_list, and must reach the SlaveManager even though slave
// zones are not in the authoritative zones map. Before X10 a slave-only zone
// answered its master's NOTIFY with NOTAUTH (never refreshed), a pure
// secondary without an allow_list REFUSED its master, and an allow-listed
// non-master was accepted.

type notifyIntakeMaster struct {
	inner server.Handler
	axfr  chan struct{}
}

func (m *notifyIntakeMaster) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	if len(r.Questions) == 1 && r.Questions[0].QType == protocol.TypeAXFR {
		m.axfr <- struct{}{}
	}
	m.inner.ServeDNS(w, r)
}

func newNotifyIntakeMaster(t *testing.T) (string, chan struct{}) {
	t.Helper()
	mh := newTestHandler()
	mh.transfer.AXFRServer = transfer.NewAXFRServer(map[string]*zone.Zone{"example.com.": xfrTSIGZone(0)},
		transfer.WithAllowList([]string{"127.0.0.0/8"}))
	mh.transfer.IXFRServer = transfer.NewIXFRServer(mh.transfer.AXFRServer)
	m := &notifyIntakeMaster{inner: mh, axfr: make(chan struct{}, 64)}
	srv := server.NewTCPServerWithWorkers("127.0.0.1:0", m, 1)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Stop() })
	return srv.Addr().String(), m.axfr
}

func newNotifyIntakeSlave(t *testing.T, yaml string, zones map[string]*zone.Zone) *integratedHandler {
	t.Helper()
	cfg, err := config.UnmarshalYAML(yaml)
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	mgr, err := NewTransferManager(cfg, zones, &sync.RWMutex{}, util.NewLogger(util.ERROR, util.TextFormat, nil))
	if err != nil {
		t.Fatalf("NewTransferManager: %v", err)
	}
	t.Cleanup(mgr.Stop)
	h := newTestHandler()
	h.zones = zones
	r := mgr.Result()
	h.transfer = TransferComponents{AXFRServer: r.AXFRServer, IXFRServer: r.IXFRServer, NotifyHandler: r.NotifyHandler, DDNSHandler: r.DDNSHandler, SlaveManager: r.SlaveManager}
	return h
}

func sendNotifyIntake(t *testing.T, h *integratedHandler, from string, serial uint32) uint8 {
	t.Helper()
	name := mustParseName(t, "example.com.")
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 4242, Flags: protocol.Flags{Opcode: protocol.OpcodeNotify, AA: true}},
		Questions: []*protocol.Question{{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN}},
		Answers: []*protocol.ResourceRecord{{Name: name, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataSOA{Serial: serial, MName: mustParseName(t, "ns1.example.com."), RName: mustParseName(t, "admin.example.com.")}}},
	}
	w := newCaptureWriter(from, "udp")
	h.ServeDNS(w, msg)
	if w.msg == nil {
		t.Fatal("no NOTIFY response")
	}
	return w.msg.Header.Flags.RCODE
}

// awaitAXFR bounds the wait for an AXFR request the test expects to happen.
func awaitAXFR(t *testing.T, ch chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: no AXFR reached the master", what)
	}
}

func TestNOTIFY_SlaveZoneAuthorizedByMasters(t *testing.T) {
	t.Run("slave-only zone with allow-listed master", func(t *testing.T) {
		addr, axfr := newNotifyIntakeMaster(t)
		h := newNotifyIntakeSlave(t, fmt.Sprintf("storage:\n  data_dir: %s\ntransfer:\n  allow_list:\n    - 127.0.0.1/32\nslave_zones:\n  - zone_name: example.com.\n    transfer_type: axfr\n    masters:\n      - %s\n", t.TempDir(), addr),
			map[string]*zone.Zone{})
		awaitAXFR(t, axfr, "initial transfer")
		if rc := sendNotifyIntake(t, h, "127.0.0.1", 3); rc != protocol.RcodeSuccess {
			t.Fatalf("NOTIFY from master rcode=%s, want NOERROR", protocol.RcodeString(int(rc)))
		}
		awaitAXFR(t, axfr, "NOTIFY from master")
	})

	t.Run("pure secondary without allow_list", func(t *testing.T) {
		addr, axfr := newNotifyIntakeMaster(t)
		h := newNotifyIntakeSlave(t, fmt.Sprintf("storage:\n  data_dir: %s\nslave_zones:\n  - zone_name: example.com.\n    transfer_type: axfr\n    masters:\n      - %s\n", t.TempDir(), addr),
			map[string]*zone.Zone{})
		awaitAXFR(t, axfr, "initial transfer")
		if rc := sendNotifyIntake(t, h, "127.0.0.1", 3); rc != protocol.RcodeSuccess {
			t.Fatalf("NOTIFY from master rcode=%s, want NOERROR", protocol.RcodeString(int(rc)))
		}
		awaitAXFR(t, axfr, "NOTIFY from master")
	})

	t.Run("allow-listed non-master refused", func(t *testing.T) {
		addr, axfr := newNotifyIntakeMaster(t)
		h := newNotifyIntakeSlave(t, fmt.Sprintf("storage:\n  data_dir: %s\ntransfer:\n  allow_list:\n    - 127.0.0.0/8\nslave_zones:\n  - zone_name: example.com.\n    transfer_type: axfr\n    masters:\n      - %s\n", t.TempDir(), addr),
			map[string]*zone.Zone{"example.com.": xfrTSIGZone(0)})
		awaitAXFR(t, axfr, "initial transfer")
		if rc := sendNotifyIntake(t, h, "127.0.0.2", 3); rc != protocol.RcodeRefused {
			t.Fatalf("NOTIFY from allow-listed non-master rcode=%s, want REFUSED", protocol.RcodeString(int(rc)))
		}
	})

	t.Run("authoritative zone keeps allow_list authorization", func(t *testing.T) {
		h := newNotifyIntakeSlave(t, fmt.Sprintf("storage:\n  data_dir: %s\ntransfer:\n  allow_list:\n    - 10.0.0.0/8\n", t.TempDir()),
			map[string]*zone.Zone{"example.com.": xfrTSIGZone(0)})
		if rc := sendNotifyIntake(t, h, "10.0.0.1", 3); rc != protocol.RcodeSuccess {
			t.Fatalf("NOTIFY for an authoritative zone rcode=%s, want NOERROR", protocol.RcodeString(int(rc)))
		}
	})
}
