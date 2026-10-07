package main

// X13 regressions (F402, F403): handler.zones is a routing source and the
// AXFR/IXFR/NOTIFY/DDNS zones map. Zone-manager deletions (API direct mode,
// Raft delete_zone, Raft snapshot restore — at runtime and at boot) left the
// config zone in it, so the node kept answering AA for and transferring a
// deleted zone; a snapshot-replaced zone was transferred with its stale
// pre-restore contents.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

type zoneDelMultiWriter struct {
	client *server.ClientInfo
	msgs   []*protocol.Message
}

func (w *zoneDelMultiWriter) Write(m *protocol.Message) (int, error) {
	if m != nil {
		w.msgs = append(w.msgs, m.Copy())
	}
	return 0, nil
}
func (w *zoneDelMultiWriter) ClientInfo() *server.ClientInfo { return w.client }
func (w *zoneDelMultiWriter) MaxSize() int                   { return 65535 }

const zoneDelZone = "$ORIGIN %[1]s\n$TTL 300\n@ IN SOA ns1.%[1]s admin.%[1]s %[2]d 3600 600 86400 300\n@ IN NS ns1.%[1]s\nns1 IN A 192.0.2.53\nwww IN A %[3]s\n"

// zoneDelBoot builds the handler like runWithContext: zones from NewZoneManager,
// the same map handed to NewTransferManager, hook composed after.
func zoneDelBoot(t *testing.T) (*integratedHandler, *zone.Manager) {
	t.Helper()
	dir := t.TempDir()
	files := []string{}
	for _, z := range []struct{ origin, ip string }{{"example.com.", "192.0.2.2"}, {"keep.test.", "192.0.2.7"}} {
		p := filepath.Join(dir, z.origin+"zone")
		if err := os.WriteFile(p, []byte(fmt.Sprintf(zoneDelZone, z.origin, 1, z.ip)), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	cfg, err := config.UnmarshalYAML(fmt.Sprintf("storage:\n  data_dir: %s\nzones:\n  - %s\n  - %s\ntransfer:\n  allow_list:\n    - 127.0.0.0/8\n", filepath.Join(dir, "data"), files[0], files[1]))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	logger := util.NewLogger(util.ERROR, util.TextFormat, nil)
	zm, err := NewZoneManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewZoneManager: %v", err)
	}
	zones := zm.Zones()
	tm, err := NewTransferManager(cfg, zones, nil, logger)
	if err != nil {
		t.Fatalf("NewTransferManager: %v", err)
	}
	t.Cleanup(tm.Stop)
	h := newTestHandler()
	h.zones = zones
	h.zoneManager = zm.Manager()
	h.kvPersistence = zm.KVPersistence()
	r := tm.Result()
	h.transfer = TransferComponents{AXFRServer: r.AXFRServer, IXFRServer: r.IXFRServer, NotifyHandler: r.NotifyHandler, DDNSHandler: r.DDNSHandler, SlaveManager: r.SlaveManager}
	h.zoneProvider = NewMultiZoneProvider(zones, h.zoneManager, h.kvPersistence, zone.BuildRadixTree(zones)).withSlaveZones(r.SlaveManager)
	prev := h.zoneManager.MutationHook()
	h.zoneManager.SetMutationHook(func(name string, deleted bool) {
		if prev != nil {
			prev(name, deleted)
		}
		h.RebuildZoneTree()
	})
	h.RebuildZoneTree()
	tm.SetZonesMu(&h.zonesMu)
	return h, h.zoneManager
}

func zoneDelQuery(h *integratedHandler, qname string) string {
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

// zoneDelAXFR returns "rcode=… soa=<serial> www=<addr>" summarising the transfer.
func zoneDelAXFR(h *integratedHandler, origin string) string {
	w := &zoneDelMultiWriter{client: newCaptureWriter("127.0.0.1", "tcp").client}
	q, _ := protocol.NewQuery(8, origin, protocol.TypeAXFR)
	h.ServeDNS(w, q)
	if len(w.msgs) == 0 {
		return "no response"
	}
	s := "rcode=" + protocol.RcodeString(int(w.msgs[0].Header.Flags.RCODE))
	for _, m := range w.msgs {
		for _, rr := range m.Answers {
			switch d := rr.Data.(type) {
			case *protocol.RDataSOA:
				if !strings.Contains(s, " soa=") {
					s += fmt.Sprintf(" soa=%d", d.Serial)
				}
			case *protocol.RDataA:
				if strings.HasPrefix(strings.ToLower(rr.Name.String()), "www.") {
					s += " www=" + d.String()
				}
			}
		}
	}
	return s
}

// zoneDelTCPAXFR sends an AXFR over TCP and returns the rcode of the first reply.
func zoneDelTCPAXFR(addr, origin string) string {
	q, _ := protocol.NewQuery(11, origin, protocol.TypeAXFR)
	buf := make([]byte, 512)
	n, err := q.Pack(buf)
	if err != nil {
		return "pack: " + err.Error()
	}
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return "dial: " + err.Error()
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	out := make([]byte, 2+n)
	binary.BigEndian.PutUint16(out, uint16(n))
	copy(out[2:], buf[:n])
	if _, err := c.Write(out); err != nil {
		return "write: " + err.Error()
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return "read: " + err.Error()
	}
	rb := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, rb); err != nil {
		return "read: " + err.Error()
	}
	m, err := protocol.UnpackMessage(rb)
	if err != nil {
		return "unpack: " + err.Error()
	}
	return fmt.Sprintf("rcode=%s answers=%d", protocol.RcodeString(int(m.Header.Flags.RCODE)), len(m.Answers))
}

func TestZoneDelete_RuntimeDeleteAndReplace(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		h, zm := zoneDelBoot(t)
		if got := zoneDelAXFR(h, "example.com."); got != "rcode=NOERROR soa=1 www=192.0.2.2" {
			t.Fatalf("setup AXFR: %s", got)
		}
		// API delete (direct mode) and Raft apply of delete_zone both call
		// zone.Manager.DeleteZone; the mutation hook rebuilds routing.
		if err := zm.DeleteZone("example.com."); err != nil {
			t.Fatalf("DeleteZone: %v", err)
		}
		if got := zoneDelQuery(h, "www.keep.test."); got != "rcode=NOERROR aa=true 192.0.2.7" {
			t.Fatalf("control zone: %s", got)
		}
		if got := zoneDelQuery(h, "www.example.com."); strings.Contains(got, "aa=true") {
			t.Errorf("F402: deleted zone still answered authoritatively: %q", got)
		}
		if got := zoneDelAXFR(h, "example.com."); !strings.HasPrefix(got, "rcode=REFUSED") {
			t.Errorf("F402: deleted zone still transferable: %q", got)
		}
		h.zonesMu.RLock()
		_, inMap := h.zones["example.com."]
		h.zonesMu.RUnlock()
		if inMap {
			t.Errorf("F402: deleted zone left in the shared AXFR/NOTIFY/DDNS zones map")
		}
	})
	t.Run("replace", func(t *testing.T) {
		h, zm := zoneDelBoot(t)
		repl, err := zone.ParseFile("repl.zone", strings.NewReader(fmt.Sprintf(zoneDelZone, "example.com.", 5, "192.0.2.99")))
		if err != nil {
			t.Fatal(err)
		}
		// cluster.restoreZones: LoadZone + NotifyMutated.
		zm.LoadZone(repl, "")
		zm.NotifyMutated("example.com.")
		if got := zoneDelQuery(h, "www.example.com."); got != "rcode=NOERROR aa=true 192.0.2.99" {
			t.Fatalf("control query: %s", got)
		}
		if got := zoneDelAXFR(h, "example.com."); got != "rcode=NOERROR soa=5 www=192.0.2.99" {
			t.Errorf("F403: AXFR of replaced zone = %q, want the restored data", got)
		}
	})
}

func TestZoneDelete_BootSnapshotDeletionNotServedOrTransferred(t *testing.T) {
	dir := t.TempDir()
	zoneFile := filepath.Join(dir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(bootRestoreZone, "example.com.", "example.com.", "example.com.", 1, "example.com.", "192.0.2.2")), 0o644); err != nil {
		t.Fatal(err)
	}
	raftDir := filepath.Join(dir, "raft")
	snaps, err := raft.NewSnapshotter(raftDir + "/snapshots")
	if err != nil {
		t.Fatal(err)
	}
	// The cluster deleted example.com. before this node's restart: the
	// snapshot holds only snaponly.test.
	payload, _ := json.Marshal(map[string]string{
		"snaponly.test.": fmt.Sprintf(bootRestoreZone, "snaponly.test.", "snaponly.test.", "snaponly.test.", 5, "snaponly.test.", "192.0.2.77"),
	})
	if err := snaps.Save(&raft.Snapshot{Index: 5, Term: 1, LastIndex: 5, LastTerm: 1, Data: payload}); err != nil {
		t.Fatal(err)
	}
	dnsPort := bootRestoreFreePort(t, "udp")
	raftPort := bootRestoreFreePort(t, "tcp")
	yaml := fmt.Sprintf(`server:
  udp_bind:
    - 127.0.0.1:%d
  tcp_bind:
    - 127.0.0.1:%d
logging:
  level: error
metrics:
  enabled: false
storage:
  data_dir: %s
zones:
  - %s
transfer:
  allow_list:
    - 127.0.0.0/8
upstream:
  servers:
    - 127.0.0.1:1
resolution:
  authoritative_only: true
cluster:
  enabled: true
  node_id: n1
  bind_addr: 127.0.0.1
  gossip_port: %d
  consensus_mode: raft
  data_dir: %s
  peers:
    - node_id: n1
      addr: 127.0.0.1:%d
  encryption_key: 7f3a9c1e5b2d8f4a6c0e9b3d7a1f5c8e2b6d0a4f8c3e7b1d5a9f2c6e0b4d8a3f
`, dnsPort, dnsPort, filepath.Join(dir, "data"), zoneFile, raftPort, raftDir, raftPort)
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	sigCh := make(chan os.Signal, 1)
	t.Cleanup(installFakeSignalHandler(sigCh))
	done := make(chan error, 1)
	go func() { done <- runWithContext(context.Background(), cfg) }()
	exited := false
	t.Cleanup(func() {
		if exited {
			return
		}
		sigCh <- syscall.SIGTERM
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Errorf("server did not stop")
		}
	})
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	ctl := ""
	deadline := time.Now().Add(15 * time.Second)
	for {
		ctl = bootRestoreQuery(addr, "www.snaponly.test.")
		if ctl == "rcode=NOERROR aa=true 192.0.2.77" || time.Now().After(deadline) {
			break
		}
		select {
		case err := <-done:
			exited = true
			t.Fatalf("server exited: %v", err)
		case <-time.After(20 * time.Millisecond): // bounded wait for boot only
		}
	}
	if ctl != "rcode=NOERROR aa=true 192.0.2.77" {
		t.Fatalf("control failed (server not up?)")
	}
	if q := bootRestoreQuery(addr, "www.example.com."); q != "rcode=REFUSED aa=false" {
		t.Errorf("F402 boot: config zone deleted by the snapshot still answered: %q, want rcode=REFUSED aa=false", q)
	}
	if ax := zoneDelTCPAXFR(addr, "example.com."); ax != "rcode=REFUSED answers=0" {
		t.Errorf("F402 boot: AXFR of the deleted config zone: %q, want rcode=REFUSED answers=0", ax)
	}
}
