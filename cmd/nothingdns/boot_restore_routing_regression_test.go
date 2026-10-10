package main

// X12 regression (F399): runWithContext starts the cluster, and with it the
// boot-time Raft snapshot restore into the zone manager, before the handler's
// RebuildZoneTree mutation hook is installed. Without a rebuild after the
// hook, the handler's static provider kept the pre-restore config zone
// objects and served the replaced data until the next zone mutation.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// bootRestoreFreePort returns a loopback port that is free on both UDP and
// TCP: the server binds both on the port a test picks, and a port that was
// only probed on one network could be taken on the other (EADDRINUSE at the
// server's TCP bind, seen in several boot tests). The probe still releases
// the port before returning, so a later steal remains possible.
func bootRestoreFreePort(t *testing.T, network string) int {
	t.Helper()
	for attempt := 0; attempt < 50; attempt++ {
		var port int
		if network == "udp" {
			c, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port = c.LocalAddr().(*net.UDPAddr).Port
			c.Close()
		} else {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port = l.Addr().(*net.TCPAddr).Port
			l.Close()
		}
		if bootRestorePortFreeOnBoth(port) {
			return port
		}
	}
	t.Fatal("no loopback port free on both UDP and TCP")
	return 0
}

// bootRestorePortFreeOnBoth reports whether port can be bound on UDP and TCP.
func bootRestorePortFreeOnBoth(port int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	defer c.Close()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func bootRestoreQuery(addr, qname string) string {
	q, _ := protocol.NewQuery(9, qname, protocol.TypeA)
	buf := make([]byte, 512)
	n, err := q.Pack(buf)
	if err != nil {
		return "pack: " + err.Error()
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		return "dial: " + err.Error()
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Write(buf[:n]); err != nil {
		return "write: " + err.Error()
	}
	rb := make([]byte, 4096)
	rn, err := c.Read(rb)
	if err != nil {
		return "read: " + err.Error()
	}
	m, err := protocol.UnpackMessage(rb[:rn])
	if err != nil {
		return "unpack: " + err.Error()
	}
	s := fmt.Sprintf("rcode=%s aa=%v", protocol.RcodeString(int(m.Header.Flags.RCODE)), m.Header.Flags.AA)
	for _, rr := range m.Answers {
		s += " " + rr.Data.String()
	}
	return s
}

const bootRestoreZone = "$ORIGIN %s\n$TTL 300\n@ IN SOA ns1.%s admin.%s %d 3600 600 86400 300\n@ IN NS ns1.%s\nns1 IN A 192.0.2.53\nwww IN A %s\n"

func TestBootSnapshotRestore_RoutesRestoredZones(t *testing.T) {
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
	payload, _ := json.Marshal(map[string]string{
		"example.com.":   fmt.Sprintf(bootRestoreZone, "example.com.", "example.com.", "example.com.", 5, "example.com.", "192.0.2.99"),
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
	want := "rcode=NOERROR aa=true 192.0.2.99"
	got := bootRestoreQuery(addr, "www.example.com.")
	if got != want {
		t.Fatalf("config zone replaced by boot snapshot: got %q, want %q", got, want)
	}
}
