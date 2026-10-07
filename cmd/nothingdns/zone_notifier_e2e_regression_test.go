package main

// F547 regression (P2-E2): a primary must send NOTIFY (RFC 1996) to its
// configured secondaries after a zone serial change. Boots the real server
// (runWithContext) with transfer.also_notify pointing at a loopback UDP
// listener, bumps the zone serial on disk, reloads via SIGHUP, confirms the
// new serial is served (control), then waits for a NOTIFY datagram.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

const notifyE2EZone = "$ORIGIN example.com.\n$TTL 300\n@ IN SOA ns1.example.com. admin.example.com. %d 3600 600 86400 300\n@ IN NS ns1.example.com.\nns1 IN A 192.0.2.53\n"

func notifyE2ESOASerial(addr string) (uint32, error) {
	q, _ := protocol.NewQuery(7, "example.com.", protocol.TypeSOA)
	buf := make([]byte, 512)
	n, err := q.Pack(buf)
	if err != nil {
		return 0, err
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Write(buf[:n]); err != nil {
		return 0, err
	}
	rb := make([]byte, 4096)
	rn, err := c.Read(rb)
	if err != nil {
		return 0, err
	}
	m, err := protocol.UnpackMessage(rb[:rn])
	if err != nil {
		return 0, err
	}
	for _, rr := range m.Answers {
		if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
			return soa.Serial, nil
		}
	}
	return 0, fmt.Errorf("no SOA in answer (rcode %d)", m.Header.Flags.RCODE)
}

func TestF547_PrimarySendsNOTIFYAfterReload(t *testing.T) {
	dir := t.TempDir()
	zoneFile := filepath.Join(dir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	secondary, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer secondary.Close()
	dnsPort := bootRestoreFreePort(t, "udp")
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
  also_notify:
    - %s
`, dnsPort, dnsPort, filepath.Join(dir, "data"), zoneFile, secondary.LocalAddr().String())
	cfgPath := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := *configPath
	*configPath = cfgPath
	t.Cleanup(func() { *configPath = prev })
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	sigCh := make(chan os.Signal, 1)
	t.Cleanup(installFakeSignalHandler(sigCh))
	done := make(chan error, 1)
	go func() { done <- runWithContext(context.Background(), cfg) }()
	t.Cleanup(func() {
		sigCh <- syscall.SIGTERM
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Errorf("server did not stop")
		}
	})
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	waitSerial := func(want uint32) bool {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if s, err := notifyE2ESOASerial(addr); err == nil && s == want {
				return true
			}
			time.Sleep(50 * time.Millisecond)
		}
		return false
	}
	if !waitSerial(1) {
		t.Fatal("setup: server never served serial 1")
	}

	// Serial change: new zone file contents + SIGHUP reload.
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 2)), 0o644); err != nil {
		t.Fatal(err)
	}
	sigCh <- syscall.SIGHUP
	if !waitSerial(2) {
		t.Fatal("setup: SIGHUP reload did not take effect")
	}

	_ = secondary.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	got := "no datagram"
	for {
		n, _, err := secondary.ReadFrom(buf)
		if err != nil {
			break
		}
		m, err := protocol.UnpackMessage(buf[:n])
		if err != nil {
			continue
		}
		if m.Header.Flags.Opcode == protocol.OpcodeNotify && len(m.Answers) > 0 {
			if soa, ok := m.Answers[0].Data.(*protocol.RDataSOA); ok && soa.Serial == 2 {
				got = fmt.Sprintf("NOTIFY example.com. serial=%d", soa.Serial)
				break
			}
		}
	}
	if got == "no datagram" {
		t.Fatalf("no NOTIFY with serial 2 reached the also_notify target after the serial change")
	}
}
