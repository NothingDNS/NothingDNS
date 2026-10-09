package main

// F567 / F568 regressions (P2-G2): SIGHUP reload applies transfer.also_notify
// and transfer.notify_key, and the primary sends NOTIFY for every zone once
// after startup (notify on load).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F568: NotifyAll announces every known zone's current serial to every
// target; it is a no-op before any zone is known and after Stop.
func TestZoneNotifier_F568_NotifyAllAnnouncesEveryZone(t *testing.T) {
	g := newGatedSender()
	close(g.release)
	n := newZoneNotifier([]string{"192.0.2.1:53", "192.0.2.2:53"}, g.send, nil)
	n.NotifyAll() // nothing observed yet
	g.noMore(t)

	zones := map[string]*zone.Zone{
		"example.com.": notifyTestZone("example.com.", 10),
		"other.test.":  notifyTestZone("other.test.", 7),
	}
	n.Observe(zones) // startup baseline: no send by itself
	g.noMore(t)
	n.NotifyAll()
	got := map[notifyCall]bool{}
	for i := 0; i < 4; i++ {
		got[g.next(t)] = true
	}
	for _, want := range []notifyCall{
		{"example.com.", "192.0.2.1:53", 10}, {"example.com.", "192.0.2.2:53", 10},
		{"other.test.", "192.0.2.1:53", 7}, {"other.test.", "192.0.2.2:53", 7},
	} {
		if !got[want] {
			t.Errorf("missing startup NOTIFY %+v (got %v)", want, got)
		}
	}
	n.Stop()
	g.noMore(t)
	n.NotifyAll() // after Stop: no-op
	g.noMore(t)
}

// F568: a startup NOTIFY still in flight (unanswered secondary) is
// superseded by a serial change — the new serial goes out at once instead of
// after the old one's retransmissions.
func TestZoneNotifier_F568_StartupSendSupersededByChange(t *testing.T) {
	g := newGatedSender()
	n := newZoneNotifier([]string{"192.0.2.1:53"}, g.send, nil)
	defer n.Stop()
	z := notifyTestZone("example.com.", 1)
	zones := map[string]*zone.Zone{"example.com.": z}
	n.Observe(zones)
	n.NotifyAll()
	if c := g.next(t); c.serial != 1 {
		t.Fatalf("startup NOTIFY serial = %d, want 1", c.serial)
	}
	setSerial(z, 2)
	n.Observe(zones)
	if c := waitCall(t, g.cancelled, "startup send cancelled"); c.serial != 1 {
		t.Fatalf("cancelled serial = %d, want 1", c.serial)
	}
	if c := g.next(t); c.serial != 2 {
		t.Fatalf("follow-up serial = %d, want 2", c.serial)
	}
	g.release <- struct{}{}
}

// F567 (gated): SetTargets cancels the in-flight send to a removed target and
// drops its pending serial; the added target is notified from the next
// change on, with the new send function (new notify_key); a re-added target
// starts fresh.
func TestZoneNotifier_F567_SetTargetsSwapsList(t *testing.T) {
	oldS := newGatedSender()
	oldS.holdCancel = make(chan struct{})
	newS := newGatedSender()
	close(newS.release)
	n := newZoneNotifier([]string{"192.0.2.1:53"}, oldS.send, nil)
	defer n.Stop()

	z := notifyTestZone("example.com.", 1)
	zones := map[string]*zone.Zone{"example.com.": z}
	n.Observe(zones)
	setSerial(z, 2)
	n.Observe(zones)
	if c := oldS.next(t); c.target != "192.0.2.1:53" || c.serial != 2 {
		t.Fatalf("unexpected first send %+v", c)
	}
	setSerial(z, 3)
	n.Observe(zones) // supersedes: serial 3 pending for A, send 2 held cancelled
	waitCall(t, oldS.cancelled, "superseded send to A")

	n.SetTargets([]string{"192.0.2.2:53"}, newS.send) // A removed, B added
	close(oldS.holdCancel)
	if c := waitCall(t, oldS.ended, "send to removed target A returns"); c.serial != 2 {
		t.Fatalf("ended %+v, want serial 2", c)
	}
	newS.noMore(t) // B is not notified until the next change
	n.mu.Lock()
	if len(n.flights) != 0 {
		t.Errorf("flights after removal = %v, want none", n.flights)
	}
	n.mu.Unlock()

	setSerial(z, 4)
	n.Observe(zones)
	if c := newS.next(t); c.target != "192.0.2.2:53" || c.serial != 4 {
		t.Fatalf("send after reload = %+v, want B serial 4", c)
	}
	waitCall(t, newS.ended, "send to B")
	// Serial 3 to A was dropped with the target.
	oldS.noMore(t)

	// Re-adding A: an independent flight; both get the next change.
	n.SetTargets([]string{"192.0.2.1:53", "192.0.2.2:53"}, newS.send)
	setSerial(z, 5)
	n.Observe(zones)
	got := map[string]uint32{}
	for i := 0; i < 2; i++ {
		c := newS.next(t)
		got[c.target] = c.serial
	}
	if got["192.0.2.1:53"] != 5 || got["192.0.2.2:53"] != 5 {
		t.Fatalf("after re-adding A got %v, want both serial 5", got)
	}
	oldS.noMore(t)
}

// F567: the reload send function signs with notify_key from the new config.
func TestNotifySendFromConfig_F567(t *testing.T) {
	if _, err := notifySendFromConfig(config.TransferConfig{NotifyKey: "missing."}); err == nil {
		t.Fatal("unknown notify_key must be an error")
	}
	if send, err := notifySendFromConfig(config.TransferConfig{}); err != nil || send == nil {
		t.Fatalf("unsigned send: %v", err)
	}
	tc := config.TransferConfig{
		TSIGKeys:  []config.TransferTSIGKeyConfig{{Name: "Notify-Key.Example.", Algorithm: "hmac-sha256", Secret: notifyReloadSecret}},
		NotifyKey: "notify-key.example",
	}
	send, err := notifySendFromConfig(tc)
	if err != nil {
		t.Fatalf("notifySendFromConfig: %v", err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = send(ctx, "example.com.", 9, pc.LocalAddr().String()); close(done) }()
	got, ok := notifyReloadRead(pc, 9, 5*time.Second)
	cancel()
	<-done
	if !ok || !got.signed {
		t.Fatalf("NOTIFY got=%v signed=%v, want a TSIG-signed NOTIFY", ok, got.signed)
	}
}

const notifyReloadSecret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ="

func notifyReloadCfg(dnsPort int, dir, zoneFile, target string, withKey bool) string {
	y := fmt.Sprintf("server:\n  udp_bind:\n    - 127.0.0.1:%d\n  tcp_bind:\n    - 127.0.0.1:%d\nlogging:\n  level: error\nmetrics:\n  enabled: false\nstorage:\n  data_dir: %s\nzones:\n  - %s\ntransfer:\n  also_notify:\n    - %s\n",
		dnsPort, dnsPort, filepath.Join(dir, "data"), zoneFile, target)
	if withKey {
		y += "  tsig_keys:\n    - name: notify-key.example.\n      algorithm: hmac-sha256\n      secret: \"" + notifyReloadSecret + "\"\n  notify_key: notify-key.example.\n"
	}
	return y
}

type notifyReloadMsg struct {
	serial uint32
	signed bool
}

// notifyReloadRead returns the first NOTIFY with serial want (0 = any)
// received before the deadline.
func notifyReloadRead(pc net.PacketConn, want uint32, d time.Duration) (notifyReloadMsg, bool) {
	_ = pc.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 4096)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return notifyReloadMsg{}, false
		}
		m, err := protocol.UnpackMessage(buf[:n])
		if err != nil || m.Header.Flags.Opcode != protocol.OpcodeNotify || len(m.Answers) == 0 {
			continue
		}
		soa, ok := m.Answers[0].Data.(*protocol.RDataSOA)
		if !ok || (want != 0 && soa.Serial != want) {
			continue
		}
		signed := false
		for _, rr := range m.Additionals {
			if rr != nil && rr.Type == protocol.TypeTSIG {
				signed = true
			}
		}
		return notifyReloadMsg{serial: soa.Serial, signed: signed}, true
	}
}

func notifyReloadBoot(t *testing.T, yaml, dir string) (chan os.Signal, string, <-chan error) {
	t.Helper()
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
	exited := make(chan struct{})
	go func() {
		err := runWithContext(context.Background(), cfg)
		done <- err
		close(exited)
	}()
	t.Cleanup(func() {
		sigCh <- syscall.SIGTERM
		// Wait on exited, not done: a caller that already consumed done
		// (the done-aware NOTIFY wait surfacing a boot failure) must not
		// turn this cleanup into a 20s stall for a server known to have
		// exited.
		select {
		case <-exited:
		case <-time.After(20 * time.Second):
			t.Errorf("server did not stop")
		}
	})
	return sigCh, cfgPath, done
}

// notifyReloadWaitNotifyOrBoot is notifyReloadRead that also fails fast when
// the server exits during startup: a boot failure (for example the port
// picked by bootRestoreFreePort being stolen before the server binds it)
// previously surfaced only as a blind full-window timeout with no diagnosis.
// Reads are sliced into short deadlines so the boot-error channel is checked
// between them without ever losing a queued datagram or leaving a stale
// reader on pc.
func notifyReloadWaitNotifyOrBoot(pc net.PacketConn, done <-chan error, want uint32, d time.Duration) (notifyReloadMsg, bool, error) {
	deadline := time.Now().Add(d)
	buf := make([]byte, 4096)
	for {
		select {
		case err := <-done:
			return notifyReloadMsg{}, false, err
		default:
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return notifyReloadMsg{}, false, nil
		}
		slice := 100 * time.Millisecond
		if remaining < slice {
			slice = remaining
		}
		_ = pc.SetReadDeadline(time.Now().Add(slice))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return notifyReloadMsg{}, false, err
		}
		m, perr := protocol.UnpackMessage(buf[:n])
		if perr != nil || m.Header.Flags.Opcode != protocol.OpcodeNotify || len(m.Answers) == 0 {
			continue
		}
		soa, ok := m.Answers[0].Data.(*protocol.RDataSOA)
		if !ok || (want != 0 && soa.Serial != want) {
			continue
		}
		signed := false
		for _, rr := range m.Additionals {
			if rr != nil && rr.Type == protocol.TypeTSIG {
				signed = true
			}
		}
		return notifyReloadMsg{serial: soa.Serial, signed: signed}, true, nil
	}
}

func notifyReloadWaitSerial(addr string, want uint32) bool {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if s, err := notifyE2ESOASerial(addr); err == nil && s == want {
			return true
		}
		time.Sleep(50 * time.Millisecond) // polling server readiness, not ordering
	}
	return false
}

// F568 e2e: the real server sends NOTIFY for its zone after startup.
//
// bootAttempts bounds the one environmental failure this test cannot
// prevent: bootRestoreFreePort releases the picked port before the server
// binds it, so under a loaded suite another test's ephemeral bind can steal
// it and the boot fails with EADDRINUSE. A stolen port retries with a fresh
// port; any other boot error fails immediately with its real cause instead
// of surfacing as a blind NOTIFY timeout.
func TestF568_PrimaryNotifiesOnStartup(t *testing.T) {
	dir := t.TempDir()
	zoneFile := filepath.Join(dir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 7)), 0o644); err != nil {
		t.Fatal(err)
	}
	sec, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sec.Close()

	const bootAttempts = 3
	for attempt := 1; ; attempt++ {
		dnsPort := bootRestoreFreePort(t, "udp")
		_, _, done := notifyReloadBoot(t, notifyReloadCfg(dnsPort, dir, zoneFile, sec.LocalAddr().String(), false), dir)
		_, ok, bootErr := notifyReloadWaitNotifyOrBoot(sec, done, 7, 15*time.Second)
		if bootErr != nil {
			if attempt < bootAttempts && errors.Is(bootErr, syscall.EADDRINUSE) {
				// The picked port was stolen between the free-port probe and
				// the server's bind; the failed boot's cleanup already ran.
				continue
			}
			t.Fatalf("server exited during startup: %v", bootErr)
		}
		if !ok {
			t.Fatal("no NOTIFY serial 7 after startup")
		}
		if !notifyReloadWaitSerial(fmt.Sprintf("127.0.0.1:%d", dnsPort), 7) {
			t.Fatal("server does not serve serial 7")
		}
		break
	}
}

// F567 e2e: a SIGHUP replacing also_notify (A -> B) and adding notify_key,
// together with a serial change, notifies B (signed) and not A.
func TestF567_ReloadAppliesAlsoNotifyAndKey(t *testing.T) {
	dir := t.TempDir()
	zoneFile := filepath.Join(dir, "example.com.zone")
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	secA, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer secA.Close()
	secB, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer secB.Close()
	dnsPort := bootRestoreFreePort(t, "udp")
	sigCh, cfgPath, bootDone := notifyReloadBoot(t, notifyReloadCfg(dnsPort, dir, zoneFile, secA.LocalAddr().String(), false), dir)
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	if !notifyReloadWaitSerial(addr, 1) {
		select {
		case err := <-bootDone:
			t.Fatalf("setup: server exited during startup: %v", err)
		default:
		}
		t.Fatal("setup: server never served serial 1")
	}
	// The startup NOTIFY (F568) reaches A, unsigned.
	if got, ok, bootErr := notifyReloadWaitNotifyOrBoot(secA, bootDone, 1, 10*time.Second); bootErr != nil {
		t.Fatalf("startup NOTIFY to A: server exited: %v", bootErr)
	} else if !ok || got.signed {
		t.Fatalf("startup NOTIFY to A: got=%v signed=%v", ok, got.signed)
	}

	if err := os.WriteFile(cfgPath, []byte(notifyReloadCfg(dnsPort, dir, zoneFile, secB.LocalAddr().String(), true)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(zoneFile, []byte(fmt.Sprintf(notifyE2EZone, 2)), 0o644); err != nil {
		t.Fatal(err)
	}
	sigCh <- syscall.SIGHUP
	if !notifyReloadWaitSerial(addr, 2) {
		t.Fatal("setup: SIGHUP reload did not take effect")
	}
	gotB, okB := notifyReloadRead(secB, 2, 10*time.Second)
	if !okB || !gotB.signed {
		t.Fatalf("new target B: got=%v signed=%v, want TSIG-signed NOTIFY serial 2", okB, gotB.signed)
	}
	// B's NOTIFY for serial 2 is sent after the reload swapped the targets,
	// so any NOTIFY for serial 2 to A would already be on its way.
	if _, okA := notifyReloadRead(secA, 2, time.Second); okA {
		t.Fatal("removed target A still received a NOTIFY after reload")
	}
}

// F567: applyNotifyTargets is nil-safe, and an unresolvable notify_key is
// reported as an error (reloadConfig then fails before applying anything).
func TestApplyNotifyTargets_F567(t *testing.T) {
	applyNotifyTargets(nil, nil, nil, nil)
	h := newTestHandler()
	applyNotifyTargets(h, []string{"192.0.2.1:53"}, newTransferNOTIFYSend(nil), nil) // no notifier: no-op
	g := newGatedSender()
	h.transfer.Notifier = newZoneNotifier(nil, g.send, nil)
	defer h.transfer.Notifier.Stop()
	applyNotifyTargets(h, []string{"192.0.2.1:53"}, g.send, nil)
	if got := h.transfer.Notifier.targets; len(got) != 1 || got[0] != "192.0.2.1:53" {
		t.Fatalf("targets after apply = %v", got)
	}
	if _, err := notifySendFromConfig(config.TransferConfig{NotifyKey: "x.", TSIGKeys: []config.TransferTSIGKeyConfig{{Name: "y.", Algorithm: "hmac-sha256", Secret: notifyReloadSecret}}}); err == nil || !strings.Contains(err.Error(), "notify_key") {
		t.Fatalf("err = %v, want notify_key error", err)
	}
}
