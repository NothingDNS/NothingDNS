package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// F547 regressions: outgoing NOTIFY (RFC 1996) on zone serial changes.

type notifyCall struct {
	zone, target string
	serial       uint32
}

// gatedSender records calls and blocks each one until released (or ctx is
// cancelled), so tests control completion order without sleeps.
type gatedSender struct {
	mu      sync.Mutex
	calls   []notifyCall
	started chan notifyCall
	release chan struct{}
	active  map[string]int
	maxConc int
	// holdCancel, when non-nil, keeps a cancelled send from returning until
	// it is closed (gates the supersede/removal ordering, F567).
	holdCancel chan struct{}
	// cancelled receives each call whose ctx was cancelled; ended each call
	// as it returns.
	cancelled chan notifyCall
	ended     chan notifyCall
}

func newGatedSender() *gatedSender {
	return &gatedSender{
		started:   make(chan notifyCall, 64),
		release:   make(chan struct{}),
		active:    make(map[string]int),
		cancelled: make(chan notifyCall, 64),
		ended:     make(chan notifyCall, 64),
	}
}

func (g *gatedSender) send(ctx context.Context, zoneName string, serial uint32, target string) error {
	c := notifyCall{zone: zoneName, target: target, serial: serial}
	key := zoneName + "|" + target
	g.mu.Lock()
	g.calls = append(g.calls, c)
	g.active[key]++
	if g.active[key] > g.maxConc {
		g.maxConc = g.active[key]
	}
	g.mu.Unlock()
	g.started <- c
	defer func() {
		g.mu.Lock()
		g.active[key]--
		g.mu.Unlock()
		g.ended <- c
	}()
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		g.cancelled <- c
		if g.holdCancel != nil {
			<-g.holdCancel
		}
		return ctx.Err()
	}
}

// wait receives one call from ch or fails the test.
func waitCall(t *testing.T, ch <-chan notifyCall, what string) notifyCall {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return notifyCall{}
	}
}

func (g *gatedSender) next(t *testing.T) notifyCall {
	t.Helper()
	select {
	case c := <-g.started:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("expected a NOTIFY send, none started")
		return notifyCall{}
	}
}

func (g *gatedSender) noMore(t *testing.T) {
	t.Helper()
	select {
	case c := <-g.started:
		t.Fatalf("unexpected NOTIFY send %+v", c)
	default:
	}
}

func notifyTestZone(origin string, serial uint32) *zone.Zone {
	z := zone.NewZone(origin)
	z.SOA = &zone.SOARecord{MName: "ns1." + origin, RName: "admin." + origin, Serial: serial, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300}
	return z
}

func setSerial(z *zone.Zone, serial uint32) {
	z.Lock()
	z.SOA.Serial = serial
	z.Unlock()
}

func TestZoneNotifier_DisabledWithoutTargets(t *testing.T) {
	// With no targets the notifier exists (a SIGHUP may add targets, F567)
	// but sends nothing, on changes or after startup.
	g := newGatedSender()
	n := newZoneNotifier(nil, g.send, nil)
	if n == nil {
		t.Fatal("notifier must exist without targets so a reload can enable it")
	}
	z := notifyTestZone("a.", 1)
	zones := map[string]*zone.Zone{"a.": z}
	n.Observe(zones)
	n.NotifyAll()
	setSerial(z, 2)
	n.Observe(zones)
	n.Stop()
	g.noMore(t)

	var nilN *zoneNotifier
	nilN.Observe(zones) // nil-safe
	nilN.NotifyAll()
	nilN.SetTargets([]string{"192.0.2.1:53"}, g.send)
	nilN.Stop()
}

func TestZoneNotifier_SerialChangeSendsToEveryTarget(t *testing.T) {
	g := newGatedSender()
	close(g.release) // sends complete immediately
	n := newZoneNotifier([]string{"192.0.2.1:53", "192.0.2.2:5300"}, g.send, nil)
	defer n.Stop()

	z := notifyTestZone("example.com.", 10)
	other := notifyTestZone("other.test.", 7)
	zones := map[string]*zone.Zone{"example.com.": z, "other.test.": other}

	n.Observe(zones) // startup baseline: nothing sent
	n.Observe(zones) // unchanged: nothing sent
	g.noMore(t)

	setSerial(z, 11)
	n.Observe(zones)
	got := map[string]uint32{}
	for i := 0; i < 2; i++ {
		c := g.next(t)
		if c.zone != "example.com." {
			t.Fatalf("NOTIFY for unchanged zone %q", c.zone)
		}
		got[c.target] = c.serial
	}
	if got["192.0.2.1:53"] != 11 || got["192.0.2.2:5300"] != 11 {
		t.Fatalf("each target must get serial 11, got %v", got)
	}

	// A zone added after startup (API create) is announced too.
	zones["new.test."] = notifyTestZone("new.test.", 1)
	n.Observe(zones)
	for i := 0; i < 2; i++ {
		if c := g.next(t); c.zone != "new.test." || c.serial != 1 {
			t.Fatalf("expected NOTIFY new.test. serial 1, got %+v", c)
		}
	}
	n.Stop()
	g.noMore(t)
}

// Gated: while one NOTIFY for a zone+target is in flight, further serial
// changes coalesce — the in-flight (now superseded) send is cancelled and
// exactly one follow-up send carries the latest serial (F547, F568).
func TestZoneNotifier_CoalescesLatestSerialWins(t *testing.T) {
	g := newGatedSender()
	g.holdCancel = make(chan struct{})
	n := newZoneNotifier([]string{"192.0.2.1:53"}, g.send, nil)
	defer n.Stop()

	z := notifyTestZone("example.com.", 1)
	zones := map[string]*zone.Zone{"example.com.": z}
	n.Observe(zones)

	setSerial(z, 2)
	n.Observe(zones)
	if c := g.next(t); c.serial != 2 {
		t.Fatalf("first send serial = %d, want 2", c.serial)
	}
	// In flight (blocked). Three more changes arrive; the first cancels the
	// in-flight send, which is held until all three are recorded.
	for _, s := range []uint32{3, 4, 5} {
		setSerial(z, s)
		n.Observe(zones)
	}
	if c := waitCall(t, g.cancelled, "superseded send cancelled"); c.serial != 2 {
		t.Fatalf("cancelled send serial = %d, want 2", c.serial)
	}
	g.noMore(t) // nothing new starts while one is in flight
	close(g.holdCancel)

	if c := g.next(t); c.serial != 5 {
		t.Fatalf("follow-up send serial = %d, want latest 5", c.serial)
	}
	g.release <- struct{}{} // finish serial 5
	n.Stop()
	g.noMore(t)
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.calls) != 2 || g.maxConc != 1 {
		t.Fatalf("calls=%v maxConcurrent=%d; want 2 calls (2, 5), 1 in flight", g.calls, g.maxConc)
	}
}

// Gated: Stop cancels a blocked in-flight NOTIFY and waits for its goroutine;
// later observations send nothing.
func TestZoneNotifier_StopCancelsInFlightAndIsFinal(t *testing.T) {
	g := newGatedSender()
	n := newZoneNotifier([]string{"192.0.2.1:53"}, g.send, nil)

	z := notifyTestZone("example.com.", 1)
	zones := map[string]*zone.Zone{"example.com.": z}
	n.Observe(zones)
	setSerial(z, 2)
	n.Observe(zones)
	g.next(t) // in flight, never released
	setSerial(z, 3)
	n.Observe(zones) // supersedes the in-flight send

	stopped := make(chan struct{})
	go func() { n.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return: in-flight NOTIFY not cancelled")
	}
	g.mu.Lock()
	active := g.active["example.com.|192.0.2.1:53"]
	g.mu.Unlock()
	if active != 0 {
		t.Fatalf("%d sender(s) still running after Stop", active)
	}
	for len(g.started) > 0 { // the superseding send may have started before Stop
		<-g.started
	}
	setSerial(z, 4)
	n.Observe(zones)
	g.noMore(t)
	n.Stop() // idempotent
}

// API/Raft path: a zone-manager mutation bumps the serial, the mutation hook
// rebuilds the zone tree, and the rebuild schedules the NOTIFY.
func TestZoneNotifier_ManagerMutationTriggersNOTIFY(t *testing.T) {
	g := newGatedSender()
	close(g.release)
	h := newTestHandler()
	h.zoneManager = zone.NewManager()
	h.transfer.Notifier = newZoneNotifier([]string{"192.0.2.1:53"}, g.send, nil)
	defer h.transfer.Notifier.Stop()

	z := notifyTestZone("example.com.", 100)
	h.zoneManager.LoadZone(z, "")
	h.zones["example.com."] = z
	h.zoneManager.SetMutationHook(func(string, bool) { h.RebuildZoneTree() })
	h.RebuildZoneTree() // boot baseline
	g.noMore(t)

	if err := h.zoneManager.AddRecord("example.com.", zone.Record{Name: "www", TTL: 300, Type: "A", RData: "192.0.2.80"}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	c := g.next(t)
	if c.zone != "example.com." || c.serial == 100 || c.target != "192.0.2.1:53" {
		t.Fatalf("expected NOTIFY with the bumped serial, got %+v", c)
	}
}

// Config wiring: NOTIFY sends nothing unless transfer.also_notify is set;
// the notifier always exists so a SIGHUP can add targets (F567).
func TestTransferManager_NotifierFromConfig(t *testing.T) {
	dir := t.TempDir()
	off := tmNewManager(t, "storage:\n  data_dir: "+dir+"/a\n", map[string]*zone.Zone{})
	defer off.Stop()
	if n := off.Result().Notifier; n == nil || len(n.targets) != 0 {
		t.Fatal("without transfer.also_notify the notifier must exist with no targets")
	}
	on := tmNewManager(t, "storage:\n  data_dir: "+dir+"/b\ntransfer:\n  also_notify:\n    - 127.0.0.1:5399\n", map[string]*zone.Zone{})
	if n := on.Result().Notifier; n == nil || len(n.targets) != 1 {
		t.Fatal("transfer.also_notify did not configure the NOTIFY sender")
	}
	on.Stop()
	on.Stop() // idempotent
}
