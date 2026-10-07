package cluster

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster/raft"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// f497Manager builds a.example. with www A 192.0.2.10 and a relative CNAME
// target (as the API stores it) and counts mutation notifications.
func f497Manager(t *testing.T) (*zone.Manager, *atomic.Int32) {
	t.Helper()
	m := zone.NewManager()
	m.LoadZone(zoneHooksTestZone(t, "a.example.", "192.0.2.1"), "")
	if err := m.AddRecord("a.example.", zone.Record{Name: "www", Type: "A", TTL: 60, RData: "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	if err := m.AddRecord("a.example.", zone.Record{Name: "alias", Type: "CNAME", TTL: 60, RData: "www"}); err != nil {
		t.Fatal(err)
	}
	n := &atomic.Int32{}
	m.SetMutationHook(func(string, bool) { n.Add(1) })
	return m, n
}

func f497Envelope(t *testing.T, p zoneBatchPayload) raft.ZoneCommand {
	t.Helper()
	meta, err := json.Marshal(zoneBatchEnvelope{Batch: &p})
	if err != nil {
		t.Fatal(err)
	}
	return raft.ZoneCommand{Type: "create_zone", Zone: "a.example.", Metadata: meta}
}

func f497Export(t *testing.T, m *zone.Manager) string {
	t.Helper()
	s, err := m.ExportZone("a.example.")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func f497Rdatas(m *zone.Manager, name, rtype string) []string {
	recs, _ := m.GetRecords("a.example.", name)
	out := []string{}
	for _, r := range recs {
		if strings.EqualFold(r.Type, rtype) {
			out = append(out, r.RData)
		}
	}
	return out
}

func f497Cluster(m *zone.Manager) *Cluster {
	return &Cluster{zoneManager: m, logger: util.NewLogger(util.ERROR, util.TextFormat, nil)}
}

// F497/F498: a batch entry is applied all-or-nothing, identically on every
// replica, with one serial bump and one mutation notification.
func TestApplyZoneBatch_F497_AllOrNothing(t *testing.T) {
	ops := []ZoneOp{
		{Op: ZoneOpDeleteRData, Name: "www", Type: "A", RData: "192.0.2.10"},
		{Op: ZoneOpAdd, Name: "www", Type: "A", TTL: 60, RData: "192.0.2.20"},
		{Op: ZoneOpAdd, Name: "www.a.example.", Type: "a", TTL: 60, RData: "192.0.2.20"}, // duplicate: no-op
		{Op: ZoneOpAdd, Name: "mail", Type: "MX", TTL: 60, RData: "10 www.a.example."},
		{Op: ZoneOpUpdate, Name: "alias", Type: "CNAME", TTL: 30, OldData: "www.a.example.", RData: "mail.a.example."},
	}
	ref, _ := f497Manager(t)
	fp, err := f497Cluster(ref).ZoneFingerprint("a.example.", []string{"www", "mail", "alias"})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("applied in full, identically on three replicas", func(t *testing.T) {
		const date = uint32(2099010100) // newer than any setup serial: deterministic date+1
		var exports []string
		for i := 0; i < 3; i++ {
			m, notes := f497Manager(t)
			if i == 2 {
				// Replica that caught up via snapshot: the zone went through
				// WriteZone/ParseFile, which absolutizes the CNAME target the
				// API stored relative. The fingerprint must still match.
				z, _ := m.Get("a.example.")
				txt, err := zone.WriteZone(z)
				if err != nil {
					t.Fatal(err)
				}
				rz, err := zone.ParseFile("a.example.", strings.NewReader(txt))
				if err != nil {
					t.Fatal(err)
				}
				m.LoadZone(rz, "")
			}
			c := f497Cluster(m)
			c.applyRaftZoneCommand(f497Envelope(t, zoneBatchPayload{V: 1, ID: "b1", Ops: ops,
				Names: []string{"www", "mail", "alias"}, Fingerprint: fp, SerialDate: date}))
			if got := f497Rdatas(m, "www", "A"); len(got) != 1 || got[0] != "192.0.2.20" {
				t.Fatalf("replica %d www A = %v", i, got)
			}
			if got := f497Rdatas(m, "mail", "MX"); len(got) != 1 {
				t.Fatalf("replica %d mail MX = %v", i, got)
			}
			if got := f497Rdatas(m, "alias", "CNAME"); len(got) != 1 || got[0] != "mail.a.example." {
				t.Fatalf("replica %d alias CNAME = %v", i, got)
			}
			z, _ := m.Get("a.example.")
			if z.SOA.Serial != date+1 {
				t.Fatalf("replica %d serial = %d, want %d (single deterministic bump)", i, z.SOA.Serial, date+1)
			}
			if n := notes.Load(); n != 1 {
				t.Fatalf("replica %d notifications = %d, want 1", i, n)
			}
			exports = append(exports, f497Export(t, m))
		}
		if exports[0] != exports[1] {
			t.Fatalf("replicas diverged:\n%s\n---\n%s", exports[0], exports[1])
		}
	})

	t.Run("one failing op: nothing applied", func(t *testing.T) {
		m, notes := f497Manager(t)
		before := f497Export(t, m)
		bad := append(append([]ZoneOp{}, ops[:2]...), ZoneOp{Op: ZoneOpDeleteRData, Name: "www", Type: "A", RData: "192.0.2.99"})
		c := f497Cluster(m)
		ch := c.zoneBatches.register("b2")
		c.applyRaftZoneCommand(f497Envelope(t, zoneBatchPayload{V: 1, ID: "b2", Ops: bad, SerialDate: 2026100700}))
		var opErr *ZoneBatchOpError
		if err := <-ch; !errors.As(err, &opErr) || opErr.Index != 2 {
			t.Fatalf("result = %v, want ZoneBatchOpError at index 2", err)
		}
		if after := f497Export(t, m); after != before || notes.Load() != 0 {
			t.Fatalf("zone changed by failed batch (notifications=%d):\n%s", notes.Load(), after)
		}
	})

	t.Run("validation failures: nothing applied", func(t *testing.T) {
		for _, op := range []ZoneOp{
			{Op: ZoneOpAdd, Name: "x.other.example.", Type: "A", RData: "192.0.2.1"}, // out of zone
			{Op: ZoneOpAdd, Name: "x", Type: "TXT", RData: "a\nb IN A 192.0.2.66"},   // injection
			{Op: ZoneOpDeleteRRset, Name: "@", Type: "SOA"},
			{Op: "rename", Name: "x", Type: "A", RData: "192.0.2.1"},
			{Op: ZoneOpDeleteRRset, Name: "nothing", Type: "A"},
		} {
			m, notes := f497Manager(t)
			before := f497Export(t, m)
			c := f497Cluster(m)
			c.applyRaftZoneCommand(f497Envelope(t, zoneBatchPayload{V: 1, ID: "v", SerialDate: 2026100700,
				Ops: []ZoneOp{ops[1], op}}))
			if after := f497Export(t, m); after != before || notes.Load() != 0 {
				t.Fatalf("op %+v: zone changed", op)
			}
		}
	})

	t.Run("precondition mismatch: conflict, nothing applied", func(t *testing.T) {
		m, notes := f497Manager(t)
		// A write lands between planning (fp) and apply.
		if err := m.AddRecord("a.example.", zone.Record{Name: "www", Type: "AAAA", TTL: 60, RData: "2001:db8::1"}); err != nil {
			t.Fatal(err)
		}
		notes.Store(0)
		before := f497Export(t, m)
		c := f497Cluster(m)
		ch := c.zoneBatches.register("b3")
		c.applyRaftZoneCommand(f497Envelope(t, zoneBatchPayload{V: 1, ID: "b3", Ops: ops,
			Names: []string{"www", "mail", "alias"}, Fingerprint: fp, SerialDate: 2026100700}))
		if err := <-ch; !errors.Is(err, ErrZoneBatchConflict) {
			t.Fatalf("result = %v, want ErrZoneBatchConflict", err)
		}
		if after := f497Export(t, m); after != before || notes.Load() != 0 {
			t.Fatal("zone changed by conflicting batch")
		}
	})

	t.Run("unknown payload version and malformed envelope rejected cleanly", func(t *testing.T) {
		m, notes := f497Manager(t)
		before := f497Export(t, m)
		c := f497Cluster(m)
		ch := c.zoneBatches.register("b4")
		c.applyRaftZoneCommand(f497Envelope(t, zoneBatchPayload{V: 2, ID: "b4", Ops: ops}))
		if err := <-ch; !errors.Is(err, ErrZoneBatchUnsupported) {
			t.Fatalf("result = %v, want ErrZoneBatchUnsupported", err)
		}
		c.applyRaftZoneCommand(raft.ZoneCommand{Type: "create_zone", Zone: "a.example.", Metadata: json.RawMessage(`{"zone_batch":[1]}`)})
		if after := f497Export(t, m); after != before || notes.Load() != 0 || m.Count() != 1 {
			t.Fatal("zone changed by rejected batch")
		}
	})

	t.Run("legacy create_zone unaffected", func(t *testing.T) {
		m, _ := f497Manager(t)
		c := f497Cluster(m)
		c.applyRaftZoneCommand(raft.ZoneCommand{Type: "create_zone", Zone: "b.example.", TTL: 300,
			AdminEmail: "hostmaster.b.example.", Nameservers: []string{"ns1.b.example."}})
		if _, ok := m.Get("b.example."); !ok {
			t.Fatal("legacy create_zone no longer creates the zone")
		}
	})
}

// F498: the fingerprint is presentation-independent and scoped to its names.
func TestZoneFingerprint_F498(t *testing.T) {
	m, _ := f497Manager(t)
	c := f497Cluster(m)
	fp1, _ := c.ZoneFingerprint("A.EXAMPLE", []string{"WWW", "alias.a.example."})
	if err := m.AddRecord("a.example.", zone.Record{Name: "other", Type: "A", TTL: 60, RData: "192.0.2.5"}); err != nil {
		t.Fatal(err)
	}
	fp2, _ := c.ZoneFingerprint("a.example.", []string{"alias", "www"})
	if fp1 != fp2 {
		t.Fatal("unrelated write or name order/case changed the fingerprint")
	}
	if err := m.DeleteRecordData("a.example.", "www", "A", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if err := m.AddRecord("a.example.", zone.Record{Name: "www", Type: "A", TTL: 60, RData: "192.0.2.10"}); err != nil {
		t.Fatal(err)
	}
	if fp3, _ := c.ZoneFingerprint("a.example.", []string{"www", "alias"}); fp3 != fp1 {
		t.Fatal("content-identical RRset (only the serial changed) altered the fingerprint")
	}
	if err := m.UpdateRecord("a.example.", "www", "A", "192.0.2.10", zone.Record{Name: "www", Type: "A", TTL: 60, RData: "192.0.2.11"}); err != nil {
		t.Fatal(err)
	}
	if fp4, _ := c.ZoneFingerprint("a.example.", []string{"www", "alias"}); fp4 == fp1 {
		t.Fatal("changed RRset kept the same fingerprint")
	}
	if _, err := c.ZoneFingerprint("missing.example.", nil); err == nil {
		t.Fatal("fingerprint of a missing zone succeeded")
	}
}

// F497/F498 through a started single-node Raft cluster: one entry per batch,
// no intermediate state observable, conflicts and op failures reported to the
// proposer with nothing applied.
func TestProposeZoneBatch_F497_SingleNodeRaft(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	m, notes := f497Manager(t)
	c, err := New(Config{
		Enabled: true, AllowInsecureCluster: true, NodeID: "n1", BindAddr: "127.0.0.1",
		ConsensusMode: ConsensusRaft, DataDir: t.TempDir(),
		Peers:       []PeerConfig{{NodeID: "n1", Addr: "127.0.0.1:0"}},
		ZoneManager: m,
	}, util.NewLogger(util.ERROR, util.TextFormat, nil), nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer c.Stop()
	deadline := time.Now().Add(10 * time.Second)
	for !c.raft.IsLeader() {
		if time.Now().After(deadline) {
			t.Fatal("single-node Raft never became leader")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Count apply-hook calls and park on each one before applying, so the
	// zone can be observed between entries of a change.
	var hookMu sync.Mutex
	var gate chan chan struct{}
	c.SetZoneApplyFunc(func(cmd raft.ZoneCommand) {
		hookMu.Lock()
		g := gate
		hookMu.Unlock()
		if g != nil {
			release := make(chan struct{})
			g <- release
			<-release
		}
		c.applyRaftZoneCommand(cmd)
	})
	setGate := func(g chan chan struct{}) { hookMu.Lock(); gate = g; hookMu.Unlock() }

	names := []string{"www.a.example."}
	replace := func(oldIP, newIP string) []ZoneOp {
		return []ZoneOp{
			{Op: ZoneOpDeleteRData, Name: "www", Type: "A", RData: oldIP},
			{Op: ZoneOpAdd, Name: "www", Type: "A", TTL: 60, RData: newIP},
		}
	}

	// Gated success: exactly one apply-hook call; before it the zone is
	// entirely old, after it entirely new.
	fp, err := c.ZoneFingerprint("a.example.", names)
	if err != nil {
		t.Fatal(err)
	}
	notes.Store(0)
	g := make(chan chan struct{})
	setGate(g)
	done := make(chan error, 1)
	go func() {
		done <- c.ProposeZoneBatch("a.example.", replace("192.0.2.10", "192.0.2.20"),
			ZoneBatchPrecondition{Names: names, Fingerprint: fp})
	}()
	release := <-g
	setGate(nil)
	if got := f497Rdatas(m, "www", "A"); len(got) != 1 || got[0] != "192.0.2.10" {
		t.Fatalf("before the batch entry applied: www A = %v", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("ProposeZoneBatch: %v", err)
	}
	if got := f497Rdatas(m, "www", "A"); len(got) != 1 || got[0] != "192.0.2.20" {
		t.Fatalf("after the batch: www A = %v", got)
	}
	if n := notes.Load(); n != 1 {
		t.Fatalf("notifications = %d, want 1", n)
	}

	// Conflict: a write between planning and proposing.
	fp, _ = c.ZoneFingerprint("a.example.", names)
	if err := c.ProposeAddRecord("a.example.", "www", "A", "IN", 60, "192.0.2.21"); err != nil {
		t.Fatal(err)
	}
	before := f497Export(t, m)
	err = c.ProposeZoneBatch("a.example.", replace("192.0.2.20", "192.0.2.30"), ZoneBatchPrecondition{Names: names, Fingerprint: fp})
	if !errors.Is(err, ErrZoneBatchConflict) {
		t.Fatalf("interleaved write: err = %v, want ErrZoneBatchConflict", err)
	}
	if f497Export(t, m) != before {
		t.Fatal("conflicting batch changed the zone")
	}

	// Op failure: nothing applied, error names the op.
	var opErr *ZoneBatchOpError
	err = c.ProposeZoneBatch("a.example.", replace("192.0.2.99", "192.0.2.30"), ZoneBatchPrecondition{})
	if !errors.As(err, &opErr) || opErr.Index != 0 {
		t.Fatalf("failing op: err = %v, want ZoneBatchOpError index 0", err)
	}
	if f497Export(t, m) != before {
		t.Fatal("failed batch changed the zone")
	}

	// Proposer-side validation (no entry proposed).
	for name, call := range map[string]func() error{
		"no ops": func() error { return c.ProposeZoneBatch("a.example.", nil, ZoneBatchPrecondition{}) },
		"SOA op": func() error {
			return c.ProposeZoneBatch("a.example.", []ZoneOp{{Op: ZoneOpDeleteRRset, Name: "@", Type: "SOA"}}, ZoneBatchPrecondition{})
		},
		"uncovered owner": func() error {
			return c.ProposeZoneBatch("a.example.", replace("192.0.2.20", "192.0.2.30"), ZoneBatchPrecondition{Names: []string{"mail"}, Fingerprint: "v1:x"})
		},
		"names w/o fp": func() error {
			return c.ProposeZoneBatch("a.example.", replace("192.0.2.20", "192.0.2.30"), ZoneBatchPrecondition{Names: names})
		},
		"too many ops": func() error {
			return c.ProposeZoneBatch("a.example.", make([]ZoneOp, MaxZoneBatchOps+1), ZoneBatchPrecondition{})
		},
	} {
		if err := call(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if f497Export(t, m) != before {
		t.Fatal("rejected proposals changed the zone")
	}

	// Not in Raft mode.
	if err := f497Cluster(m).ProposeZoneBatch("a.example.", replace("192.0.2.20", "192.0.2.30"), ZoneBatchPrecondition{}); err == nil {
		t.Fatal("ProposeZoneBatch outside Raft mode succeeded")
	}
}
