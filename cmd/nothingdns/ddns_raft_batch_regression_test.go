package main

// F532/F533 (P2-E3b) regression: in Raft cluster mode one DDNS UPDATE is
// committed as ONE atomic zone batch guarded by a fingerprint of the RRs at
// its prerequisite and update owner names. Built from
// .temp_files/verify_F532_F533_ddns_batch.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cluster"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/transfer"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ddnsBatchGate parks the Raft apply goroutine inside the zone mutation hook
// (which runs synchronously after each applied zone change) on the first
// call after arm, and records the observed state at every call.
type ddnsBatchGate struct {
	mu      sync.Mutex
	armed   bool
	calls   int
	states  []string
	observe func() string
	reached chan struct{}
	release chan struct{}
}

func newDDNSBatchGate(m *zone.Manager) *ddnsBatchGate {
	g := &ddnsBatchGate{}
	m.SetMutationHook(func(string, bool) {
		g.mu.Lock()
		g.calls++
		if g.observe != nil {
			g.states = append(g.states, g.observe())
		}
		park := g.armed && g.calls == 1
		reached, release := g.reached, g.release
		g.mu.Unlock()
		if park {
			close(reached)
			<-release
		}
	})
	return g
}

func (g *ddnsBatchGate) arm(observe func() string) (reached, release chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed, g.calls, g.states, g.observe = true, 0, nil, observe
	g.reached, g.release = make(chan struct{}), make(chan struct{})
	return g.reached, g.release
}

func (g *ddnsBatchGate) disarm() (calls int, states []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed, g.observe = false, nil
	return g.calls, g.states
}

func ddnsBatchWait[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(15 * time.Second):
		t.Fatalf("timeout waiting for %s", what)
		panic("unreachable")
	}
}

// ddnsBatchWaitCommit waits (for a condition, not an ordering) until the
// Raft log holds an entry beyond index.
func ddnsBatchWaitCommit(t *testing.T, c *cluster.Cluster, index int64, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for ddnsPolCommit(c) <= index {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s to reach the Raft log", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func ddnsBatchServe(t *testing.T) (*ddnsPolServer, *transfer.TSIGKey) {
	t.Helper()
	key := ddnsPolKey("ddns-key.example.", ddnsPolSecret)
	keys := "  tsig_keys:\n" + ddnsPolVKey("ddns-key.example.", ddnsPolSecret, "      allow_update:\n        - example.com.\n")
	return ddnsPolServe(t, ddnsPolVYAML(t.TempDir(), keys), true), key
}

// F532: a multi-record UPDATE is never observable half-applied and produces
// one Raft entry and one mutation notification.
func TestDDNSRaftBatch_F532_AtomicUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	rs, key := ddnsBatchServe(t)
	gate := newDDNSBatchGate(rs.manager)
	www := func() string { return strings.Join(ddnsPolA(rs.zone, "www.example.com."), ",") }

	before := ddnsPolCommit(rs.cluster)
	reached, release := gate.arm(www)
	done := make(chan ddnsPolResult, 1)
	go func() {
		done <- ddnsPolUpdate(t, rs.addr, key, ddnsPolDelRR(t, "www.example.com.", "192.0.2.2"), ddnsPolAdd(t, "www.example.com.", "192.0.2.20"), ddnsPolAdd(t, "www2.example.com.", "192.0.2.21"))
	}()
	ddnsBatchWait(t, reached, "first apply of the UPDATE")
	intermediate := www()
	close(release)
	res := ddnsBatchWait(t, done, "UPDATE response")
	calls, states := gate.disarm()
	ddnsPolExpect(t, "atomic replace", res, protocol.RcodeSuccess, true)
	if intermediate != "192.0.2.20" {
		t.Errorf("state at the first applied entry: www A = %q, want the complete new RRset 192.0.2.20 (states %q)", intermediate, states)
	}
	if calls != 1 {
		t.Errorf("mutation notifications = %d, want 1 (states %q)", calls, states)
	}
	if d := ddnsPolCommit(rs.cluster) - before; d != 1 {
		t.Errorf("Raft entries for one UPDATE = %d, want 1", d)
	}
	ddnsPolExpectA(t, "after", rs.zone, "www2.example.com.", "192.0.2.21")
}

// F533: a write that lands between the UPDATE's planning and its apply is
// detected; the UPDATE is re-planned against the new state (here its
// prerequisite then fails) and nothing of the stale plan is applied.
func TestDDNSRaftBatch_F533_ConcurrentWriteReplans(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	rs, key := ddnsBatchServe(t)
	c := rs.cluster
	if r := ddnsPolUpdate(t, rs.addr, key, ddnsPolAdd(t, "p.example.com.", "192.0.2.80"), ddnsPolAdd(t, "r.example.com.", "192.0.2.81")); r.rcode != protocol.RcodeSuccess {
		t.Fatalf("setup: %s", r)
	}
	gate := newDDNSBatchGate(rs.manager)
	state := func() string {
		return "p=" + strings.Join(ddnsPolA(rs.zone, "p.example.com."), ",") + " r=" + strings.Join(ddnsPolA(rs.zone, "r.example.com."), ",")
	}

	// Park the apply loop on an unrelated write W0.
	reached, release := gate.arm(state)
	w0 := make(chan error, 1)
	go func() { w0 <- c.ProposeAddRecord("example.com.", "u.example.com.", "A", "IN", 300, "192.0.2.99") }()
	ddnsBatchWait(t, reached, "W0 apply")
	// W1 (API delete of the prerequisite RR) enters the log, unapplied.
	ci := ddnsPolCommit(c)
	w1 := make(chan error, 1)
	go func() { w1 <- c.ProposeDeleteRecordData("example.com.", "p.example.com.", "A", "192.0.2.80") }()
	ddnsBatchWaitCommit(t, c, ci, "W1")
	// The UPDATE plans against the state without W1 (its prerequisite holds
	// there) and its batch is appended after W1.
	pre := ddnsPolAdd(t, "p.example.com.", "192.0.2.80")
	pre.TTL = 0 // RFC 2136 §2.4.2 value-dependent "RR exists"
	ci = ddnsPolCommit(c)
	done := make(chan ddnsPolResult, 1)
	go func() {
		done <- ddnsPolUpdateWithPrereq(t, rs.addr, key, pre, ddnsPolDelRR(t, "r.example.com.", "192.0.2.81"), ddnsPolAdd(t, "r.example.com.", "192.0.2.90"))
	}()
	ddnsBatchWaitCommit(t, c, ci, "the UPDATE batch")
	close(release)
	res := ddnsBatchWait(t, done, "UPDATE response")
	if err := ddnsBatchWait(t, w0, "W0"); err != nil {
		t.Fatalf("W0: %v", err)
	}
	if err := ddnsBatchWait(t, w1, "W1"); err != nil {
		t.Fatalf("W1: %v", err)
	}
	_, states := gate.disarm()
	ddnsPolExpect(t, "stale plan re-planned", res, protocol.RcodeNXRRSet, true)
	for _, s := range states {
		if strings.Contains(s, "192.0.2.90") || !strings.Contains(s, "192.0.2.81") {
			t.Errorf("stale UPDATE plan became visible: %q (states %q)", s, states)
		}
	}
	if got := state(); got != "p= r=192.0.2.81" {
		t.Errorf("final state %q, want %q", got, "p= r=192.0.2.81")
	}
}

// F582: an UPDATE with a value-dependent prerequisite on the apex SOA is
// applied only if the zone did not change between its planning and its
// apply; a write committed in between (here an unrelated add, which bumps
// the serial) makes it re-plan and fail its prerequisite (NXRRSET). Gated
// like F533; control: an UPDATE without an SOA prerequisite is not
// re-planned by an unrelated write.
func TestDDNSRaftBatch_F582_SOAPrereqGuarded(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	for _, withSOA := range []bool{true, false} {
		t.Run(fmt.Sprintf("soa_prereq=%v", withSOA), func(t *testing.T) {
			rs, key := ddnsBatchServe(t)
			c := rs.cluster
			rs.zone.Lock()
			s := rs.zone.SOA
			rs.zone.Records[ddnsPolZone] = append(rs.zone.Records[ddnsPolZone], zone.Record{Name: ddnsPolZone, TTL: s.TTL, Class: "IN", Type: "SOA",
				RData: fmt.Sprintf("%s %s %d %d %d %d %d", s.MName, s.RName, s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum)})
			rs.zone.Unlock()
			serial := func() uint32 {
				rs.zone.RLock()
				defer rs.zone.RUnlock()
				return rs.zone.SOA.Serial
			}
			soaPrereq := func(n uint32) *protocol.ResourceRecord {
				rs.zone.RLock()
				soa := *rs.zone.SOA
				rs.zone.RUnlock()
				return &protocol.ResourceRecord{Name: ddnsPolName(t, ddnsPolZone), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 0,
					Data: &protocol.RDataSOA{MName: ddnsPolName(t, soa.MName), RName: ddnsPolName(t, soa.RName), Serial: n, Refresh: soa.Refresh, Retry: soa.Retry, Expire: soa.Expire, Minimum: soa.Minimum}}
			}
			gate := newDDNSBatchGate(rs.manager)
			reached, release := gate.arm(func() string { return strings.Join(ddnsPolA(rs.zone, "r.example.com."), ",") })
			w0 := make(chan error, 1)
			go func() { w0 <- c.ProposeAddRecord("example.com.", "u0.example.com.", "A", "IN", 300, "192.0.2.98") }()
			ddnsBatchWait(t, reached, "W0 apply")
			planSerial := serial()
			ci := ddnsPolCommit(c)
			w1 := make(chan error, 1)
			go func() { w1 <- c.ProposeAddRecord("example.com.", "u1.example.com.", "A", "IN", 300, "192.0.2.99") }()
			ddnsBatchWaitCommit(t, c, ci, "W1")
			var pre *protocol.ResourceRecord
			if withSOA {
				pre = soaPrereq(planSerial)
			}
			ci = ddnsPolCommit(c)
			done := make(chan ddnsPolResult, 1)
			go func() {
				done <- ddnsPolUpdateWithPrereq(t, rs.addr, key, pre, ddnsPolAdd(t, "r.example.com.", "192.0.2.90"))
			}()
			ddnsBatchWaitCommit(t, c, ci, "the UPDATE batch")
			close(release)
			res := ddnsBatchWait(t, done, "UPDATE response")
			for _, ch := range []chan error{w0, w1} {
				if err := ddnsBatchWait(t, ch, "API write"); err != nil {
					t.Fatalf("API write: %v", err)
				}
			}
			_, states := gate.disarm()
			if withSOA {
				ddnsPolExpect(t, "stale SOA prerequisite", res, protocol.RcodeNXRRSet, true)
				ddnsPolExpectA(t, "after", rs.zone, "r.example.com.")
				for _, st := range states {
					if st != "" {
						t.Errorf("stale UPDATE became visible: states %q", states)
					}
				}
				return
			}
			ddnsPolExpect(t, "no SOA prerequisite", res, protocol.RcodeSuccess, true)
			ddnsPolExpectA(t, "after", rs.zone, "r.example.com.", "192.0.2.90")
		})
	}
}

// An UPDATE whose plan exceeds cluster.MaxZoneBatchOps record changes is
// REFUSED (local policy limit, RFC 2136 §2.2) without proposing anything.
// The wire format caps an UPDATE at 512 update RRs, so the oversized plan
// comes from one "delete RRset" RR expanding to many removals.
func TestDDNSRaftBatch_TooManyOpsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a single-node Raft cluster")
	}
	rs, key := ddnsBatchServe(t)
	fill := func(name string, n int) {
		recs := make([]zone.Record, 0, n)
		for i := 0; i < n; i++ {
			recs = append(recs, zone.Record{Name: name, TTL: 300, Class: "IN", Type: "A", RData: fmt.Sprintf("198.51.%d.%d", i/250, i%250+1)})
		}
		rs.zone.Lock()
		rs.zone.Records[name] = recs
		rs.zone.Unlock()
	}
	fill("big.example.com.", cluster.MaxZoneBatchOps+1)
	fill("ok.example.com.", cluster.MaxZoneBatchOps)

	before := ddnsPolCommit(rs.cluster)
	ddnsPolExpect(t, "delete RRset of 1025 RRs", ddnsPolUpdate(t, rs.addr, key, ddnsPolDelRRset(t, "big.example.com.", protocol.TypeA)), protocol.RcodeRefused, true)
	if after := ddnsPolCommit(rs.cluster); after != before {
		t.Errorf("refused UPDATE advanced the commit index %d -> %d", before, after)
	}
	if n := len(ddnsPolA(rs.zone, "big.example.com.")); n != cluster.MaxZoneBatchOps+1 {
		t.Errorf("refused UPDATE changed the zone: %d RRs left", n)
	}
	ddnsPolExpect(t, "delete RRset of 1024 RRs", ddnsPolUpdate(t, rs.addr, key, ddnsPolDelRRset(t, "ok.example.com.", protocol.TypeA)), protocol.RcodeSuccess, true)
	if d := ddnsPolCommit(rs.cluster) - before; d != 1 {
		t.Errorf("1024-change UPDATE = %d Raft entries, want 1", d)
	}
	ddnsPolExpectA(t, "accepted", rs.zone, "ok.example.com.")
}

// fakeDDNSBatchCluster scripts ProposeZoneBatch results.
type fakeDDNSBatchCluster struct {
	results    []error
	proposals  int
	fpCalls    int
	lastNames  []string
	lastOps    []cluster.ZoneOp
	lastPre    cluster.ZoneBatchPrecondition
	fpErr      error
	fpSequence int
}

func (f *fakeDDNSBatchCluster) ZoneFingerprint(_ string, names []string) (string, error) {
	f.fpCalls++
	f.lastNames = append([]string(nil), names...)
	if f.fpErr != nil {
		return "", f.fpErr
	}
	f.fpSequence++
	return fmt.Sprintf("fp-%d", f.fpSequence), nil
}

func (f *fakeDDNSBatchCluster) ZoneContentFingerprint(_ string) (string, error) {
	f.fpCalls++
	f.lastNames = nil
	if f.fpErr != nil {
		return "", f.fpErr
	}
	f.fpSequence++
	return fmt.Sprintf("zone-fp-%d", f.fpSequence), nil
}

func (f *fakeDDNSBatchCluster) ProposeZoneBatch(_ string, ops []cluster.ZoneOp, pre cluster.ZoneBatchPrecondition) error {
	f.proposals++
	f.lastOps, f.lastPre = ops, pre
	if len(f.results) == 0 {
		return nil
	}
	err := f.results[0]
	f.results = f.results[1:]
	return err
}

func TestCommitUpdateBatch_Outcomes(t *testing.T) {
	newZone := func() *zone.Zone {
		z := xfrTSIGZone(0)
		z.Records["p.example.com."] = []zone.Record{{Name: "p.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.80"}}
		return z
	}
	req := &transfer.UpdateRequest{
		ZoneName:      "example.com.",
		Prerequisites: []transfer.UpdatePrerequisite{{Name: "P.example.com.", Type: protocol.TypeA, Class: protocol.ClassIN, RData: "192.0.2.80", Condition: transfer.PrecondExistsValue}},
		Updates: []transfer.UpdateOperation{
			{Name: "www.example.com.", Type: protocol.TypeA, RData: "192.0.2.2", Operation: transfer.UpdateOpDelete},
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 60, RData: "192.0.2.20", Operation: transfer.UpdateOpAdd},
		},
	}
	conflict := cluster.ErrZoneBatchConflict

	t.Run("one batch, precondition over prerequisite and update names", func(t *testing.T) {
		f := &fakeDDNSBatchCluster{}
		z := newZone()
		if err := commitUpdateBatch(f, z, req); err != nil {
			t.Fatalf("err = %v", err)
		}
		if f.proposals != 1 {
			t.Fatalf("proposals = %d, want 1", f.proposals)
		}
		if got := strings.Join(f.lastPre.Names, ","); got != "p.example.com.,www.example.com." {
			t.Errorf("precondition names = %q", got)
		}
		if f.lastPre.Fingerprint != "fp-1" {
			t.Errorf("fingerprint = %q, want the pre-plan fp-1", f.lastPre.Fingerprint)
		}
		want := []cluster.ZoneOp{
			{Op: cluster.ZoneOpDeleteRData, Name: "www.example.com.", Type: "A", RData: "192.0.2.2"},
			{Op: cluster.ZoneOpAdd, Name: "www.example.com.", Type: "A", Class: "IN", TTL: 60, RData: "192.0.2.20"},
		}
		if fmt.Sprint(f.lastOps) != fmt.Sprint(want) {
			t.Errorf("ops = %+v, want %+v", f.lastOps, want)
		}
		if got := strings.Join(ddnsPolA(z, "www.example.com."), ","); got != "192.0.2.2" {
			t.Errorf("commit mutated the zone locally: www A = %q", got)
		}
	})
	t.Run("conflict then success re-plans with a fresh fingerprint", func(t *testing.T) {
		f := &fakeDDNSBatchCluster{results: []error{conflict, nil}}
		if err := commitUpdateBatch(f, newZone(), req); err != nil {
			t.Fatalf("err = %v", err)
		}
		if f.proposals != 2 || f.fpCalls != 2 || f.lastPre.Fingerprint != "fp-2" {
			t.Errorf("proposals=%d fingerprints=%d last=%q, want 2/2/fp-2", f.proposals, f.fpCalls, f.lastPre.Fingerprint)
		}
	})
	t.Run("persistent conflict gives up after the bound (SERVFAIL)", func(t *testing.T) {
		f := &fakeDDNSBatchCluster{results: []error{conflict, conflict, conflict, conflict}}
		err := commitUpdateBatch(f, newZone(), req)
		if !errors.Is(err, cluster.ErrZoneBatchConflict) || errors.Is(err, transfer.ErrUpdateRefused) {
			t.Fatalf("err = %v, want a conflict error that is not a refusal", err)
		}
		if f.proposals != ddnsRaftMaxAttempts {
			t.Errorf("proposals = %d, want %d", f.proposals, ddnsRaftMaxAttempts)
		}
	})
	t.Run("op error is not retried (SERVFAIL)", func(t *testing.T) {
		opErr := &cluster.ZoneBatchOpError{Index: 0, Err: errors.New("rdata absent")}
		f := &fakeDDNSBatchCluster{results: []error{opErr}}
		err := commitUpdateBatch(f, newZone(), req)
		var got *cluster.ZoneBatchOpError
		if !errors.As(err, &got) || errors.Is(err, transfer.ErrUpdateRefused) || f.proposals != 1 {
			t.Fatalf("err = %v proposals = %d, want the op error once", err, f.proposals)
		}
	})
	t.Run("failed prerequisite proposes nothing (NXRRSET)", func(t *testing.T) {
		f := &fakeDDNSBatchCluster{}
		z := newZone()
		z.Records["p.example.com."] = nil
		if err := commitUpdateBatch(f, z, req); !errors.Is(err, transfer.ErrPrereqFailed) || f.proposals != 0 {
			t.Fatalf("err = %v proposals = %d", err, f.proposals)
		}
	})
	t.Run("no-op update proposes nothing", func(t *testing.T) {
		f := &fakeDDNSBatchCluster{}
		noop := &transfer.UpdateRequest{ZoneName: "example.com.", Updates: []transfer.UpdateOperation{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 300, RData: "192.0.2.2", Operation: transfer.UpdateOpAdd},
		}}
		if err := commitUpdateBatch(f, newZone(), noop); err != nil || f.proposals != 0 {
			t.Fatalf("err = %v proposals = %d", err, f.proposals)
		}
	})
	t.Run("too many record changes are refused", func(t *testing.T) {
		f := &fakeDDNSBatchCluster{}
		big := &transfer.UpdateRequest{ZoneName: "example.com."}
		for i := 0; i <= cluster.MaxZoneBatchOps; i++ {
			big.Updates = append(big.Updates, transfer.UpdateOperation{Name: fmt.Sprintf("b%d.example.com.", i), Type: protocol.TypeA, TTL: 300, RData: "192.0.2.1", Operation: transfer.UpdateOpAdd})
		}
		if err := commitUpdateBatch(f, newZone(), big); !errors.Is(err, transfer.ErrUpdateRefused) || f.proposals != 0 {
			t.Fatalf("err = %v proposals = %d, want ErrUpdateRefused and no proposal", err, f.proposals)
		}
	})
	t.Run("SOA prerequisite is guarded by the whole-zone fingerprint (F582)", func(t *testing.T) {
		f := &fakeDDNSBatchCluster{}
		z := newZone()
		z.Records["example.com."] = append(z.Records["example.com."], zone.Record{Name: "example.com.", TTL: 300, Class: "IN", Type: "SOA", RData: "ns1.example.com. admin.example.com. 2 3600 600 86400 300"})
		soaReq := &transfer.UpdateRequest{
			ZoneName:      "example.com.",
			Prerequisites: []transfer.UpdatePrerequisite{{Name: "example.com.", Type: protocol.TypeSOA, Class: protocol.ClassIN, RData: "ns1.example.com. admin.example.com. 2 3600 600 86400 300", Condition: transfer.PrecondExistsValue}},
			Updates:       req.Updates,
		}
		if err := commitUpdateBatch(f, z, soaReq); err != nil {
			t.Fatalf("err = %v", err)
		}
		if !f.lastPre.Zone || f.lastPre.Fingerprint != "zone-fp-1" {
			t.Errorf("precondition = %+v, want the whole-zone guard", f.lastPre)
		}
		g := &fakeDDNSBatchCluster{}
		if err := commitUpdateBatch(g, newZone(), req); err != nil || g.lastPre.Zone {
			t.Errorf("non-SOA UPDATE: err=%v whole-zone guard=%v, want the per-name guard", err, g.lastPre.Zone)
		}
	})
	t.Run("fingerprint failure proposes nothing", func(t *testing.T) {
		f := &fakeDDNSBatchCluster{fpErr: errors.New("zone gone")}
		if err := commitUpdateBatch(f, newZone(), req); err == nil || f.proposals != 0 {
			t.Fatalf("err = %v proposals = %d", err, f.proposals)
		}
	})
}
