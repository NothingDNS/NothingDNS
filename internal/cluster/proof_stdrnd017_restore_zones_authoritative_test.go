package cluster

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// proofLoadZone parses a minimal, well-formed one-SOA zone and installs it into
// m, mirroring how the cluster package seeds a zone manager in production.
//
// NOTE on key form: LoadZone stores under z.Origin, which the zone parser
// renders fully qualified — "a.example." with a trailing dot — and Manager.Get
// is an exact map lookup that does NOT normalize its argument. Asserting on
// "a.example" would miss and report a false failure, so every name here carries
// the trailing dot.
func proofLoadZone(t *testing.T, m *zone.Manager, origin string) {
	t.Helper()
	txt := `$ORIGIN ` + origin + `.
@	IN SOA	ns1.` + origin + `. hostmaster.` + origin + `. ( 1 3600 600 604800 86400 )
	IN NS	ns1.` + origin + `.
ns1	IN A	192.0.2.1
`
	z, err := zone.ParseFile(origin, strings.NewReader(txt))
	if err != nil {
		t.Fatalf("ParseFile(%q): %v", origin, err)
	}
	m.LoadZone(z, "")
}

func proofZoneNames(m *zone.Manager) []string {
	var out []string
	for name := range m.List() {
		out = append(out, name)
	}
	return out
}

// TestProofRound017_RestoreZonesIsAuthoritative drives the real snapshot
// producer and consumer end to end against a real zone.Manager.
//
// A Raft snapshot is the COMPLETE state machine — installing one must leave the
// follower's zone set equal to the leader's (RFC 9590 §7: the snapshot replaces
// the entire log prefix it covers). snapshotZones() documents itself as
// serializing "the FULL zone store", so restoreZones() is authoritative input.
//
// It is not treated that way: it only adds/overwrites the zones named in the
// payload. A zone the leader has since deleted is therefore resurrected on any
// follower that catches up by snapshot rather than by log replay — precisely
// the situation a snapshot exists to serve, since the log entry carrying the
// delete has been compacted away by the time the snapshot is needed.
func TestProofRound017_RestoreZonesIsAuthoritative(t *testing.T) {
	const keep = "a.example."  // present on both sides
	const stale = "b.example." // deleted on the leader while the follower was offline

	// Leader: zone b was deleted while this follower was offline, so the log
	// entry carrying the delete has since been compacted out of the leader's
	// log. The snapshot is the only remaining way for the follower to learn it.
	leaderMgr := zone.NewManager()
	proofLoadZone(t, leaderMgr, "a.example")

	// Follower: never saw the delete, so it still holds a AND the stale b.
	followerMgr := zone.NewManager()
	proofLoadZone(t, followerMgr, "a.example")
	proofLoadZone(t, followerMgr, "b.example")

	leader := &Cluster{zoneManager: leaderMgr}
	follower := &Cluster{zoneManager: followerMgr}

	payload, err := leader.snapshotZones()
	if err != nil {
		t.Fatalf("snapshotZones: %v", err)
	}

	// Precondition: the payload really is a full-store snapshot — it names the
	// zone the leader has and omits the one it deleted. Checked on the exact
	// keys the manager uses, so this cannot pass vacuously.
	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, ok := decoded[keep]; !ok {
		t.Fatalf("precondition: leader payload should contain %q, got keys %v", keep, proofZoneNames(leaderMgr))
	}
	if _, ok := decoded[stale]; ok {
		t.Fatalf("precondition: leader payload should omit %q, got keys %v", stale, proofZoneNames(leaderMgr))
	}

	if err := follower.restoreZones(payload); err != nil {
		t.Fatalf("restoreZones: %v", err)
	}

	// Control: a zone present in the snapshot must be installed. This already
	// works today, which is what proves the harness itself is sound.
	if _, ok := followerMgr.Get(keep); !ok {
		t.Errorf("control: zone present in snapshot was not installed; follower now has %v", proofZoneNames(followerMgr))
	}

	// The defect: a zone absent from an authoritative full-state snapshot must
	// be dropped, otherwise the follower diverges permanently from the leader.
	if _, ok := followerMgr.Get(stale); ok {
		t.Errorf("FAIL: after installing the leader's full-state snapshot the follower still serves %s (leader=%v follower=%v)",
			stale, proofZoneNames(leaderMgr), proofZoneNames(followerMgr))
	}
}

// TestProofRound017_RestoreZonesPayloadBoundaries covers the neighbouring paths
// the fix touches: a corrupt payload must be rejected without mutating state,
// and an empty (but well-formed) payload is a legitimate full-state snapshot
// meaning "this cluster has no zones" — so it must CLEAR the follower's zones
// rather than being silently treated as a no-op.
func TestProofRound017_RestoreZonesPayloadBoundaries(t *testing.T) {
	const keep = "a.example."

	mgr := zone.NewManager()
	proofLoadZone(t, mgr, "a.example")
	c := &Cluster{zoneManager: mgr}

	if err := c.restoreZones([]byte("{not json")); err == nil {
		t.Error("FAIL: restoreZones accepted a corrupt payload")
	}
	// A rejected payload must leave the existing zone set untouched.
	if _, ok := mgr.Get(keep); !ok {
		t.Errorf("FAIL: corrupt payload mutated the zone set; now has %v", proofZoneNames(mgr))
	}

	// An empty snapshot is authoritative: the cluster has no zones.
	if err := c.restoreZones([]byte(`{}`)); err != nil {
		t.Fatalf("restoreZones(empty): %v", err)
	}
	if _, ok := mgr.Get(keep); ok {
		t.Errorf("FAIL: empty full-state snapshot left %s loaded (%v)", keep, proofZoneNames(mgr))
	}
}
