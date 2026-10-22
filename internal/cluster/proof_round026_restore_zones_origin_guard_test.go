package cluster

// Round 026 (2026-10-22): restoreZones (Raft snapshot install) and
// handleZoneUpdate (gossip full/reload) parse peer payloads with
// zone.ParseFile and install via Manager.LoadZone, whose own doc comment
// says it performs no validation. Every other load path gates on
// z.Validate() (loadZoneFile in cmd/nothingdns, Manager.Load) and
// slave_persist.go additionally refuses an origin mismatch. A payload whose
// text carries no $ORIGIN parses with Origin "." — exactly what Validate
// calls "has no origin" — yet the unguarded install registered it under
// ".", and zone.nameInZone answers true for every name against a "."
// origin: one malformed payload from a buggy or compromised peer turned
// this node into an authoritative server for the entire DNS namespace.
// The guard validates each parsed zone exactly where the parse error is
// already handled: restoreZones aborts the whole install (its
// parse-before-mutate atomicity contract), handleZoneUpdate warns and
// drops the payload.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// round026OriginlessZone has no $ORIGIN and no apex NS: it parses with
// Origin "." and a delegation NS in z.NS — the exact shape round-061 proved
// Validate must reject.
const round026OriginlessZone = "$TTL 3600\n" +
	"@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 604800 60\n" +
	"sub IN NS ns.sub.example.com.\n"

func round026Cluster(mgr *zone.Manager) *Cluster {
	return &Cluster{zoneManager: mgr, logger: util.NewLogger(util.ERROR, util.TextFormat, nil)}
}

func TestRestoreZones_RejectsOriginlessPayload(t *testing.T) {
	mgr := zone.NewManager()
	c := round026Cluster(mgr)

	payload, err := json.Marshal(map[string]string{"example.com.": round026OriginlessZone})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	if err := c.restoreZones(payload); err == nil {
		if z, ok := mgr.Get("."); ok && z != nil {
			t.Fatalf("PROBLEM CONFIRMED: originless payload installed as the root zone (Origin %q); the node now answers authoritatively for every name", z.Origin)
		}
		t.Fatal("PROBLEM CONFIRMED: restoreZones accepted a payload zone.Validate rejects (no $ORIGIN)")
	}
	if z, ok := mgr.Get("."); ok && z != nil {
		t.Fatalf("originless zone installed under %q despite the returned error", z.Origin)
	}
	if z, ok := mgr.Get("example.com."); ok && z != nil {
		t.Fatalf("originless zone installed under %q", z.Origin)
	}
}

func TestHandleZoneUpdate_DropsOriginlessPayload(t *testing.T) {
	mgr := zone.NewManager()
	c := round026Cluster(mgr)

	c.handleZoneUpdate(ZoneUpdatePayload{
		ZoneName: "example.com.",
		Action:   "full",
		Serial:   1,
		RawZone:  []byte(round026OriginlessZone),
	})

	if z, ok := mgr.Get("."); ok && z != nil {
		t.Fatalf("PROBLEM CONFIRMED: gossip full update installed an originless zone as the root zone (Origin %q)", z.Origin)
	}
	if z, ok := mgr.Get("example.com."); ok && z != nil {
		t.Fatalf("originless gossip zone installed under %q", z.Origin)
	}
}

func TestRestoreZones_StillInstallsWellFormedPayload(t *testing.T) {
	mgr := zone.NewManager()
	c := round026Cluster(mgr)

	good := "$ORIGIN example.com.\n$TTL 3600\n" +
		"@ IN SOA ns1.example.com. hostmaster.example.com. 1 3600 900 604800 60\n" +
		"@ IN NS ns1.example.com.\n" +
		"www IN A 192.0.2.1\n"
	payload, err := json.Marshal(map[string]string{"example.com.": good})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	if err := c.restoreZones(payload); err != nil {
		t.Fatalf("control: well-formed payload rejected: %v", err)
	}
	z, ok := mgr.Get("example.com.")
	if !ok || z == nil {
		t.Fatal("control: well-formed zone not installed")
	}
	if !strings.EqualFold(z.Origin, "example.com.") {
		t.Fatalf("control: unexpected origin %q", z.Origin)
	}
}
