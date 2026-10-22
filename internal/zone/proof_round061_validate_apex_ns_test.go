package zone

// Round-061 proof + regression: Zone.Validate accepted a zone file with NO
// apex NS whenever any delegation NS existed, because the NS check counted
// z.NS — which handleSpecialRecord fills with EVERY NS record, delegations
// included. Such a zone loaded through Manager.Load / loadZoneFile, and the
// first mutation made WriteZone's apex fallback (writer.go) publish the
// delegation's nameserver as an apex NS in the persisted zone file, where
// the next reload adopted it as real apex NS data. Records[z.Origin] (and,
// for programmatically built zones, z.NS entries owned by the apex) is the
// source of truth the check must use.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const round061ZoneWithoutApexNS = `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 60
sub IN NS ns.sub.example.com.
www IN A 192.0.2.1
`

const round061ZoneWithApexNS = `$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 60
@ IN NS ns1.example.com.
sub IN NS ns.sub.example.com.
www IN A 192.0.2.1
`

// A zone file with no apex NS must fail validation even though its
// delegation NS populated z.NS — that is what the check's own
// "missing NS records" error means (RFC 1034: the apex carries the zone's NS set).
func TestValidate_RejectsMissingApexNS(t *testing.T) {
	z, err := ParseFile("missing-apex-ns.zone", strings.NewReader(round061ZoneWithoutApexNS))
	if err != nil {
		t.Fatalf("FAIL: fixture failed to parse: %v", err)
	}
	if z.SOA == nil {
		t.Fatalf("FAIL: fixture unexpectedly has no SOA")
	}
	// Fixture sanity: the delegation NS reached z.NS, and the apex owns no NS
	// in the source of truth — without both, the assertion below proves nothing.
	if len(z.NS) == 0 {
		t.Fatalf("FAIL: fixture invalid — delegation NS did not reach z.NS")
	}
	for _, rec := range z.Records[z.Origin] {
		if strings.EqualFold(rec.Type, "NS") {
			t.Fatalf("FAIL: fixture invalid — apex NS present in Records: %+v", rec)
		}
	}

	if err := z.Validate(); err == nil {
		t.Errorf("FAIL: zone with no apex NS validated; delegation NS (%+v) satisfied the NS check", z.NS)
	}
}

// The production gate: Manager.Load must refuse the same file. Before the
// fix it installed the zone; one mutation then made ExportZone/WriteZone
// publish the delegation's nameserver at the apex.
func TestManagerLoad_RejectsZoneWithoutApexNS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing-apex-ns.zone")
	if err := os.WriteFile(path, []byte(round061ZoneWithoutApexNS), 0o644); err != nil {
		t.Fatalf("FAIL: fixture write: %v", err)
	}

	m := NewManager()
	m.SetZoneDir("")

	if err := m.Load("example.com.", path); err != nil {
		// Fixed behavior: the malformed zone is rejected at the gate.
		return
	}

	// Pre-fix behavior: the zone loaded. Demonstrate the downstream corruption
	// before failing, so the red run records the real impact.
	if err := m.AddRecord("example.com.", Record{Name: "api.example.com.", TTL: 300, Type: "A", RData: "192.0.2.99"}); err != nil {
		t.Errorf("FAIL: Load accepted a zone file with no apex NS (mutation failed: %v)", err)
		return
	}
	out, err := m.ExportZone("example.com.")
	if err != nil {
		t.Errorf("FAIL: Load accepted a zone file with no apex NS (export failed: %v)", err)
		return
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "@") && strings.Contains(trimmed, "IN") && strings.Contains(trimmed, "NS") && strings.Contains(trimmed, "ns.sub.example.com.") {
			t.Errorf("FAIL: Load accepted a zone file with no apex NS; after one mutation the zone publishes the delegation NS at the apex: %q", trimmed)
			return
		}
	}
	t.Errorf("FAIL: Load accepted a zone file with no apex NS")
}

// Control: the same zone WITH its apex NS must keep validating, loading and
// exporting its own apex NS — before and after the fix.
func TestValidate_ApexNSZoneStillValid(t *testing.T) {
	z, err := ParseFile("with-apex-ns.zone", strings.NewReader(round061ZoneWithApexNS))
	if err != nil {
		t.Fatalf("FAIL: control fixture failed to parse: %v", err)
	}
	if err := z.Validate(); err != nil {
		t.Fatalf("FAIL: control zone with apex NS rejected: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "with-apex-ns.zone")
	if err := os.WriteFile(path, []byte(round061ZoneWithApexNS), 0o644); err != nil {
		t.Fatalf("FAIL: control fixture write: %v", err)
	}
	m := NewManager()
	m.SetZoneDir("")
	if err := m.Load("example.com.", path); err != nil {
		t.Fatalf("FAIL: control zone rejected by Manager.Load: %v", err)
	}
	out, err := m.ExportZone("example.com.")
	if err != nil {
		t.Fatalf("FAIL: control zone export failed: %v", err)
	}
	if !strings.Contains(out, "ns1.example.com.") {
		t.Errorf("FAIL: control zone export lost its apex NS")
	}
}
