package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const glueZoneFile = `$ORIGIN deleg.test.
$TTL 3600
@       IN  SOA ns1.deleg.test. admin.deleg.test. ( 1 3600 600 86400 300 )
@       IN  NS  ns1.deleg.test.
ns1     IN  A   192.0.2.1
sub     IN  NS  ns1.sub.deleg.test.
ns1.sub IN  A   192.0.2.50
`

// loadTestZoneFile parses a zone through the real file parser, which is what makes
// this test meaningful: the defect lived in the parser leaving Record.Name
// relative, and a hand-built zone map would not reproduce it.
func loadTestZoneFile(t *testing.T, origin, body string) *zone.Zone {
	t.Helper()
	path := filepath.Join(t.TempDir(), origin+"zone")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write zone: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open zone: %v", err)
	}
	defer f.Close()
	z, err := zone.ParseFile(path, f)
	if err != nil {
		t.Fatalf("parse zone: %v", err)
	}
	return z
}

// TestReferral_CarriesGlue is the regression for a delegation going out with
// no glue. The zone parser keyed Records by the absolute owner name but left
// Record.Name as the file's relative label ("ns1.sub"), so the glue RR was
// built with a relative owner, failed to match the NS target during response
// minimisation, and was dropped. The referral then pointed at a nameserver
// inside the delegated zone with no address — the child zone was unreachable.
func TestReferral_CarriesGlue(t *testing.T) {
	h := newTestHandler()
	z := loadTestZoneFile(t, "deleg.test.", glueZoneFile)
	h.zones["deleg.test."] = z
	h.RebuildZoneTree()

	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, newTestQuery(t, "host.sub.deleg.test.", protocol.TypeA))

	resp := w.msg
	if resp == nil {
		t.Fatal("no response")
	}
	if resp.Header.Flags.AA {
		t.Error("AA set on a referral")
	}

	var sawNS bool
	for _, rr := range resp.Authorities {
		if rr != nil && rr.Type == protocol.TypeNS {
			sawNS = true
		}
	}
	if !sawNS {
		t.Fatal("referral has no NS record in the authority section")
	}

	var glue *protocol.ResourceRecord
	for _, rr := range resp.Additionals {
		if rr != nil && rr.Type == protocol.TypeA {
			glue = rr
		}
	}
	if glue == nil {
		t.Fatal("referral carries no glue A record; the child zone is unreachable")
	}
	if got := glue.Name.String(); got != "ns1.sub.deleg.test." {
		t.Errorf("glue owner = %q, want the absolute NS target %q", got, "ns1.sub.deleg.test.")
	}
}

// TestParseFile_RecordNameIsAbsolute pins the root cause directly: whatever
// reads Record.Name must get the same name the Records map is keyed by.
func TestParseFile_RecordNameIsAbsolute(t *testing.T) {
	z := loadTestZoneFile(t, "deleg.test.", glueZoneFile)

	for owner, recs := range z.Records {
		for _, rec := range recs {
			if rec.Name != owner {
				t.Errorf("record %s/%s: Name = %q, want the map key %q",
					owner, rec.Type, rec.Name, owner)
			}
		}
	}
}

const entZoneFile = `$ORIGIN ent.test.
$TTL 3600
@                IN  SOA ns1.ent.test. admin.ent.test. ( 1 3600 600 86400 300 )
@                IN  NS  ns1.ent.test.
ns1              IN  A   192.0.2.1
host.enta.entb   IN  A   192.0.2.40
`

// TestEmptyNonTerminal_IsNoDataNotNXDOMAIN pins the end-to-end answer. The
// handler asked NameExists ("does this name own records?") where the question
// is "does this name exist?", so it answered NXDOMAIN at every empty
// non-terminal. NXDOMAIN asserts nothing exists at or below the name; an RFC
// 8020 resolver that caches it for "entb.ent.test." then refuses
// "host.enta.entb.ent.test." — a name this zone serves.
func TestEmptyNonTerminal_IsNoDataNotNXDOMAIN(t *testing.T) {
	h := newTestHandler()
	h.zones["ent.test."] = loadTestZoneFile(t, "ent.test.", entZoneFile)
	h.RebuildZoneTree()

	tests := []struct {
		qname     string
		wantRcode uint8
		wantAns   int
		why       string
	}{
		{"host.enta.entb.ent.test.", protocol.RcodeSuccess, 1, "owns an A record"},
		{"enta.entb.ent.test.", protocol.RcodeSuccess, 0, "empty non-terminal -> NODATA"},
		{"entb.ent.test.", protocol.RcodeSuccess, 0, "empty non-terminal -> NODATA"},
		{"nothere.ent.test.", protocol.RcodeNameError, 0, "genuinely absent -> NXDOMAIN"},
		{"a.b.nothere.ent.test.", protocol.RcodeNameError, 0, "genuinely absent -> NXDOMAIN"},
	}
	for _, tc := range tests {
		w := newCaptureWriter("192.0.2.100", "tcp")
		h.ServeDNS(w, newTestQuery(t, tc.qname, protocol.TypeA))
		if w.msg == nil {
			t.Errorf("%s: no response", tc.qname)
			continue
		}
		if got := w.msg.Header.Flags.RCODE; got != tc.wantRcode {
			t.Errorf("%s: rcode = %d, want %d (%s)", tc.qname, got, tc.wantRcode, tc.why)
		}
		if got := len(w.msg.Answers); got != tc.wantAns {
			t.Errorf("%s: %d answers, want %d", tc.qname, got, tc.wantAns)
		}
	}
}
