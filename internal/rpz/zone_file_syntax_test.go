package rpz

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func loadRPZText(t *testing.T, content string) *Engine {
	t.Helper()
	file := filepath.Join(t.TempDir(), "policy.rpz")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Config{Enabled: true, Files: []string{file}})
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return e
}

// F859: TTL and class are optional in a master-file record (RFC 1035 §5.1),
// so "name CNAME ." is a complete RPZ rule, not a malformed line.
func TestRPZRecordWithoutTTLOrClassLoads(t *testing.T) {
	e := loadRPZText(t, "bad.example.com CNAME .\n*.ads.example.com CNAME *.\n")
	if r := e.QNAMEPolicy("bad.example.com."); r == nil || r.Action != ActionNXDOMAIN {
		t.Fatalf("bad.example.com: got %#v, want NXDOMAIN rule", r)
	}
	if r := e.QNAMEPolicy("x.ads.example.com."); r == nil || r.Action != ActionNODATA {
		t.Fatalf("x.ads.example.com: got %#v, want NODATA rule", r)
	}
	if n := e.Stats().ParseErrors; n != 0 {
		t.Fatalf("ParseErrors = %d, want 0", n)
	}
}

// F860: an absolute QNAME trigger owner below the policy zone apex (as an
// AXFR dump writes it) triggers on the name relative to the apex.
func TestRPZAbsoluteOwnerBelowPolicyApex(t *testing.T) {
	e := loadRPZText(t, "$TTL 300\n"+
		"rpz.example.com. 300 IN SOA localhost. hostmaster.localhost. 1 3600 600 86400 300\n"+
		"rpz.example.com. 300 IN NS localhost.\n"+
		"bad.example.com.rpz.example.com. 300 IN CNAME .\n"+
		"*.Wild.Example.com.RPZ.example.com. 300 IN CNAME *.\n")
	if r := e.QNAMEPolicy("bad.example.com."); r == nil || r.Action != ActionNXDOMAIN {
		t.Fatalf("bad.example.com: got %#v, want NXDOMAIN rule", r)
	}
	if r := e.QNAMEPolicy("a.wild.example.com."); r == nil || r.Action != ActionNODATA {
		t.Fatalf("a.wild.example.com: got %#v, want NODATA rule", r)
	}
	if r := e.QNAMEPolicy("bad.example.com.rpz.example.com."); r != nil {
		t.Fatalf("rule still keyed on the owner with the apex: %#v", r)
	}
}

// F861: a line that begins with a blank belongs to the last stated owner
// (RFC 1035 §5.1); it is not a record owned by its first token.
func TestRPZBlankOwnerContinuesPreviousOwner(t *testing.T) {
	e := loadRPZText(t, "ov.example.com IN A 192.0.2.9\n"+
		"    IN A 192.0.2.10\n"+
		"\tIN AAAA 2001:db8::10\n")
	r := e.QNAMEPolicy("ov.example.com.")
	if r == nil || r.Action != ActionOverride || len(r.Additional) != 2 {
		t.Fatalf("ov.example.com: got %#v, want override RRset of 3 records", r)
	}
	if r := e.QNAMEPolicy("in."); r != nil {
		t.Fatalf("indented record became a rule for %q", r.Pattern)
	}
}

// F862: a relative owner is relative to the $ORIGIN in force, which
// named-compilezone moves below the policy apex.
func TestRPZRelativeOwnerUnderSubOrigin(t *testing.T) {
	e := loadRPZText(t, "$ORIGIN rpz.example.com.\n"+
		"@ 300 IN SOA localhost. hostmaster.localhost. 1 3600 600 86400 300\n"+
		"$ORIGIN example.net.rpz.example.com.\n"+
		"bad CNAME .\n"+
		"$ORIGIN rpz-ip.rpz.example.com.\n"+
		"32.1.2.0.192 CNAME .\n")
	if r := e.QNAMEPolicy("bad.example.net."); r == nil || r.Action != ActionNXDOMAIN {
		t.Fatalf("bad.example.net: got %#v, want NXDOMAIN rule", r)
	}
	if r := e.ResponseIPPolicy([]net.IP{net.ParseIP("192.0.2.1")}); r == nil {
		t.Fatal("rpz-ip trigger under $ORIGIN rpz-ip.<apex> not loaded")
	}
	if r := e.QNAMEPolicy("bad."); r != nil {
		t.Fatalf("relative owner kept unqualified: %#v", r)
	}
}

// draft-vixie-dnsop-dns-rpz-00 §10: a CNAME to the trigger QNAME is the
// deprecated PASSTHRU encoding, still recognised (F884).
func TestRPZLegacyPassthruEncoding(t *testing.T) {
	f := t.TempDir() + "/p.rpz"
	body := "$TTL 60\n@ IN SOA ns.rpz. admin.rpz. 1 3600 600 86400 60\n@ IN NS ns.rpz.\n" +
		"*.azone.example.com CNAME garden.example.net.\n" +
		"ok.azone.example.com CNAME ok.azone.example.com.\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Config{Enabled: true, Files: []string{f}})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if r := e.QNAMEPolicy("ok.azone.example.com."); r == nil || r.Action != ActionPassThrough {
		t.Fatalf("ok.azone.example.com: %+v, want PASSTHRU", r)
	}
	if r := e.QNAMEPolicy("x.azone.example.com."); r == nil || r.Action != ActionCNAME {
		t.Fatalf("x.azone.example.com: %+v, want the walled-garden CNAME", r)
	}
}
