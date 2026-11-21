package rpz

import (
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
