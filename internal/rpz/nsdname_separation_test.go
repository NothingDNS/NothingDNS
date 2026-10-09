package rpz

import (
	"os"
	"path/filepath"
	"testing"
)

// F645: NSDNAME triggers shared the QNAME map, so an NSDNAME passthru for a
// nameserver name replaced a QNAME block on the same name, and NSDNAME rules
// fired for queries of the nameserver name itself.
func TestNSDNAMERulesDoNotShadowQNAMERules(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.rpz")
	zone := "bad.example.com.rpz-nsdname. 300 IN CNAME rpz-passthru.\n" +
		"bad.example.com.rpz-zone. 300 IN CNAME .\n" +
		"ns1.example.net.rpz-nsdname. 300 IN CNAME .\n" +
		"*.evil-ns.example.rpz-nsdname. 300 IN CNAME .\n"
	if err := os.WriteFile(file, []byte(zone), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Config{Enabled: true, Files: []string{file}})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}

	if r := e.QNAMEPolicy("bad.example.com."); r == nil || r.Action != ActionNXDOMAIN || r.Trigger != TriggerQNAME {
		t.Errorf("QNAME block replaced by the NSDNAME passthru: %+v", r)
	}
	if r := e.NSDNAMEPolicy("bad.example.com."); r == nil || r.Action != ActionPassThrough {
		t.Errorf("NSDNAME passthru lost: %+v", r)
	}
	if r := e.QNAMEPolicy("ns1.example.net."); r != nil {
		t.Errorf("NSDNAME rule fired for a query of the nameserver name: %+v", r)
	}
	if r := e.NSDNAMEPolicy("ns1.example.net."); r == nil || r.Action != ActionNXDOMAIN {
		t.Errorf("NSDNAME block missing: %+v", r)
	}
	if r := e.NSDNAMEPolicy("a.evil-ns.example."); r == nil {
		t.Error("wildcard NSDNAME rule did not match")
	}
	if r := e.NSDNAMEPolicy("www.example.org."); r != nil {
		t.Errorf("unrelated nameserver matched: %+v", r)
	}
	if got := e.Stats().QNAMERules; got != 4 {
		t.Errorf("Stats().QNAMERules = %d, want 4 (QNAME + NSDNAME)", got)
	}
	if got := len(e.ListQNAMERules()); got != 4 {
		t.Errorf("ListQNAMERules returned %d rules, want 4", got)
	}
}
