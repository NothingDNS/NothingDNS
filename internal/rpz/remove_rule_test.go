package rpz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveRulesReportWhetherOneExisted(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.rpz")
	const zoneText = "bad.example.rpz-zone. 300 IN CNAME .\nns.evil.example.rpz-nsdname. 300 IN CNAME .\n"
	if err := os.WriteFile(file, []byte(zoneText), 0o600); err != nil {
		t.Fatal(err)
	}
	e := NewEngine(Config{Enabled: true, Files: []string{file}})
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}

	if e.RemoveNSDNAMERule("bad.example") || e.RemoveQNAMERule("ns.evil.example") {
		t.Fatal("a rule of the other trigger was reported removed")
	}
	if e.QNAMEPolicy("bad.example") == nil || e.NSDNAMEPolicy("ns.evil.example") == nil {
		t.Fatal("removing with the wrong trigger changed the rules")
	}
	if !e.RemoveNSDNAMERule("NS.Evil.Example.") || e.NSDNAMEPolicy("ns.evil.example") != nil {
		t.Fatal("NSDNAME rule not removed (pattern is case- and dot-insensitive)")
	}
	if !e.RemoveQNAMERule("bad.example") || e.RemoveQNAMERule("bad.example") {
		t.Fatal("QNAME removal result wrong: want true, then false")
	}
}
