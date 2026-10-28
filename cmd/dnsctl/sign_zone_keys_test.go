package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// sign-zone with no key files generates a KSK and a ZSK and keeps them in the
// key directory, so a second run signs with the same keys (and the DS in the
// parent stays valid) instead of silently minting new ones (F764).
func TestSignZoneKeepsGeneratedKeys(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "ex.zone")
	zoneText := "$ORIGIN ex.test.\n$TTL 300\n@ IN SOA ns1.ex.test. h.ex.test. 1 3600 600 86400 300\n@ IN NS ns1.ex.test.\nns1 IN A 192.0.2.53\n"
	if err := os.WriteFile(in, []byte(zoneText), 0o600); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(dir, "keys")
	out1 := filepath.Join(dir, "one.signed")
	out2 := filepath.Join(dir, "two.signed")
	args := func(out string) []string {
		return []string{"--zone", "ex.test", "--input", in, "--output", out, "--keydir", keys}
	}
	if err := cmdDNSSECSignZone(args(out1)); err != nil {
		t.Fatal(err)
	}
	private, _ := filepath.Glob(filepath.Join(keys, "Kex.test.+*.private"))
	public, _ := filepath.Glob(filepath.Join(keys, "Kex.test.+*.key"))
	if len(private) != 2 || len(public) != 2 {
		t.Fatalf("key directory holds %d private and %d public key files, want 2 and 2", len(private), len(public))
	}
	if err := cmdDNSSECSignZone(args(out2)); err != nil {
		t.Fatal(err)
	}
	if again, _ := filepath.Glob(filepath.Join(keys, "Kex.test.+*.key")); len(again) != 2 {
		t.Errorf("second run left %d public key files, want the same 2", len(again))
	}
	dnskeys := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, l := range strings.Split(string(data), "\n") {
			if strings.Contains(l, "DNSKEY") && !strings.Contains(l, "RRSIG") {
				lines = append(lines, l)
			}
		}
		sort.Strings(lines)
		return strings.Join(lines, "\n")
	}
	if a, b := dnskeys(out1), dnskeys(out2); a == "" || a != b {
		t.Errorf("DNSKEY records differ between runs:\n%s\n---\n%s", a, b)
	}
}
