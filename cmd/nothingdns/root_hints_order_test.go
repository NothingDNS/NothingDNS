package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRootHintsFileAddressBeforeNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named.root")
	body := "a.root. 3600 IN A 192.0.2.1\n" +
		"a.root. 3600 IN AAAA 2001:db8::1\n" +
		". 3600 IN NS a.root.\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	hints, err := loadRootHintsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(hints) != 1 || len(hints[0].IPv4) != 1 || hints[0].IPv4[0] != "192.0.2.1" ||
		len(hints[0].IPv6) != 1 || hints[0].IPv6[0] != "2001:db8::1" {
		t.Fatalf("address-first root hint parsed as %#v", hints)
	}
}
