package transfer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F719: RFC 8976 §2.2.3 hash algorithm numbers (IANA): 1 = SHA384 (48-octet
// digest), 2 = SHA512 (64). The manager used to publish SHA-256 digests as 1.
func TestStreamedZONEMDUsesRFC8976AlgorithmNumbers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.test.zone")
	text := "$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\nns1 IN A 192.0.2.1\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	m := zone.NewManager()
	m.SetZONEMDEnabled(true)
	if err := m.Load("example.test.", path); err != nil {
		t.Fatal(err)
	}
	z, _ := m.Get("example.test.")

	check := func(label string, recs []*protocol.ResourceRecord, alg uint8, size int) {
		t.Helper()
		for _, r := range recs {
			if zm, ok := r.Data.(*protocol.RDataZONEMD); ok {
				if zm.Algorithm != alg || len(zm.Digest) != size {
					t.Fatalf("%s: algorithm=%d digest=%dB, want %d/%dB", label, zm.Algorithm, len(zm.Digest), alg, size)
				}
				return
			}
		}
		t.Fatalf("%s: no ZONEMD streamed", label)
	}

	axfr, err := NewAXFRServer(nil).generateAXFRRecords(z)
	if err != nil {
		t.Fatal(err)
	}
	check("axfr", axfr, 1, 48)
	xot, err := (&XoTServer{}).generateAXFRRecords(z)
	if err != nil {
		t.Fatal(err)
	}
	check("xot", xot, 1, 48)

	// A zone carrying a SHA-512 digest keeps its algorithm and size.
	z.ZONEMD.Algorithm = uint8(zone.ZONEMDSHA512)
	axfr, err = NewAXFRServer(nil).generateAXFRRecords(z)
	if err != nil {
		t.Fatal(err)
	}
	check("axfr sha512", axfr, 2, 64)
}
