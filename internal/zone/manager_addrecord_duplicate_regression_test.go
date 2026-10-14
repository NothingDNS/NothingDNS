package zone

import (
	"errors"
	"strings"
	"testing"
)

func f718Manager(t *testing.T) (*Manager, *Zone) {
	t.Helper()
	z, err := ParseFile("t", strings.NewReader("$ORIGIN example.test.\n$TTL 300\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	m.LoadZone(z, "")
	return m, z
}

func f718Count(z *Zone, name, typ string) int {
	z.RLock()
	defer z.RUnlock()
	n := 0
	for _, r := range z.Records[name] {
		if strings.EqualFold(r.Type, typ) {
			n++
		}
	}
	return n
}

// F718: an RRset holds no duplicate RR; AddRecord is where the check is atomic.
func TestAddRecordRejectsDuplicateRR(t *testing.T) {
	m, z := f718Manager(t)
	add := func(typ, name, data string, ttl uint32) error {
		return m.AddRecord("example.test.", Record{Name: name, Type: typ, TTL: ttl, Class: "IN", RData: data})
	}
	if err := add("A", "host.example.test.", "192.0.2.1", 300); err != nil {
		t.Fatal(err)
	}
	if err := add("A", "host.example.test.", "192.0.2.2", 300); err != nil {
		t.Fatalf("distinct RDATA must be accepted: %v", err)
	}
	serial := z.SOA.Serial
	for _, tc := range []struct {
		typ, name, data string
		ttl             uint32
	}{
		{"A", "host.example.test.", "192.0.2.1", 300},
		{"a", "host.example.test.", "192.0.2.1", 300}, // type spelling
		{"A", "host", "192.0.2.1", 300},               // relative owner
		{"A", "host.example.test.", "192.0.2.1", 60},  // TTL differs: still the same RR
	} {
		if err := add(tc.typ, tc.name, tc.data, tc.ttl); !errors.Is(err, ErrRecordExists) {
			t.Fatalf("%+v: err = %v, want ErrRecordExists", tc, err)
		}
	}
	if n := f718Count(z, "host.example.test.", "A"); n != 2 {
		t.Fatalf("A RRs = %d, want 2", n)
	}
	if z.SOA.Serial != serial {
		t.Fatalf("serial bumped by a rejected add: %d -> %d", serial, z.SOA.Serial)
	}
	// same text under another type is a different RR
	if err := add("TXT", "host.example.test.", "192.0.2.1", 300); err != nil {
		t.Fatalf("other type with same text: %v", err)
	}
}
