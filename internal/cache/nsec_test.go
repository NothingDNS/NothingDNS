package cache

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func mustName(s string) *protocol.Name {
	n, err := protocol.ParseName(s)
	if err != nil {
		panic("mustName: " + err.Error())
	}
	return n
}

func TestNameInNSECRange(t *testing.T) {
	tests := []struct {
		name   string
		owner  string
		next   string
		expect bool
	}{
		// Normal range: alpha.example.com. < beta.example.com. < gamma.example.com.
		{"beta.example.com.", "alpha.example.com.", "gamma.example.com.", true},
		// Outside range (before owner)
		{"aaa.example.com.", "alpha.example.com.", "gamma.example.com.", false},
		// Outside range (after next)
		{"zzz.example.com.", "alpha.example.com.", "gamma.example.com.", false},
		// Exactly at owner — not in range (strict)
		{"alpha.example.com.", "alpha.example.com.", "gamma.example.com.", false},
		// Exactly at next — not in range (strict)
		{"gamma.example.com.", "alpha.example.com.", "gamma.example.com.", false},
		// Wrap-around: next < owner (last NSEC in zone)
		{"zzz.example.com.", "xyz.example.com.", "aaa.example.com.", true},
		{"aaa.example.com.", "xyz.example.com.", "aaa.example.com.", false},
	}

	for _, tt := range tests {
		got := nameInNSECRange(mustName(tt.name), mustName(tt.owner), mustName(tt.next))
		if got != tt.expect {
			t.Errorf("nameInNSECRange(%s, %s, %s) = %v, want %v",
				tt.name, tt.owner, tt.next, got, tt.expect)
		}
	}
}

func TestTypeInBitmap(t *testing.T) {
	bitmap := []uint16{protocol.TypeA, protocol.TypeAAAA, protocol.TypeNS}

	if !typeInBitmap(protocol.TypeA, bitmap) {
		t.Error("expected A in bitmap")
	}
	if typeInBitmap(protocol.TypeMX, bitmap) {
		t.Error("expected MX not in bitmap")
	}
}

func TestNSECCacheAddAndLookupNXDOMAIN(t *testing.T) {
	nc := NewNSECCache(100)

	soaName := mustName("example.com.")
	soaRR := &protocol.ResourceRecord{
		Name:  soaName,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataSOA{
			MName:   mustName("ns1.example.com."),
			RName:   mustName("admin.example.com."),
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minimum: 300,
		},
	}

	// NSEC record: alpha.example.com. -> gamma.example.com.
	// This proves no names exist between alpha and gamma
	nsecRR := &protocol.ResourceRecord{
		Name:  mustName("alpha.example.com."),
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataNSEC{
			NextDomain: mustName("gamma.example.com."),
			TypeBitMap: []uint16{protocol.TypeA, protocol.TypeAAAA, protocol.TypeNSEC},
		},
	}

	// Simulate NXDOMAIN response with NSEC
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{soaRR, nsecRR},
	}

	nc.AddFromResponse(resp, true)

	if nc.Size() != 1 {
		t.Fatalf("cache size = %d, want 1", nc.Size())
	}

	// Query for beta.example.com. — should be proven non-existent
	synthResp := nc.Lookup("beta.example.com.", protocol.TypeA)
	if synthResp == nil {
		t.Fatal("expected synthesized NXDOMAIN for beta.example.com.")
	}
	if synthResp.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Errorf("RCODE = %d, want NXDOMAIN", synthResp.Header.Flags.RCODE)
	}
	if !synthResp.Header.Flags.AD {
		t.Error("expected AD bit set on synthesized response")
	}

	// Query for delta.example.com. — also in range
	synthResp = nc.Lookup("delta.example.com.", protocol.TypeA)
	if synthResp == nil {
		t.Fatal("expected synthesized NXDOMAIN for delta.example.com.")
	}

	// Query for zzz.example.com. — outside range, should return nil
	synthResp = nc.Lookup("zzz.example.com.", protocol.TypeA)
	if synthResp != nil {
		t.Error("expected nil for zzz.example.com. (outside NSEC range)")
	}
}

func TestNSECCacheNODATA(t *testing.T) {
	nc := NewNSECCache(100)

	// NSEC proves www.example.com. exists but only has A, not AAAA
	nsecRR := &protocol.ResourceRecord{
		Name:  mustName("www.example.com."),
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataNSEC{
			NextDomain: mustName("zzz.example.com."),
			TypeBitMap: []uint16{protocol.TypeA, protocol.TypeNSEC},
		},
	}

	soaRR := &protocol.ResourceRecord{
		Name:  mustName("example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data: &protocol.RDataSOA{
			MName:  mustName("ns1.example.com."),
			RName:  mustName("admin.example.com."),
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300,
		},
	}

	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{soaRR, nsecRR},
	}

	nc.AddFromResponse(resp, true)

	// Query AAAA for www.example.com. — should get NODATA (name exists, type doesn't)
	synthResp := nc.Lookup("www.example.com.", protocol.TypeAAAA)
	if synthResp == nil {
		t.Fatal("expected synthesized NODATA for www.example.com. AAAA")
	}
	if synthResp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("RCODE = %d, want Success (NODATA)", synthResp.Header.Flags.RCODE)
	}
	if len(synthResp.Answers) != 0 {
		t.Error("expected no answers for NODATA")
	}

	// Query A for www.example.com. — type exists, should return nil (not cached)
	synthResp = nc.Lookup("www.example.com.", protocol.TypeA)
	if synthResp != nil {
		t.Error("expected nil for www.example.com. A (type exists in bitmap)")
	}
}

func TestNSECCacheExpiration(t *testing.T) {
	nc := NewNSECCache(100)

	nsecRR := &protocol.ResourceRecord{
		Name:  mustName("a.example.com."),
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		TTL:   1, // 1 second TTL
		Data: &protocol.RDataNSEC{
			NextDomain: mustName("z.example.com."),
			TypeBitMap: []uint16{protocol.TypeA},
		},
	}

	soaRR := &protocol.ResourceRecord{
		Name:  mustName("example.com."),
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   1,
		Data: &protocol.RDataSOA{
			MName:  mustName("ns1.example.com."),
			RName:  mustName("admin.example.com."),
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 1,
		},
	}

	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{soaRR, nsecRR},
	}

	nc.AddFromResponse(resp, true)

	// Should match immediately
	if nc.Lookup("m.example.com.", protocol.TypeA) == nil {
		t.Error("expected match before expiry")
	}

	// Wait for expiry
	time.Sleep(2 * time.Second)

	// Should not match after expiry
	if nc.Lookup("m.example.com.", protocol.TypeA) != nil {
		t.Error("expected no match after expiry")
	}
}

func TestNSECCacheIgnoresNonNXDOMAIN(t *testing.T) {
	nc := NewNSECCache(100)

	// Response with RCODE=Success — should NOT be cached
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustName("a.example.com."),
				Type:  protocol.TypeNSEC,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataNSEC{
					NextDomain: mustName("z.example.com."),
					TypeBitMap: []uint16{protocol.TypeA},
				},
			},
		},
	}

	nc.AddFromResponse(resp, true)
	if nc.Size() != 0 {
		t.Errorf("expected 0 entries for non-NXDOMAIN, got %d", nc.Size())
	}
}
