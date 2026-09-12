package cache

import (
	"strings"
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

func TestNSECCacheSynthesizedAuthorityTTLsAreBoundedByRemainingProofTTL(t *testing.T) {
	nc := NewNSECCache(100)
	entry := &nsecEntry{
		Owner:      mustName("alpha.example.com."),
		NextDomain: mustName("gamma.example.com."),
		TypeBitMap: []uint16{protocol.TypeA, protocol.TypeNSEC},
		ExpireTime: time.Now().Add(2 * time.Minute),
		SOA: &protocol.ResourceRecord{
			Name:  mustName("example.com."),
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data: &protocol.RDataSOA{
				MName:   mustName("ns1.example.com."),
				RName:   mustName("admin.example.com."),
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minimum: 300,
			},
		},
	}
	nc.entries["alpha.example.com."] = entry

	for _, resp := range []*protocol.Message{
		nc.Lookup("beta.example.com.", protocol.TypeA),
		nc.Lookup("alpha.example.com.", protocol.TypeAAAA),
	} {
		if resp == nil {
			t.Fatal("expected synthesized response")
		}
		if len(resp.Authorities) != 2 {
			t.Fatalf("authority count = %d, want 2", len(resp.Authorities))
		}
		for _, rr := range resp.Authorities {
			if rr.TTL > 120 {
				t.Fatalf("authority TTL = %d, want <= remaining proof TTL", rr.TTL)
			}
			if rr.TTL == 300 {
				t.Fatal("authority TTL was not decremented from original SOA TTL")
			}
		}
	}
}

func TestRemainingNSECTTLBounds(t *testing.T) {
	tests := []struct {
		name       string
		expireTime time.Time
		want       uint32
	}{
		{name: "expired", expireTime: time.Now().Add(-time.Second), want: 0},
		{name: "sub_second", expireTime: time.Now().Add(500 * time.Millisecond), want: 0},
		{name: "saturates_far_future", expireTime: time.Now().Add(time.Duration(1<<63 - 1)), want: ^uint32(0)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := &nsecEntry{ExpireTime: tc.expireTime}
			if got := remainingNSECTTL(entry); got != tc.want {
				t.Fatalf("remainingNSECTTL() = %d, want %d", got, tc.want)
			}
		})
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

func TestNSECCacheExactExpiryBoundary(t *testing.T) {
	nc := NewNSECCache(100)
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	entry := &nsecEntry{
		Owner:      mustName("a.example.com."),
		NextDomain: mustName("z.example.com."),
		TypeBitMap: []uint16{protocol.TypeA, protocol.TypeNSEC},
		ExpireTime: now,
	}
	nc.entries["a.example.com."] = entry

	if !nsecEntryExpiredAt(entry, now) {
		t.Fatal("NSEC entry should be expired exactly at ExpireTime")
	}
	if resp := nc.lookupAt("m.example.com.", protocol.TypeA, now); resp != nil {
		t.Fatalf("Lookup at exact expiry returned response: %+v", resp)
	}

	nc.evictExpiredAt(now)
	if _, exists := nc.entries["a.example.com."]; exists {
		t.Fatal("evictExpired should remove NSEC entry exactly at ExpireTime")
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

func TestNSECCacheAddFromResponseSkipsMalformedAuthorityRecords(t *testing.T) {
	nc := NewNSECCache(100)
	resp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Authorities: []*protocol.ResourceRecord{
			nil,
			{Type: protocol.TypeSOA, Data: (*protocol.RDataSOA)(nil)},
			{Name: mustName("example.com."), Type: protocol.TypeSOA, Data: &protocol.RDataSOA{Minimum: 60}},
			{Type: protocol.TypeNSEC, Data: &protocol.RDataNSEC{NextDomain: mustName("b.example.com.")}},
			{Name: mustName("a.example.com."), Type: protocol.TypeNSEC, Data: (*protocol.RDataNSEC)(nil)},
			{Name: mustName("a.example.com."), Type: protocol.TypeNSEC, Data: &protocol.RDataNSEC{}},
			{
				Name:  mustName("a.example.com."),
				Type:  protocol.TypeNSEC,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataNSEC{
					NextDomain: mustName("c.example.com."),
					TypeBitMap: []uint16{protocol.TypeNSEC},
				},
			},
		},
	}

	nc.AddFromResponse(resp, true)

	if nc.Size() != 1 {
		t.Fatalf("cache size = %d, want 1 valid NSEC entry", nc.Size())
	}
	synthResp := nc.Lookup("b.example.com.", protocol.TypeA)
	if synthResp == nil {
		t.Fatal("expected synthesized NXDOMAIN from valid NSEC entry")
	}
	if len(synthResp.Authorities) != 2 {
		t.Fatalf("authority count = %d, want SOA + NSEC", len(synthResp.Authorities))
	}
}

func TestNSECCacheLookupSkipsMalformedEntries(t *testing.T) {
	nc := NewNSECCache(100)
	nc.entries["nil"] = nil
	nc.entries["missing-owner"] = &nsecEntry{NextDomain: mustName("z.example.com."), ExpireTime: time.Now().Add(time.Minute)}
	nc.entries["missing-next"] = &nsecEntry{Owner: mustName("a.example.com."), ExpireTime: time.Now().Add(time.Minute)}

	if resp := nc.Lookup("m.example.com.", protocol.TypeA); resp != nil {
		t.Fatalf("Lookup with malformed entries returned response: %+v", resp)
	}
	if got := remainingNSECTTL(nil); got != 0 {
		t.Fatalf("remainingNSECTTL(nil) = %d, want 0", got)
	}
	if got := appendSOAWithTTL(nil, nil, 10); len(got) != 0 {
		t.Fatalf("appendSOAWithTTL(nil entry) len = %d, want 0", len(got))
	}
}

func TestNSECCacheEvictsLiveEntriesAtMaxSize(t *testing.T) {
	nc := NewNSECCache(2)

	for _, rr := range []struct {
		owner string
		next  string
	}{
		{owner: "a.example.com.", next: "b.example.com."},
		{owner: "b.example.com.", next: "c.example.com."},
		{owner: "c.example.com.", next: "d.example.com."},
	} {
		resp := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
			},
			Authorities: []*protocol.ResourceRecord{
				{
					Name:  mustName(rr.owner),
					Type:  protocol.TypeNSEC,
					Class: protocol.ClassIN,
					TTL:   300,
					Data: &protocol.RDataNSEC{
						NextDomain: mustName(rr.next),
						TypeBitMap: []uint16{protocol.TypeNSEC},
					},
				},
			},
		}
		nc.AddFromResponse(resp, true)
	}

	if nc.Size() != 2 {
		t.Fatalf("expected live NSEC cache to stay at max size 2, got %d", nc.Size())
	}
}

// TestNSECCacheEntriesSurviveSourceMessageRelease pins the detached-copy
// contract: AddFromResponse stores the NSEC Owner/NextDomain/TypeBitMap for
// as long as the cache holds the entry, even though the production caller
// (pipeline_stages.go:661) releases the pooled response message after the
// stage. The entry must own copies, not shared references.
func TestNSECCacheEntriesSurviveSourceMessageRelease(t *testing.T) {
	nc := NewNSECCache(100)

	// Build the response production-style: pack it, then unpack it so the
	// records live in a POOLED message exactly like the pipeline's upstream
	// responses (the released wire buffer is what shared references end up
	// pointing into).
	fresh := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Questions: []*protocol.Question{
			{Name: mustName("_covered.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustName("_covered.example.com."),
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataSOA{
					MName:   mustName("ns1.example.com."),
					RName:   mustName("admin.example.com."),
					Serial:  1,
					Refresh: 7200,
					Retry:   3600,
					Expire:  1209600,
					Minimum: 300,
				},
			},
			{
				Name:  mustName("_covered.example.com."),
				Type:  protocol.TypeNSEC,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataNSEC{
					NextDomain: mustName("_end.example.com."),
					TypeBitMap: []uint16{protocol.TypeA, protocol.TypeNSEC},
				},
			},
		},
	}
	wireBuf := make([]byte, fresh.WireLength())
	n, err := fresh.Pack(wireBuf)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	wire := wireBuf[:n]
	pooled, err := protocol.UnpackMessage(wire)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}

	nc.AddFromResponse(pooled, true)

	// The production caller releases the pooled response after the stage.
	pooled.Release()

	// Churn the protocol pool so the released wire buffer is reused and
	// overwritten with different bytes — making the use-after-release
	// exposure deterministic instead of latent until the next reuse.
	for i := 0; i < 4; i++ {
		churn := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: []*protocol.Question{
				{Name: mustName("churned-name-to-overwrite-the-buffer.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
			},
		}
		cwBuf := make([]byte, churn.WireLength())
		cn, err := churn.Pack(cwBuf)
		if err != nil {
			t.Fatalf("churn pack: %v", err)
		}
		cm, err := protocol.UnpackMessage(cwBuf[:cn])
		if err != nil {
			t.Fatalf("churn unpack: %v", err)
		}
		cm.Release()
	}

	// The cached entry must still synthesize a correct NXDOMAIN: the NSEC
	// data was shared with the released message, so a gutted entry either
	// misses the range check or synthesizes with garbage.
	resp := nc.Lookup("_d.example.com.", protocol.TypeA)
	if resp == nil {
		t.Fatalf("FAIL: the covering NSEC no longer synthesizes a response after the source message was released")
	}
	if len(resp.Authorities) < 2 {
		t.Fatalf("FAIL: synthesized response missing authority records: %d", len(resp.Authorities))
	}
	nsecRR := resp.Authorities[len(resp.Authorities)-1]
	if nsecRR.Name == nil || !strings.EqualFold(nsecRR.Name.String(), "_covered.example.com.") {
		t.Fatalf("FAIL: synthesized NSEC owner reads freed wire bytes: got %q, want %q",
			nsecRR.Name.String(), "_covered.example.com.")
	}
	nd, ok := nsecRR.Data.(*protocol.RDataNSEC)
	if !ok || nd.NextDomain == nil {
		t.Fatalf("FAIL: synthesized NSEC record missing NextDomain")
	}
	if !strings.EqualFold(nd.NextDomain.String(), "_end.example.com.") {
		t.Fatalf("FAIL: synthesized NSEC NextDomain reads freed wire bytes: got %q, want %q",
			nd.NextDomain.String(), "_end.example.com.")
	}
}
