package cache

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// The wildcard-denial half of an aggressive NXDOMAIN (RFC 8198 §5.3) looks for a
// cached NSEC covering "*.<closest encloser>". That NSEC is subject to the same
// RFC 6840 §4.1 rule: one owned by a delegation or a DNAME cannot deny anything
// below its owner, and "*.<x>" for an x at or under such an owner is below it.
func TestNSECCacheWildcardDenialIgnoresZoneCutNSEC(t *testing.T) {
	soa := func() *protocol.ResourceRecord {
		return &protocol.ResourceRecord{
			Name: mustName("example.com."), Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataSOA{
				MName: mustName("ns1.example.com."), RName: mustName("admin.example.com."),
				Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300,
			},
		}
	}
	nsec := func(owner, next string, bitmap []uint16) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{
			Name: mustName(owner), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC{NextDomain: mustName(next), TypeBitMap: bitmap},
		}
	}
	build := func(rrs ...*protocol.ResourceRecord) *NSECCache {
		nc := NewNSECCache(100)
		nc.AddFromResponse(&protocol.Message{
			Header:      protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)},
			Authorities: append([]*protocol.ResourceRecord{soa()}, rrs...),
		}, true)
		return nc
	}

	// Covering NSEC for tt.example.com.: sub -> zzz (tt sits between them).
	// The closest encloser of tt.example.com. is example.com., so the wildcard
	// to deny is *.example.com. — it needs an NSEC covering that name.
	t.Run("control: an apex-side NSEC covering *.example.com. completes the proof", func(t *testing.T) {
		nc := build(
			nsec("sub.example.com.", "zzz.example.com.", plainBitmap),
			nsec("example.com.", "aaa.example.com.", apexBitmap),
		)
		if got := nc.Lookup("tt.example.com.", protocol.TypeA); got == nil || got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("control: expected NXDOMAIN, got %+v", got)
		}
	})

	t.Run("without any wildcard-denying NSEC there is no synthesis (existing behaviour)", func(t *testing.T) {
		nc := build(nsec("sub.example.com.", "zzz.example.com.", plainBitmap))
		if got := nc.Lookup("tt.example.com.", protocol.TypeA); got != nil {
			t.Fatalf("no wildcard proof is cached, expected nil, got %+v", got)
		}
	})

	// The closest encloser of x.y.sub.example.com. (covered below by an NSEC
	// owned by "a.sub.example.com.") is sub.example.com., so the wildcard to
	// deny is "*.sub.example.com." — a name BELOW the delegation sub.example.com.
	// An NSEC owned by that delegation cannot deny it (RFC 6840 §4.1), however
	// its range sorts.
	t.Run("a delegation NSEC owned above the wildcard cannot supply its denial", func(t *testing.T) {
		nc := build(
			nsec("a.sub.example.com.", "z.sub.example.com.", plainBitmap),    // covers x.y.sub.example.com. (a < x.y < z)
			nsec("sub.example.com.", "a.sub.example.com.", delegationBitmap), // delegation; its range covers *.sub.example.com.
		)
		got := nc.Lookup("x.y.sub.example.com.", protocol.TypeA)
		if got != nil {
			t.Fatalf("FAIL: synthesized rcode=%d (AD=%v) for a name below the delegation sub.example.com.; "+
				"the wildcard denial came from the delegation's own NSEC", got.Header.Flags.RCODE, got.Header.Flags.AD)
		}
	})

	t.Run("control: the same shape with an ordinary owner above completes the proof", func(t *testing.T) {
		nc := build(
			nsec("a.sub.example.com.", "z.sub.example.com.", plainBitmap),
			nsec("sub.example.com.", "a.sub.example.com.", plainBitmap),
		)
		if got := nc.Lookup("x.y.sub.example.com.", protocol.TypeA); got == nil || got.Header.Flags.RCODE != protocol.RcodeNameError {
			t.Fatalf("control: with ordinary owners the proof is complete, expected NXDOMAIN, got %+v", got)
		}
	})
}
