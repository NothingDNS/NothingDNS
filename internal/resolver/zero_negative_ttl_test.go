package resolver

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// negativeRecordingCache records every negative store, by key.
type negativeRecordingCache struct {
	stored map[string]uint32
}

func (c *negativeRecordingCache) Get(string) *CacheEntry                              { return nil }
func (c *negativeRecordingCache) Set(string, *protocol.Message, uint32)               {}
func (c *negativeRecordingCache) SetNegative(key string, _ uint8)                     { c.stored[key] = 0 }
func (c *negativeRecordingCache) ApplyTTLPolicy(_ *protocol.Message, t uint32) uint32 { return t }
func (c *negativeRecordingCache) SetNegativeMessage(key string, _ uint8, _ *protocol.Message, ttl uint32) {
	c.stored[key] = ttl
}

func negativeWithSOA(t *testing.T, soaTTL, minimum uint32, withSOA bool) *protocol.Message {
	t.Helper()
	owner, err := protocol.ParseName("example.com.")
	if err != nil {
		t.Fatal(err)
	}
	m := &protocol.Message{Header: protocol.Header{Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeNameError}}}
	if withSOA {
		m.Authorities = []*protocol.ResourceRecord{{
			Name: owner, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: soaTTL,
			Data: &protocol.RDataSOA{MName: owner, RName: owner, Minimum: minimum},
		}}
	}
	return m
}

// RFC 2308 §5: the negative TTL is min(SOA TTL, SOA MINIMUM). When that is 0 the
// answer must not be cached (RFC 1035 §3.2.1). The cache treats a 0 TTL as "no
// SOA was given, use negative_ttl", so the resolver must not hand it one.
func TestCacheNegativeZeroSOATTLIsNotStored(t *testing.T) {
	key := cacheKey("fresh.example.com.", protocol.TypeA)

	for _, tc := range []struct {
		name      string
		msg       func(t *testing.T) *protocol.Message
		wantStore bool
		wantTTL   uint32
	}{
		{"control: SOA 300/120 stores 120", func(t *testing.T) *protocol.Message { return negativeWithSOA(t, 300, 120, true) }, true, 120},
		{"control: SOA 30/300 stores 30", func(t *testing.T) *protocol.Message { return negativeWithSOA(t, 30, 300, true) }, true, 30},
		{"SOA TTL 0 is not stored", func(t *testing.T) *protocol.Message { return negativeWithSOA(t, 0, 300, true) }, false, 0},
		{"SOA MINIMUM 0 is not stored", func(t *testing.T) *protocol.Message { return negativeWithSOA(t, 300, 0, true) }, false, 0},
		{"both 0 is not stored", func(t *testing.T) *protocol.Message { return negativeWithSOA(t, 0, 0, true) }, false, 0},
		{"no SOA still falls back to the cache default", func(t *testing.T) *protocol.Message { return negativeWithSOA(t, 0, 0, false) }, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &negativeRecordingCache{stored: map[string]uint32{}}
			r := NewResolver(Config{}, c, nil)
			r.cacheNegative("fresh.example.com.", protocol.TypeA, protocol.RcodeNameError, tc.msg(t))
			got, stored := c.stored[key]
			if stored != tc.wantStore {
				t.Fatalf("stored = %v, want %v", stored, tc.wantStore)
			}
			if stored && got != tc.wantTTL {
				t.Fatalf("stored TTL = %d, want %d", got, tc.wantTTL)
			}
		})
	}
}
