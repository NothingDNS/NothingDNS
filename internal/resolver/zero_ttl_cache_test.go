package resolver

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// recordingCache is a Cache that remembers the TTL each Set was given.
type recordingCache struct {
	ttls map[string]uint32
}

func newRecordingCache() *recordingCache {
	return &recordingCache{ttls: map[string]uint32{}}
}

func (c *recordingCache) Get(key string) *CacheEntry                      { return nil }
func (c *recordingCache) Set(key string, _ *protocol.Message, ttl uint32) { c.ttls[key] = ttl }
func (c *recordingCache) SetNegative(key string, rcode uint8)             {}
func (c *recordingCache) ApplyTTLPolicy(_ *protocol.Message, ttl uint32) uint32 {
	return ttl
}

// A record published with TTL 0 may only be used for the transaction in
// progress (RFC 1035 §3.2.1): the answer that holds it must be stored with
// TTL 0, not with the 300s default that stands in for "no TTL at all".
func TestCacheResponseZeroTTLIsNotCached(t *testing.T) {
	mk := func(t *testing.T, ttls ...uint32) *protocol.Message {
		t.Helper()
		name, err := protocol.ParseName("dyn.example.com.")
		if err != nil {
			t.Fatal(err)
		}
		m := &protocol.Message{Header: protocol.Header{Flags: protocol.Flags{QR: true, AA: true}}}
		for _, ttl := range ttls {
			m.Answers = append(m.Answers, &protocol.ResourceRecord{
				Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: ttl,
				Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
			})
		}
		return m
	}

	for _, tc := range []struct {
		name string
		ttls []uint32
		want uint32
	}{
		{"control: a 120s record keeps 120", []uint32{120}, 120},
		{"minimum of several positive TTLs", []uint32{600, 45, 300}, 45},
		{"a TTL 0 record is stored with TTL 0", []uint32{0}, 0},
		{"TTL 0 after a long record still wins", []uint32{3600, 0}, 0},
		{"TTL 0 before a long record still wins", []uint32{0, 3600}, 0},
		{"no answer records fall back to the 300s default", nil, 300},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newRecordingCache()
			r := NewResolver(Config{}, c, nil)
			r.cacheResponse("dyn.example.com.", protocol.TypeA, mk(t, tc.ttls...), "example.com.")
			got, ok := c.ttls[cacheKey("dyn.example.com.", protocol.TypeA)]
			if !ok {
				t.Fatal("primary entry was not stored")
			}
			if got != tc.want {
				t.Fatalf("stored TTL = %d, want %d", got, tc.want)
			}
		})
	}
}
