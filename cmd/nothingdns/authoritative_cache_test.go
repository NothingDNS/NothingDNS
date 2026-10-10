package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/dashboard"
	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func answerA(t *testing.T, msg *protocol.Message) (string, uint32) {
	t.Helper()
	if msg == nil || len(msg.Answers) != 1 {
		t.Fatalf("expected exactly one answer, got %+v", msg)
	}
	a, ok := msg.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatalf("answer is %T, want *protocol.RDataA", msg.Answers[0].Data)
	}
	return a.String(), msg.Answers[0].TTL
}

// Answers from local zones are served from the cache, counted as hits, and
// carry the zone's TTL untouched (the test cache's max_ttl is 300).
func TestAuthoritativeAnswer_ServedFromCache(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 3600, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})

	for i := 0; i < 3; i++ {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
		addr, ttl := answerA(t, w.msg)
		if addr != "192.0.2.1" || ttl != 3600 {
			t.Fatalf("query %d: got %s TTL %d, want 192.0.2.1 TTL 3600", i, addr, ttl)
		}
		if !w.msg.Header.Flags.AA {
			t.Fatalf("query %d: AA flag lost", i)
		}
	}

	stats := h.cache.Stats()
	if stats.Misses != 1 || stats.Hits != 2 {
		t.Errorf("cache hits/misses = %d/%d, want 2/1", stats.Hits, stats.Misses)
	}
}

func TestAuthoritativeAnswer_CacheHitKeepsClientCase(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))

	w = newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "WwW.ExAmPlE.CoM.", protocol.TypeA))
	if h.cache.Stats().Hits != 1 {
		t.Fatal("second query should be a cache hit")
	}
	if got := w.msg.Answers[0].Name.String(); got != "WwW.ExAmPlE.CoM." {
		t.Errorf("answer owner = %q, want the client's spelling", got)
	}
	if got := w.msg.Questions[0].Name.String(); got != "WwW.ExAmPlE.CoM." {
		t.Errorf("question = %q, want the client's spelling", got)
	}
}

// Every in-place zone change goes through Zone.Lock/Unlock, which moves the
// zone to a new cache generation: the next query must see the new data.
func TestAuthoritativeAnswer_ZoneChangeInvalidates(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})
	z := h.zones["example.com."]

	query := func(name string) *protocol.Message {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, name, protocol.TypeA))
		return w.msg
	}

	query("www.example.com.")
	if w := query("new.example.com."); w.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("new.example.com. rcode = %d, want NXDOMAIN", w.Header.Flags.RCODE)
	}

	z.Lock()
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.2"},
	}
	z.Records["new.example.com."] = []zone.Record{
		{Name: "new.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.3"},
	}
	z.Unlock()

	if addr, _ := answerA(t, query("www.example.com.")); addr != "192.0.2.2" {
		t.Errorf("after update got %s, want 192.0.2.2", addr)
	}
	if addr, _ := answerA(t, query("new.example.com.")); addr != "192.0.2.3" {
		t.Errorf("cached NXDOMAIN survived the record being added: got %s", addr)
	}
}

// RRSIGs and the DNSKEY set of a signed zone come from its signer, whose key
// rollovers the zone generation does not see, so those answers are uncached.
func TestAuthoritativeCacheKey_SkipsSignerDependentAnswers(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})
	z := h.zones["example.com."]
	h.zoneSigners = map[string]*dnssec.Signer{"example.com.": nil}

	if key := h.authoritativeCacheKey(z, "www.example.com.", protocol.TypeA, true); key != "" {
		t.Errorf("signed zone, DO=1: key = %q, want uncached", key)
	}
	if key := h.authoritativeCacheKey(z, "example.com.", protocol.TypeDNSKEY, false); key != "" {
		t.Errorf("signed zone, DNSKEY: key = %q, want uncached", key)
	}
	if key := h.authoritativeCacheKey(z, "www.example.com.", protocol.TypeA, false); key == "" {
		t.Error("signed zone, DO=0: answer carries no signer data and should be cached")
	}
}

// A reload re-reads every zone file into new Zone objects. A zone whose file
// did not change keeps its cached answers; a changed one is served fresh.
func TestAuthoritativeAnswer_UnchangedReloadKeepsCache(t *testing.T) {
	h := newTestHandler()
	h.zoneManager = zone.NewManager()
	zoneFiles := map[string]string{}

	mailAddr := "192.0.2.20"
	load := func(string) (*zone.Zone, error) {
		z := zone.NewZone("example.com.")
		z.DefaultTTL = 300
		z.Records["www.example.com."] = []zone.Record{
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.10"},
		}
		z.Records["mail.example.com."] = []zone.Record{
			{Name: "mail.example.com.", TTL: 300, Class: "IN", Type: "A", RData: mailAddr},
		}
		return z, nil
	}
	reload := func() {
		t.Helper()
		if _, err := reloadConfiguredZoneFiles(h, h.zoneManager, zoneFiles, []string{"example.com.zone"}, load, reloadTestLogger()); err != nil {
			t.Fatalf("reload: %v", err)
		}
	}
	query := func(name string) string {
		t.Helper()
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, name, protocol.TypeA))
		addr, _ := answerA(t, w.msg)
		return addr
	}
	hits := func() uint64 { return h.cache.Stats().Hits }

	reload()
	query("www.example.com.")
	query("mail.example.com.")

	reload() // file unchanged
	before := hits()
	if addr := query("www.example.com."); addr != "192.0.2.10" {
		t.Fatalf("www after unchanged reload = %s", addr)
	}
	if addr := query("mail.example.com."); addr != "192.0.2.20" {
		t.Fatalf("mail after unchanged reload = %s", addr)
	}
	if got := hits() - before; got != 2 {
		t.Errorf("unchanged reload: %d cache hits, want 2", got)
	}

	mailAddr = "192.0.2.77"
	reload() // file changed
	before = hits()
	if addr := query("mail.example.com."); addr != "192.0.2.77" {
		t.Errorf("changed reload served %s, want 192.0.2.77", addr)
	}
	if got := hits() - before; got != 0 {
		t.Errorf("changed reload: %d cache hits, want 0", got)
	}
}

// An answer built while the zone's tag moved (a mutation, or a reload that
// handed the tag to a new Zone) must not be filed under the old key.
func TestCacheAuthoritative_DropsAnswerAfterTagMoved(t *testing.T) {
	h := newTestHandler()
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})
	z := h.zones["example.com."]

	key := h.authoritativeCacheKey(z, "www.example.com.", protocol.TypeA, false)
	resp := newTestQuery(t, "www.example.com.", protocol.TypeA)
	resp.Answers = []*protocol.ResourceRecord{{
		Name: resp.Questions[0].Name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}}

	z.Lock()
	z.DefaultTTL = 600
	z.Unlock()
	h.cacheAuthoritative(z, key, resp)
	if h.cache.Get(key) != nil {
		t.Fatal("answer cached under a tag the zone no longer holds")
	}
}

// A repeated query answered from the authoritative cache is reported as
// cached in the dashboard query log and live stream, like any cache hit.
func TestAuthoritativeAnswer_CacheHitReportedToQueryLog(t *testing.T) {
	h := newTestHandler()
	ds := dashboard.NewServer()
	h.dashboardServer = ds
	addZoneRecords(t, h, "example.com.", []zone.Record{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})

	for i := 0; i < 2; i++ {
		w := newCaptureWriter("10.0.0.1", "udp")
		h.ServeDNS(w, newTestQuery(t, "www.example.com.", protocol.TypeA))
	}

	queries, total := ds.GetStats().GetRecentQueries(0, 10)
	if total != 2 || len(queries) != 2 {
		t.Fatalf("dashboard query log: total=%d len=%d, want 2/2", total, len(queries))
	}
	cached := 0
	for _, e := range queries {
		if e.Cached {
			cached++
		}
	}
	if cached != 1 {
		t.Errorf("%d of 2 events marked cached, want 1 (the repeat)", cached)
	}
}
