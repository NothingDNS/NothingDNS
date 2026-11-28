package main

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
)

type prefetchInvalidationTransport struct {
	started chan struct{}
	release chan struct{}
}

func (g prefetchInvalidationTransport) QueryContext(_ context.Context, q *protocol.Message, _ string) (*protocol.Message, error) {
	close(g.started)
	<-g.release
	r := &protocol.Message{Header: protocol.Header{ID: q.Header.ID, Flags: protocol.Flags{QR: true, AA: true}}, Questions: q.Questions}
	r.AddAnswer(&protocol.ResourceRecord{
		Name: q.Questions[0].Name.Copy(), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 99}},
	})
	return r, nil
}

func prefetchAddrAfterChange(t *testing.T, change func(*cache.Cache, string)) (result byte) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		const name = "refresh.example."
		key := cache.MakeKey(name, protocol.TypeA, false)
		cfg := cache.DefaultConfig()
		cfg.PrefetchEnabled = true
		cfg.PrefetchThreshold = 5 * time.Second
		h := newTestHandler()
		h.cache = cache.New(cfg)
		initial := aMsg(t, name, 300, 10)
		initial.Questions = newTestQuery(t, name, protocol.TypeA).Questions
		h.cache.Set(key, initial, 300)
		h.cache.Get(key).PrefetchDue = time.Now().Add(-time.Second)

		gate := prefetchInvalidationTransport{started: make(chan struct{}), release: make(chan struct{})}
		rc := resolver.DefaultConfig()
		rc.Hints = []resolver.RootHint{{Name: "root.example.", IPv4: []string{"192.0.2.1"}}}
		rc.QnameMinimization = false
		h.resolver = resolver.NewResolver(rc, nil, gate)
		h.wirePrefetch()
		_ = h.cache.Get(key)
		<-gate.started
		change(h.cache, key)
		close(gate.release)
		synctest.Wait()
		if entry := h.cache.Get(key); entry != nil {
			result = entry.Message.Answers[0].Data.(*protocol.RDataA).Address[3]
		}
	})
	return result
}

func TestPrefetchDoesNotRepopulateFlushedCache_F892(t *testing.T) {
	if got := prefetchAddrAfterChange(t, func(c *cache.Cache, _ string) { c.Flush() }); got != 0 {
		t.Fatalf("REGRESSION: an in-flight refresh repopulated the flushed cache with address ending in %d", got)
	}
}
