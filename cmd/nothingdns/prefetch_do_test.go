package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/util"
)

// signingUpstream answers A queries for name with 192.0.2.<last>, adding an
// RRSIG only when the query sets DO (RFC 4035 §3.2.1). It records the DO bit
// of the latest query in lastDO (1 set, 0 clear).
func signingUpstream(t *testing.T, name string, last *atomic.Int32, lastDO *atomic.Int32) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q, err := protocol.UnpackMessage(buf[:n])
			if err != nil || len(q.Questions) != 1 {
				continue
			}
			do := false
			if opt := q.GetOPT(); opt != nil {
				if h := protocol.ParseEDNS0Header(opt); h != nil {
					do = h.DO
				}
			}
			if do {
				lastDO.Store(1)
			} else {
				lastDO.Store(0)
			}
			resp := aMsg(t, name, 600, byte(last.Load()))
			resp.Header.ID = q.Header.ID
			resp.Questions = q.Questions
			if do {
				now := time.Now()
				resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
					Name: ttlName(t, name), Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 600,
					Data: &protocol.RDataRRSIG{TypeCovered: protocol.TypeA, Algorithm: 13, Labels: 3, OriginalTTL: 600,
						Expiration: uint32(now.Add(time.Hour).Unix()), Inception: uint32(now.Add(-time.Hour).Unix()),
						KeyTag: 1, SignerName: ttlName(t, "example.com."), Signature: []byte{1, 2, 3, 4}},
				})
				resp.SetEDNS0(1232, true)
			}
			out := make([]byte, 4096)
			if m, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:m], addr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func hasRRSIGAnswer(m *protocol.Message) bool {
	if m == nil {
		return false
	}
	for _, rr := range m.Answers {
		if rr.Type == protocol.TypeRRSIG {
			return true
		}
	}
	return false
}

// A prefetch refreshes an entry as the client miss behind it asked: the DO=1
// entry of a forwarding server without a validator holds the RRSIGs DO=1
// clients get, and a refresh sent without DO replaced it with an unsigned
// answer, so every DO=1 client got the RRSIGs stripped until it expired
// (F891). A DO=0 entry is still refreshed without DO.
func TestPrefetchKeepsTheDOBitOfTheEntry(t *testing.T) {
	const name = "pf.example.com."
	var last, lastDO atomic.Int32
	last.Store(10)
	addr := signingUpstream(t, name, &last, &lastDO)

	cfg := config.DefaultConfig()
	cfg.Cache.Prefetch = true
	cfg.Cache.PrefetchThreshold = 5
	cfg.Cache.MinTTL = 0
	cfg.Cache.MaxTTL = 3600
	mgr := NewCacheManager(cfg, util.NewLogger(util.ERROR, util.TextFormat, nil))
	t.Cleanup(mgr.Stop)
	h := newTestHandler()
	h.config = cfg
	h.cache = mgr.Cache
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{addr}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	h.upstream = uc // forwarding, no validator

	for _, do := range []bool{true, false} {
		last.Store(10)
		q := newTestQuery(t, name, protocol.TypeA)
		q.SetEDNS0(1232, do)
		h.ServeDNS(newCaptureWriter("10.0.0.1", "udp"), q)
		key := cache.MakeKey(name, protocol.TypeA, do)
		if e := mgr.Cache.Get(key); e == nil || hasRRSIGAnswer(e.Message) != do {
			t.Fatalf("DO=%v: client miss not cached as expected under %s", do, key)
		}

		last.Store(99)
		h.prefetch(key, protocol.TypeA)

		if got := lastDO.Load() == 1; got != do {
			t.Errorf("DO=%v entry: refresh sent with DO=%v", do, got)
		}
		e := mgr.Cache.Get(key)
		if e == nil {
			t.Fatalf("DO=%v: entry gone after the refresh", do)
		}
		a, _ := e.Message.Answers[0].Data.(*protocol.RDataA)
		if a == nil || a.Address[3] != 99 {
			t.Errorf("DO=%v: entry not refreshed: %v", do, e.Message.Answers)
		}
		if hasRRSIGAnswer(e.Message) != do {
			t.Errorf("DO=%v: refreshed entry RRSIG present = %v, want %v", do, hasRRSIGAnswer(e.Message), do)
		}
	}
}
