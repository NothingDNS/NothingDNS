package dnssec

// Regression tests for R40 signer/rollover findings (red against 80ea9a2):
//   - F242: the rollover scheduler added a new key with Timing == nil and set
//     its Published state/timing afterwards; isActive treats a timing-less key
//     as always active, so concurrent signing used the unpublished key.
//   - F248: NSEC/NSEC3 records carried a fixed 86400 TTL instead of
//     MIN(SOA MINIMUM, SOA TTL) (RFC 9077 §3).
// F247 (opt-out NSEC3 bitmap at an unsigned delegation) is pinned by
// TestGenerateNSEC3_OptOutClassification.

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// waitForGoroutineFrames polls goroutine stacks (no sleeps) until one
// goroutine's stack contains every frame substring.
func waitForGoroutineFrames(t *testing.T, frames ...string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for i := 0; i < 10_000_000; i++ {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			all := true
			for _, f := range frames {
				all = all && strings.Contains(g, f)
			}
			if all {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatalf("no goroutine reached %v", frames)
}

func TestRolloverNewKeyNeverActiveBeforeTiming(t *testing.T) {
	for _, ksk := range []bool{false, true} {
		s := NewSigner("example.com.", DefaultSignerConfig())
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		old, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, ksk)
		if err != nil {
			t.Fatal(err)
		}
		s.SetKeyState(old.KeyTag, KeyStateActive)
		s.SetKeyTiming(old.KeyTag, &KeyTiming{Active: now.Add(-24 * time.Hour), Retire: now.Add(time.Hour)})
		rs := NewRolloverScheduler(s, DefaultRolloverConfig(), nil)
		active, activeFn := s.GetActiveZSKs, "GetActiveZSKs"
		if ksk {
			active, activeFn = s.GetActiveKSKs, "GetActiveKSKs"
		}

		// Gate: hold a read lock so the scheduler blocks inside AddKey's
		// Lock, queue a reader behind it, then release. sync.RWMutex hands
		// the lock to the queued reader when AddKey unlocks, before any
		// later write lock, so the reader observes the key exactly as
		// AddKey published it.
		s.mu.RLock()
		done := make(chan struct{})
		go func() {
			defer close(done)
			if ksk {
				rs.generateRolloverKSK(now)
			} else {
				rs.generateRolloverZSK(now)
			}
		}()
		waitForGoroutineFrames(t, "(*Signer).AddKey", "sync.runtime_SemacquireRWMutex(")
		seen := make(chan []*SigningKey, 1)
		go func() { seen <- active() }()
		waitForGoroutineFrames(t, "(*Signer)."+activeFn, "sync.runtime_SemacquireRWMutexR(")
		s.mu.RUnlock()
		window := <-seen
		<-done

		for _, k := range window {
			if k.KeyTag != old.KeyTag {
				t.Fatalf("ksk=%v: new key %d was active before its Active time (state %v, timing %v)", ksk, k.KeyTag, k.State, k.Timing)
			}
		}
		for _, k := range s.GetKeys() {
			if k.KeyTag != old.KeyTag && (k.State != KeyStatePublished || k.Timing == nil || !k.Timing.Active.Equal(now.Add(DefaultRolloverConfig().PublishSafety))) {
				t.Fatalf("ksk=%v: new key %d state %v timing %+v, want Published with Active=now+PublishSafety", ksk, k.KeyTag, k.State, k.Timing)
			}
		}
	}
}

func TestSignZoneDenialTTLFollowsSOA(t *testing.T) {
	mk := func(name string, rrtype uint16, text string, ttl uint32) *protocol.ResourceRecord {
		rr, err := protocol.NewResourceRecord(name, rrtype, protocol.ClassIN, ttl, protocol.ParseRDataText(protocol.TypeString(rrtype), text))
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	cases := []struct {
		soaTTL uint32
		soa    string
		want   uint32
	}{
		{3600, "ns1.example.com. h.example.com. 1 3600 600 86400 300", 300},      // MINIMUM smaller
		{120, "ns1.example.com. h.example.com. 1 3600 600 86400 300", 120},       // SOA TTL smaller
		{86400, "ns1.example.com. h.example.com. 1 3600 600 86400 86400", 86400}, // control
	}
	for _, nsec3 := range []bool{false, true} {
		for _, c := range cases {
			cfg := DefaultSignerConfig()
			cfg.NSEC3Enabled = nsec3
			s := NewSigner("example.com.", cfg)
			if _, err := s.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true); err != nil {
				t.Fatal(err)
			}
			signed, err := s.SignZone([]*protocol.ResourceRecord{
				mk("example.com.", protocol.TypeSOA, c.soa, c.soaTTL),
				mk("example.com.", protocol.TypeNS, "ns1.example.com.", 3600),
				mk("www.example.com.", protocol.TypeA, "192.0.2.1", 3600),
			})
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, rr := range signed {
				var ttl uint32
				switch rr.Type {
				case protocol.TypeNSEC, protocol.TypeNSEC3:
					ttl = rr.TTL
				case protocol.TypeRRSIG:
					sig := rr.Data.(*protocol.RDataRRSIG)
					if sig.TypeCovered != protocol.TypeNSEC && sig.TypeCovered != protocol.TypeNSEC3 {
						continue
					}
					ttl = sig.OriginalTTL
				default:
					continue
				}
				n++
				if ttl != c.want {
					t.Errorf("nsec3=%v SOA ttl=%d (%s): %s TTL %d, want %d", nsec3, c.soaTTL, c.soa, protocol.TypeString(rr.Type), ttl, c.want)
				}
			}
			if n == 0 {
				t.Fatalf("nsec3=%v: no denial records", nsec3)
			}
		}
	}
}
