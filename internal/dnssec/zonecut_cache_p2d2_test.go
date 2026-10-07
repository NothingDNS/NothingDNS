package dnssec

// F477 (P2-D2): the F472 zone-cut check costs one DS lookup per name between
// the RRSIG signer and a deeper owner. Authenticated results are cached
// across responses for the proof's lifetime (min TTL, RRSIG expiration), so
// repeated answers under the same signer cost 0 extra lookups after the
// first; failures are never cached and an expired entry is re-proven.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// p2d2Resolver wraps p2d1Resolver: it is safe for concurrent use, counts DS
// queries, and answers each DS query like a real server — only the denial
// records matching the queried name (the NSEC owned by it, or the NSEC3 at
// H(name)) plus their RRSIGs (a deep name has one NSEC/NSEC3 per ENT, which
// would exceed the 16-RRset cap if the whole chain were returned).
type p2d2Resolver struct {
	mu       sync.Mutex
	inner    *p2d1Resolver
	dsCount  int
	unsigned string // serve an unsigned DS RRset for this name
}

func (r *p2d2Resolver) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if qtype == protocol.TypeDS {
		r.dsCount++
		if strings.EqualFold(name, r.unsigned) {
			n, _ := protocol.ParseName(name)
			ds := &protocol.ResourceRecord{Name: n, Type: protocol.TypeDS, Class: protocol.ClassIN, TTL: 300,
				Data: &protocol.RDataDS{KeyTag: 1, Algorithm: protocol.AlgorithmECDSAP256SHA256, DigestType: 2, Digest: make([]byte, 32)}}
			return p2d1Msg(name, qtype, []*protocol.ResourceRecord{ds}, nil), nil
		}
	}
	m, err := r.inner.Query(ctx, name, qtype)
	if err != nil || qtype != protocol.TypeDS || len(m.Authorities) == 0 {
		return m, err
	}
	want := map[string]bool{strings.ToLower(name): true}
	for _, rr := range m.Authorities {
		if n3, ok := rr.Data.(*protocol.RDataNSEC3); ok {
			if h, err := NSEC3Hash(name, n3.HashAlgorithm, n3.Iterations, n3.Salt); err == nil {
				want[strings.ToLower(protocol.Base32Encode(h))+".example.com."] = true
			}
			break
		}
	}
	var keep []*protocol.ResourceRecord
	for _, rr := range m.Authorities {
		if want[strings.ToLower(rr.Name.String())] {
			keep = append(keep, rr)
		}
	}
	m.Authorities = keep
	return m, nil
}

func (r *p2d2Resolver) lookups() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dsCount
}

func (r *p2d2Resolver) setZones(zones ...*p2d1Zone) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inner.zones = zones
}

func (r *p2d2Resolver) setFailDS(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inner.failDS = name
}

// p2d2Deep is an 18-label name under example.com. (20 labels, 17 names
// strictly between the signer and the owner).
func p2d2Deep(prefix string) string {
	labels := make([]string, 17)
	for i := range labels {
		labels[i] = fmt.Sprintf("%x", i)
	}
	return prefix + "." + strings.Join(labels, ".") + ".example.com."
}

type p2d2Env struct {
	parent *p2d1Zone
	res    *p2d2Resolver
	v      *Validator
	clk    time.Time
	deep   string
	k      int
}

func p2d2Setup(t *testing.T, cfg SignerConfig, extra ...*protocol.ResourceRecord) *p2d2Env {
	t.Helper()
	deep := p2d2Deep("h1")
	recs := append([]*protocol.ResourceRecord{
		p2d1RR(t, "example.com.", protocol.TypeSOA, "ns1.example.com. h.example.com. 1 3600 600 86400 300"),
		p2d1RR(t, "example.com.", protocol.TypeNS, "ns1.example.com."),
		p2d1RR(t, "www.example.com.", protocol.TypeA, "192.0.2.1"),
		p2d1RR(t, deep, protocol.TypeA, "192.0.2.9"),
		p2d1RR(t, p2d2Deep("h2"), protocol.TypeA, "192.0.2.10"),
		p2d1RR(t, "a.b.c.example.com.", protocol.TypeA, "192.0.2.3"),
		p2d1RR(t, "insecure.example.com.", protocol.TypeNS, "ns1.insecure.example.com."),
	}, extra...)
	parent := p2d1Sign(t, "example.com.", cfg, recs...)
	ta, err := DSFromDNSKEY("example.com.", parent.signer.GetKSKs()[0].DNSKEY, 2)
	if err != nil {
		t.Fatal(err)
	}
	store := NewTrustAnchorStore()
	store.AddAnchor(ta)
	vcfg := DefaultValidatorConfig()
	vcfg.ValidationCacheTTL = 0
	env := &p2d2Env{parent: parent, res: &p2d2Resolver{inner: &p2d1Resolver{zones: []*p2d1Zone{parent}}},
		clk: time.Now(), deep: deep, k: len(dnsLabelsLower(deep)) - 3}
	env.v = NewValidator(vcfg, store, env.res)
	env.v.now = func() time.Time { return env.clk }
	return env
}

// validate validates owner's A RRset (from z) and returns the verdict and
// the DS lookups it caused.
func (e *p2d2Env) validate(t *testing.T, z *p2d1Zone, owner string) (ValidationResult, int) {
	t.Helper()
	return e.validateRRs(t, owner, z.rrset(owner, protocol.TypeA))
}

func (e *p2d2Env) validateRRs(t *testing.T, owner string, ans []*protocol.ResourceRecord) (ValidationResult, int) {
	t.Helper()
	before := e.res.lookups()
	got, _ := e.v.ValidateResponse(context.Background(), p2d1Msg(owner, protocol.TypeA, ans, nil), owner)
	return got, e.res.lookups() - before
}

func (e *p2d2Env) forge(t *testing.T, owner string) []*protocol.ResourceRecord {
	t.Helper()
	rr := p2d1RR(t, owner, protocol.TypeA, "203.0.113.66")
	sig, err := e.parent.signer.SignRRSet([]*protocol.ResourceRecord{rr}, e.parent.signer.GetZSKs()[0],
		uint32(e.clk.Add(-time.Hour).Unix()), uint32(e.clk.Add(24*time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	return []*protocol.ResourceRecord{rr, sig}
}

// p2d2Run runs every F477 scenario; report receives the measurements.
func p2d2Run(t *testing.T, report func(format string, args ...any)) {
	const N = 20
	for _, nsec3 := range []bool{false, true} {
		cfg := DefaultSignerConfig()
		cfg.NSEC3Enabled = nsec3
		mode := map[bool]string{false: "NSEC", true: "NSEC3"}[nsec3]
		expect := func(what string, got ValidationResult, lookups int, want ValidationResult, wantLookups int) {
			t.Helper()
			report("[%s] %-62s %v lookups=%d (want %v, %d)", mode, what, got, lookups, want, wantLookups)
			if got != want || lookups != wantLookups {
				t.Errorf("[%s] %s: got %v lookups %d, want %v lookups %d", mode, what, got, lookups, want, wantLookups)
			}
		}

		// 1. Cost: N repeated responses -> k lookups in total (was N*k).
		e := p2d2Setup(t, cfg)
		got, n := e.validate(t, e.parent, "www.example.com.")
		expect("control: owner one label below signer", got, n, ValidationSecure, 0)
		total := 0
		for i := 0; i < N; i++ {
			got, n := e.validate(t, e.parent, e.deep)
			total += n
			if got != ValidationSecure {
				t.Errorf("[%s] repeated deep response %d: %v", mode, i, got)
			}
		}
		expect(fmt.Sprintf("deep owner x%d (k=%d): total DS lookups", N, e.k), ValidationSecure, total, ValidationSecure, e.k)
		got, n = e.validate(t, e.parent, p2d2Deep("h2"))
		expect("sibling deep owner sharing all intermediates", got, n, ValidationSecure, 0)

		// 2. Forged answers stay BOGUS with a warm cache: a tampered RRset
		// under cached intermediates, and parent-signed data below a cut
		// (proven cut cached: the repeat costs no lookup).
		tampered := e.parent.rrset(e.deep, protocol.TypeA)
		for _, rr := range tampered {
			if rr.Type == protocol.TypeA {
				rr.Data = &protocol.RDataA{Address: [4]byte{203, 0, 113, 1}}
			}
		}
		got, n = e.validateRRs(t, e.deep, tampered)
		expect("tampered deep RRset, warm cache", got, n, ValidationBogus, 0)
		for i, want := range []int{1, 0} {
			got, n = e.validateRRs(t, "www.insecure.example.com.", e.forge(t, "www.insecure.example.com."))
			expect(fmt.Sprintf("parent-signed below insecure cut #%d", i+1), got, n, ValidationBogus, want)
		}

		// 3. Lifetime: live until TTL, re-proven at TTL expiry.
		e.clk = e.clk.Add(299 * time.Second)
		got, n = e.validate(t, e.parent, e.deep)
		expect("deep owner at TTL-1s (cached)", got, n, ValidationSecure, 0)
		e.clk = e.clk.Add(time.Second)
		got, n = e.validate(t, e.parent, e.deep)
		expect("deep owner at TTL (expired, re-proven)", got, n, ValidationSecure, e.k)

		// 4. A cut appearing after the proof expires is detected: the zone
		// now delegates c.example.com. (insecure), a stale parent signature
		// over a.b.c.example.com. is replayed.
		e = p2d2Setup(t, cfg)
		stale := e.parent.rrset("a.b.c.example.com.", protocol.TypeA)
		got, n = e.validateRRs(t, "a.b.c.example.com.", stale)
		expect("a.b.c before delegation", got, n, ValidationSecure, 2)
		signed, err := e.parent.signer.SignZone([]*protocol.ResourceRecord{
			p2d1RR(t, "example.com.", protocol.TypeSOA, "ns1.example.com. h.example.com. 2 3600 600 86400 300"),
			p2d1RR(t, "example.com.", protocol.TypeNS, "ns1.example.com."),
			p2d1RR(t, "c.example.com.", protocol.TypeNS, "ns1.c.example.com."),
		})
		if err != nil {
			t.Fatal(err)
		}
		e.res.setZones(&p2d1Zone{zone: "example.com.", signed: signed, signer: e.parent.signer})
		got, n = e.validateRRs(t, "a.b.c.example.com.", stale)
		expect("stale a.b.c after delegation, within proof TTL (cached)", got, n, ValidationSecure, 0)
		e.clk = e.clk.Add(300 * time.Second)
		got, n = e.validateRRs(t, "a.b.c.example.com.", stale)
		expect("stale a.b.c after delegation, TTL expired", got, n, ValidationBogus, 1)

		// 5. Failures are never cached: fetch failure, unsigned DS, budget
		// exhaustion. The next good response re-proves the failed name.
		e = p2d2Setup(t, cfg)
		e.res.setFailDS("b.c.example.com.")
		got, n = e.validate(t, e.parent, "a.b.c.example.com.")
		expect("DS fetch failure at b.c", got, n, ValidationBogus, 2)
		e.res.setFailDS("")
		got, n = e.validate(t, e.parent, "a.b.c.example.com.")
		expect("after failure: c cached, b.c re-proven", got, n, ValidationSecure, 1)
		e = p2d2Setup(t, cfg)
		e.res.unsigned = "c.example.com."
		got, n = e.validate(t, e.parent, "a.b.c.example.com.")
		expect("unsigned DS at c (unauthenticated cut)", got, n, ValidationBogus, 1)
		e.res.unsigned = ""
		got, n = e.validate(t, e.parent, "a.b.c.example.com.")
		expect("after unsigned DS: nothing cached", got, n, ValidationSecure, 2)
		e = p2d2Setup(t, cfg)
		b := newResponseBudget()
		b.lookupLimit = 1
		got, err = e.v.validateResponseBudget(context.Background(), p2d1Msg("a.b.c.example.com.", protocol.TypeA, e.parent.rrset("a.b.c.example.com.", protocol.TypeA), nil), "a.b.c.example.com.", b)
		if got != ValidationBogus || err != errWorkBudgetExceeded {
			t.Errorf("[%s] lookup budget 1: got %v (%v)", mode, got, err)
		}
		report("[%s] lookup budget 1 -> %v (err=%v), cache entries=%d (want 1: only the proven c)", mode, got, err, e.v.zoneCuts.len())
		if e.v.zoneCuts.len() != 1 {
			t.Errorf("[%s] cache after budget exhaustion: %d entries, want 1", mode, e.v.zoneCuts.len())
		}
		got, n = e.validate(t, e.parent, "a.b.c.example.com.")
		expect("after budget exhaustion: b.c re-proven", got, n, ValidationSecure, 1)
		e = p2d2Setup(t, cfg)
		base := newResponseBudget() // signatures for chain + answer, no proofs
		if got, _ := e.v.validateResponseBudget(context.Background(), p2d1Msg("www.example.com.", protocol.TypeA, e.parent.rrset("www.example.com.", protocol.TypeA), nil), "www.example.com.", base); got != ValidationSecure {
			t.Fatalf("[%s] www: %v", mode, got)
		}
		b = newResponseBudget()
		b.sigLimit = base.sigs // the first DS proof cannot verify
		got, _ = e.v.validateResponseBudget(context.Background(), p2d1Msg("a.b.c.example.com.", protocol.TypeA, e.parent.rrset("a.b.c.example.com.", protocol.TypeA), nil), "a.b.c.example.com.", b)
		report("[%s] signature budget = chain+answer only -> %v, cache entries=%d (want 0)", mode, got, e.v.zoneCuts.len())
		if got != ValidationBogus || e.v.zoneCuts.len() != 0 {
			t.Errorf("[%s] sig budget exhausted: got %v, cache %d entries", mode, got, e.v.zoneCuts.len())
		}

		// 6. RRSIG expiration bounds the lifetime below the TTL: signatures
		// valid for 120s (the 5-minute clock skew keeps them verifiable).
		short := cfg
		short.SignatureValidity = 120 * time.Second
		short.InceptionOffset = time.Hour
		e = p2d2Setup(t, short)
		got, n = e.validate(t, e.parent, "a.b.c.example.com.")
		expect("short-signature zone: first a.b.c", got, n, ValidationSecure, 2)
		e.clk = e.clk.Add(110 * time.Second)
		got, n = e.validate(t, e.parent, "a.b.c.example.com.")
		expect("+110s (< RRSIG expiration)", got, n, ValidationSecure, 0)
		e.clk = e.clk.Add(15 * time.Second)
		got, n = e.validate(t, e.parent, "a.b.c.example.com.")
		expect("+125s (> RRSIG expiration, < TTL): re-proven", got, n, ValidationSecure, 2)

		// 7. Size cap: a 4-entry cache never holds more than 4 entries.
		e = p2d2Setup(t, cfg)
		e.v.zoneCuts = newZoneCutCache(4)
		got, n = e.validate(t, e.parent, e.deep)
		report("[%s] cap 4: deep owner -> %v lookups=%d entries=%d", mode, got, n, e.v.zoneCuts.len())
		if got != ValidationSecure || n != e.k || e.v.zoneCuts.len() != 4 {
			t.Errorf("[%s] cap 4: got %v lookups %d entries %d", mode, got, n, e.v.zoneCuts.len())
		}

		// 8. Concurrent validations sharing one cache (-race); a gate
		// releases all goroutines together.
		e = p2d2Setup(t, cfg)
		const G = 16
		gate := make(chan struct{})
		results := make(chan ValidationResult, 2*G)
		var wg sync.WaitGroup
		for i := 0; i < G; i++ {
			for _, owner := range []string{e.deep, "www.insecure.example.com."} {
				ans := e.parent.rrset(owner, protocol.TypeA)
				if owner != e.deep {
					ans = e.forge(t, owner)
				}
				wg.Add(1)
				go func(owner string, ans []*protocol.ResourceRecord) {
					defer wg.Done()
					<-gate
					got, _ := e.v.ValidateResponse(context.Background(), p2d1Msg(owner, protocol.TypeA, ans, nil), owner)
					results <- got
				}(owner, ans)
			}
		}
		close(gate)
		wg.Wait()
		close(results)
		secure, bogus := 0, 0
		for r := range results {
			switch r {
			case ValidationSecure:
				secure++
			case ValidationBogus:
				bogus++
			}
		}
		lookups := e.res.lookups()
		report("[%s] concurrent %d deep + %d forged: SECURE=%d BOGUS=%d lookups=%d (<= %d)", mode, G, G, secure, bogus, lookups, G*(e.k+1))
		if secure != G || bogus != G || lookups < e.k+1 || lookups > G*(e.k+1) {
			t.Errorf("[%s] concurrent: secure %d bogus %d lookups %d", mode, secure, bogus, lookups)
		}
		got, n = e.validate(t, e.parent, e.deep)
		expect("after concurrent round: deep owner", got, n, ValidationSecure, 0)
	}
}

func TestZoneCutCache_RepeatedResponses_F477(t *testing.T) {
	p2d2Run(t, t.Logf)
}

func TestZoneCutCache_LRUAndLifetime_F477(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := newZoneCutCache(2)
	c.put("example.com.", "a.example.com.", false, now, time.Minute)
	c.put("example.com.", "b.example.com.", true, now, time.Minute)
	if _, ok := c.get("example.com.", "a.example.com.", now); !ok { // a is now most recent
		t.Fatal("a missing")
	}
	c.put("example.com.", "c.example.com.", false, now, time.Minute) // evicts b
	if _, ok := c.get("example.com.", "b.example.com.", now); ok {
		t.Fatal("LRU entry b not evicted")
	}
	if isCut, ok := c.get("other.", "a.example.com.", now); ok {
		t.Fatalf("key must include the signer, got hit isCut=%v", isCut)
	}
	if _, ok := c.get("example.com.", "a.example.com.", now.Add(time.Minute)); ok {
		t.Fatal("entry live at its expiry")
	}
	c.put("example.com.", "d.example.com.", false, now, 0)
	if _, ok := c.get("example.com.", "d.example.com.", now); ok || c.len() > 2 {
		t.Fatalf("zero lifetime cached (len %d)", c.len())
	}
	var nilCache *zoneCutCache
	nilCache.put("example.com.", "a.example.com.", false, now, time.Minute)
	if _, ok := nilCache.get("example.com.", "a.example.com.", now); ok {
		t.Fatal("nil cache hit")
	}

	n, _ := protocol.ParseName("x.example.com.")
	nowSec := uint32(now.Unix())
	rr := func(ttl uint32, data protocol.RData) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: n, Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: ttl, Data: data}
	}
	sig := func(origTTL, exp uint32) protocol.RData {
		return &protocol.RDataRRSIG{OriginalTTL: origTTL, Expiration: exp}
	}
	for _, tc := range []struct {
		name string
		msg  *protocol.Message
		want time.Duration
	}{
		{"nil", nil, 0},
		{"empty", &protocol.Message{}, 0},
		{"min TTL", &protocol.Message{Authorities: []*protocol.ResourceRecord{rr(600, nil), rr(300, sig(3600, nowSec+86400))}}, 300 * time.Second},
		{"original TTL", &protocol.Message{Authorities: []*protocol.ResourceRecord{rr(600, sig(60, nowSec+86400))}}, 60 * time.Second},
		{"RRSIG expiration", &protocol.Message{Answers: []*protocol.ResourceRecord{rr(3600, sig(3600, nowSec+100))}}, 100 * time.Second},
		{"expired RRSIG", &protocol.Message{Authorities: []*protocol.ResourceRecord{rr(3600, sig(3600, nowSec-1))}}, 0},
		{"zero TTL", &protocol.Message{Authorities: []*protocol.ResourceRecord{rr(0, sig(3600, nowSec+100))}}, 0},
	} {
		if got := proofLifetime(tc.msg, now); got != tc.want {
			t.Errorf("proofLifetime %s = %v, want %v", tc.name, got, tc.want)
		}
	}
}
