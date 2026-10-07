package resolver

// Regression tests for P2-E11 (F542–F545): CNAME/DNAME chain assembly.
//
//   F542 the DNAME path answered NOERROR with no Authority whatever the
//        target's outcome (NXDOMAIN, NODATA, SERVFAIL).
//   F543 the DNAME path (and pruneAnswerToChain) dropped the RRSIG over the
//        DNAME, so a validator could not authenticate it.
//   F544 an uncompletable CNAME chain (longer than MaxCNAMEDepth) returned a
//        dangling CNAME-only NOERROR instead of SERVFAIL.
//   F545 a cache hit on a stored CNAME/DNAME reply was returned without
//        chasing, ending the chain at a dangling alias.
//
// In-process fake authoritative network (no sockets); every authoritative
// reply carries RRSIG/NSEC records so their survival can be checked:
//
//	root 1.1.1.1 : refers src.test. -> 2.2.2.2, tgt.test. -> 3.3.3.3, sf.test. -> 4.4.4.4
//	src.test.    : DNAME d.src.test. -> tgt.test., dsf.src.test. -> sf.test. (+RRSIG)
//	               c-ok/c-nx/c-nodata CNAME into tgt.test.; cN CNAME c(N+1),
//	               c50 CNAME ok.tgt.test.; loop1 <-> loop2; c-dname CNAME nx.d.src.test.
//	tgt.test.    : ok A (+RRSIG); nodata NODATA; else NXDOMAIN (SOA/NSEC/RRSIG)
//	sf.test.     : SERVFAIL to everything

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func p2eN(s string) *protocol.Name { n, _ := protocol.ParseName(s); return n }

func p2eRR(owner string, t uint16, d protocol.RData) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{Name: p2eN(owner), Type: t, Class: protocol.ClassIN, TTL: 300, Data: d}
}

func p2eSig(owner string, covered uint16, signer string) *protocol.ResourceRecord {
	return p2eRR(owner, protocol.TypeRRSIG, &protocol.RDataRRSIG{TypeCovered: covered, Algorithm: 13,
		Labels: uint8(strings.Count(strings.TrimSuffix(owner, "."), ".") + 1), OriginalTTL: 300,
		Expiration: 2000000000, Inception: 1, KeyTag: 1, SignerName: p2eN(signer), Signature: []byte{1, 2, 3}})
}

func p2eSOA(zone string) *protocol.ResourceRecord {
	return p2eRR(zone, protocol.TypeSOA, &protocol.RDataSOA{MName: p2eN("ns." + zone), RName: p2eN("h." + zone), Serial: 1, Minimum: 300})
}

type p2eNet struct {
	mu    sync.Mutex
	Calls int
}

func (f *p2eNet) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	f.mu.Lock()
	f.Calls++
	f.mu.Unlock()
	q := msg.Questions[0]
	qn := strings.ToLower(q.Name.String())
	r := &protocol.Message{Header: protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
		Questions: []*protocol.Question{q}}
	switch addr {
	case "1.1.1.1:53":
		for _, z := range [][2]string{{"src.test.", "2.2.2.2"}, {"tgt.test.", "3.3.3.3"}, {"sf.test.", "4.4.4.4"}} {
			if qn == z[0] || strings.HasSuffix(qn, "."+z[0]) {
				var ip [4]byte
				_, _ = fmt.Sscanf(z[1], "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])
				r.Authorities = append(r.Authorities, p2eRR(z[0], protocol.TypeNS, &protocol.RDataNS{NSDName: p2eN("ns." + z[0])}))
				r.Additionals = append(r.Additionals, p2eRR("ns."+z[0], protocol.TypeA, &protocol.RDataA{Address: ip}))
				return r, nil
			}
		}
		r.Header.Flags.AA = true
		r.Header.Flags.RCODE = protocol.RcodeNameError
		r.Authorities = append(r.Authorities, p2eSOA("."))
	case "2.2.2.2:53":
		r.Header.Flags.AA = true
		for _, d := range [][2]string{{"d.src.test.", "tgt.test."}, {"dsf.src.test.", "sf.test."}} {
			if strings.HasSuffix(qn, "."+d[0]) {
				target := strings.TrimSuffix(qn, d[0]) + d[1]
				r.Answers = append(r.Answers,
					p2eRR(d[0], protocol.TypeDNAME, &protocol.RDataDNAME{DName: p2eN(d[1])}),
					p2eSig(d[0], protocol.TypeDNAME, "src.test."),
					p2eRR(qn, protocol.TypeCNAME, &protocol.RDataCNAME{CName: p2eN(target)}))
				return r, nil
			}
		}
		var target string
		switch {
		case qn == "c-ok.src.test.":
			target = "ok.tgt.test."
		case qn == "c-nx.src.test.":
			target = "nx.tgt.test."
		case qn == "c-nodata.src.test.":
			target = "nodata.tgt.test."
		case qn == "c-sf.src.test.":
			target = "x.sf.test."
		case qn == "c50.src.test.":
			target = "ok.tgt.test." // c35 -> ... -> c50 -> ok is exactly 16 CNAMEs
		case qn == "loop1.src.test.":
			target = "loop2.src.test."
		case qn == "loop2.src.test.":
			target = "loop1.src.test."
		case qn == "c-dname.src.test.":
			target = "nx.d.src.test."
		case strings.HasPrefix(qn, "c") && strings.HasSuffix(qn, ".src.test."):
			var n int
			if _, err := fmt.Sscanf(qn, "c%d.src.test.", &n); err == nil {
				target = fmt.Sprintf("c%d.src.test.", n+1)
			}
		}
		if target == "" {
			r.Header.Flags.RCODE = protocol.RcodeNameError
			r.Authorities = append(r.Authorities, p2eSOA("src.test."), p2eSig("src.test.", protocol.TypeSOA, "src.test."))
			return r, nil
		}
		r.Answers = append(r.Answers, p2eRR(qn, protocol.TypeCNAME, &protocol.RDataCNAME{CName: p2eN(target)}),
			p2eSig(qn, protocol.TypeCNAME, "src.test."))
	case "3.3.3.3:53":
		r.Header.Flags.AA = true
		switch {
		case qn == "ok.tgt.test." && q.QType == protocol.TypeA:
			r.Answers = append(r.Answers, p2eRR(qn, protocol.TypeA, &protocol.RDataA{Address: [4]byte{7, 7, 7, 7}}),
				p2eSig(qn, protocol.TypeA, "tgt.test."))
		case qn == "nodata.tgt.test." || qn == "ok.tgt.test.":
			r.Authorities = append(r.Authorities, p2eSOA("tgt.test."), p2eSig("tgt.test.", protocol.TypeSOA, "tgt.test."),
				p2eRR(qn, protocol.TypeNSEC, &protocol.RDataNSEC{NextDomain: p2eN("z.tgt.test."), TypeBitMap: []uint16{protocol.TypeTXT, protocol.TypeRRSIG, protocol.TypeNSEC}}),
				p2eSig(qn, protocol.TypeNSEC, "tgt.test."))
		default:
			r.Header.Flags.RCODE = protocol.RcodeNameError
			r.Authorities = append(r.Authorities, p2eSOA("tgt.test."), p2eSig("tgt.test.", protocol.TypeSOA, "tgt.test."),
				p2eRR("tgt.test.", protocol.TypeNSEC, &protocol.RDataNSEC{NextDomain: p2eN("z.tgt.test."), TypeBitMap: []uint16{protocol.TypeSOA, protocol.TypeNS, protocol.TypeRRSIG, protocol.TypeNSEC}}),
				p2eSig("tgt.test.", protocol.TypeNSEC, "tgt.test."))
		}
	case "4.4.4.4:53":
		r.Header.Flags.RCODE = protocol.RcodeServerFailure
	default:
		return nil, fmt.Errorf("unreachable %s", addr)
	}
	return r, nil
}

// p2eMemCache is a minimal positive+negative message cache (like the
// production resolverCacheAdapter: stores copies, serves copies).
type p2eMemCache struct {
	mu  sync.Mutex
	pos map[string]*protocol.Message
	neg map[string]*CacheEntry
}

func Newp2eMemCache() *p2eMemCache {
	return &p2eMemCache{pos: map[string]*protocol.Message{}, neg: map[string]*CacheEntry{}}
}
func (c *p2eMemCache) Get(key string) *CacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m, ok := c.pos[key]; ok {
		return &CacheEntry{Message: m.Copy()}
	}
	if e, ok := c.neg[key]; ok {
		return e
	}
	return nil
}
func (c *p2eMemCache) Set(key string, msg *protocol.Message, _ uint32) {
	c.mu.Lock()
	c.pos[key] = msg.Copy()
	c.mu.Unlock()
}
func (c *p2eMemCache) SetNegative(key string, rcode uint8) {
	c.mu.Lock()
	c.neg[key] = &CacheEntry{IsNegative: true, RCode: rcode}
	c.mu.Unlock()
}
func (c *p2eMemCache) SetNegativeMessage(key string, rcode uint8, msg *protocol.Message, _ uint32) {
	c.mu.Lock()
	c.neg[key] = &CacheEntry{IsNegative: true, RCode: rcode, Message: msg.Copy()}
	c.mu.Unlock()
}
func (c *p2eMemCache) ApplyTTLPolicy(_ *protocol.Message, ttl uint32) uint32 { return ttl }

// Has reports whether section contains a record of type t (and, for RRSIG,
// covering `covered`) owned by owner ("" = any owner).
func p2eHas(section []*protocol.ResourceRecord, owner string, t, covered uint16) bool {
	for _, x := range section {
		if x == nil || x.Type != t {
			continue
		}
		if owner != "" && !strings.EqualFold(x.Name.String(), owner) {
			continue
		}
		if t == protocol.TypeRRSIG {
			if s, ok := x.Data.(*protocol.RDataRRSIG); !ok || s.TypeCovered != covered {
				continue
			}
		}
		return true
	}
	return false
}

func p2eResolver(c Cache, f *p2eNet) *Resolver {
	cfg := DefaultConfig()
	cfg.Hints = []RootHint{{Name: "a.root.test.", IPv4: []string{"1.1.1.1"}}}
	cfg.DNSSECOK = true
	if c == nil {
		return NewResolver(cfg, nil, f)
	}
	return NewResolver(cfg, c, f)
}

func p2eDenial(m *protocol.Message) bool {
	return p2eHas(m.Authorities, "tgt.test.", protocol.TypeSOA, 0) &&
		p2eHas(m.Authorities, "tgt.test.", protocol.TypeRRSIG, protocol.TypeSOA) &&
		p2eHas(m.Authorities, "", protocol.TypeNSEC, 0) &&
		p2eHas(m.Authorities, "", protocol.TypeRRSIG, protocol.TypeNSEC)
}

// p2eResolveTwice resolves qname on a fresh resolver; with warm it resolves
// it twice on a caching resolver and returns the cache-served second answer.
func p2eResolveTwice(t *testing.T, qname string, warm bool) *protocol.Message {
	t.Helper()
	var c Cache
	if warm {
		c = &p2eMemCache{pos: map[string]*protocol.Message{}, neg: map[string]*CacheEntry{}}
	}
	r := p2eResolver(c, &p2eNet{})
	m, err := r.Resolve(context.Background(), qname, protocol.TypeA)
	if warm && err == nil {
		m, err = r.Resolve(context.Background(), qname, protocol.TypeA)
	}
	if err != nil || m == nil {
		t.Fatalf("Resolve(%s, warm=%v): resp=%v err=%v", qname, warm, m, err)
	}
	return m
}

func TestResolve_DNAMEKeepsTargetRcodeAndDenial_F542(t *testing.T) {
	for _, warm := range []bool{false, true} {
		m := p2eResolveTwice(t, "nx.d.src.test.", warm)
		if m.Header.Flags.RCODE != protocol.RcodeNameError || !p2eDenial(m) {
			t.Fatalf("warm=%v DNAME->NXDOMAIN: rcode=%d auth=%v, want NXDOMAIN + SOA/NSEC/RRSIG", warm, m.Header.Flags.RCODE, m.Authorities)
		}
		m = p2eResolveTwice(t, "nodata.d.src.test.", warm)
		if m.Header.Flags.RCODE != protocol.RcodeSuccess || !p2eDenial(m) || p2eHas(m.Answers, "", protocol.TypeA, 0) {
			t.Fatalf("warm=%v DNAME->NODATA: rcode=%d auth=%v, want NOERROR + SOA/NSEC/RRSIG", warm, m.Header.Flags.RCODE, m.Authorities)
		}
		m = p2eResolveTwice(t, "x.dsf.src.test.", warm)
		if m.Header.Flags.RCODE != protocol.RcodeServerFailure {
			t.Fatalf("warm=%v DNAME->SERVFAIL target: rcode=%d, want SERVFAIL", warm, m.Header.Flags.RCODE)
		}
		m = p2eResolveTwice(t, "c-dname.src.test.", warm)
		if m.Header.Flags.RCODE != protocol.RcodeNameError || !p2eDenial(m) ||
			!p2eHas(m.Answers, "c-dname.src.test.", protocol.TypeCNAME, 0) || !p2eHas(m.Answers, "d.src.test.", protocol.TypeDNAME, 0) {
			t.Fatalf("warm=%v CNAME->DNAME->NXDOMAIN: rcode=%d answers=%v", warm, m.Header.Flags.RCODE, m.Answers)
		}
		if len(m.Questions) != 1 || !strings.EqualFold(m.Questions[0].Name.String(), "c-dname.src.test.") {
			t.Fatalf("warm=%v: question %v, want the client's", warm, m.Questions)
		}
		// Control: positive DNAME answer still complete.
		m = p2eResolveTwice(t, "ok.d.src.test.", warm)
		if m.Header.Flags.RCODE != protocol.RcodeSuccess || !p2eHas(m.Answers, "ok.tgt.test.", protocol.TypeA, 0) ||
			!p2eHas(m.Answers, "ok.d.src.test.", protocol.TypeCNAME, 0) {
			t.Fatalf("warm=%v DNAME positive: rcode=%d answers=%v", warm, m.Header.Flags.RCODE, m.Answers)
		}
	}
}

func TestResolve_DNAMEKeepsRRSIG_F543(t *testing.T) {
	for _, warm := range []bool{false, true} {
		for _, qn := range []string{"ok.d.src.test.", "nx.d.src.test."} {
			m := p2eResolveTwice(t, qn, warm)
			if !p2eHas(m.Answers, "d.src.test.", protocol.TypeRRSIG, protocol.TypeDNAME) {
				t.Fatalf("warm=%v %s: RRSIG(DNAME) dropped: answers=%v", warm, qn, m.Answers)
			}
		}
		m := p2eResolveTwice(t, "ok.d.src.test.", warm)
		if !p2eHas(m.Answers, "ok.tgt.test.", protocol.TypeRRSIG, protocol.TypeA) {
			t.Fatalf("warm=%v: target RRSIG(A) dropped: %v", warm, m.Answers)
		}
	}

	// pruneAnswerToChain keeps the RRSIG over an ancestor DNAME but still
	// drops off-chain RRSIGs (and RRSIGs over other types at that owner).
	msg := &protocol.Message{Answers: []*protocol.ResourceRecord{
		p2eRR("d.src.test.", protocol.TypeDNAME, &protocol.RDataDNAME{DName: p2eN("tgt.test.")}),
		p2eSig("d.src.test.", protocol.TypeDNAME, "src.test."),
		p2eSig("d.src.test.", protocol.TypeA, "src.test."),
		p2eRR("x.d.src.test.", protocol.TypeCNAME, &protocol.RDataCNAME{CName: p2eN("x.tgt.test.")}),
		p2eRR("x.tgt.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}),
		p2eSig("evil.test.", protocol.TypeDNAME, "evil.test."),
	}}
	pruneAnswerToChain(msg, "x.d.src.test.", protocol.TypeA)
	if !p2eHas(msg.Answers, "d.src.test.", protocol.TypeRRSIG, protocol.TypeDNAME) {
		t.Fatalf("prune dropped RRSIG(DNAME): %v", msg.Answers)
	}
	if p2eHas(msg.Answers, "d.src.test.", protocol.TypeRRSIG, protocol.TypeA) || p2eHas(msg.Answers, "evil.test.", protocol.TypeRRSIG, protocol.TypeDNAME) {
		t.Fatalf("prune kept off-chain RRSIGs: %v", msg.Answers)
	}
}

func TestResolve_CNAMEChainTooDeepIsSERVFAIL_F544(t *testing.T) {
	for _, warm := range []bool{false, true} {
		for _, qn := range []string{"c0.src.test.", "c34.src.test.", "loop1.src.test."} {
			if m := p2eResolveTwice(t, qn, warm); m.Header.Flags.RCODE != protocol.RcodeServerFailure {
				t.Fatalf("warm=%v %s: rcode=%d answers=%d, want SERVFAIL (no dangling-CNAME NOERROR)", warm, qn, m.Header.Flags.RCODE, len(m.Answers))
			}
		}
		// Boundary: exactly MaxCNAMEDepth (16) CNAMEs still resolves.
		m := p2eResolveTwice(t, "c35.src.test.", warm)
		if m.Header.Flags.RCODE != protocol.RcodeSuccess || !p2eHas(m.Answers, "ok.tgt.test.", protocol.TypeA, 0) {
			t.Fatalf("warm=%v 16-CNAME chain: rcode=%d, want NOERROR with the A", warm, m.Header.Flags.RCODE)
		}
		// Control: a CNAME to a negative target keeps its rcode and proof.
		m = p2eResolveTwice(t, "c-nx.src.test.", warm)
		if m.Header.Flags.RCODE != protocol.RcodeNameError || !p2eDenial(m) {
			t.Fatalf("warm=%v CNAME->NXDOMAIN: rcode=%d auth=%v", warm, m.Header.Flags.RCODE, m.Authorities)
		}
		m = p2eResolveTwice(t, "c-nodata.src.test.", warm)
		if m.Header.Flags.RCODE != protocol.RcodeSuccess || !p2eDenial(m) {
			t.Fatalf("warm=%v CNAME->NODATA: rcode=%d auth=%v", warm, m.Header.Flags.RCODE, m.Authorities)
		}
	}
}

func TestResolve_CachedAliasIsChased_F545(t *testing.T) {
	for _, qn := range []string{"c-ok.src.test.", "ok.d.src.test."} {
		f := &p2eNet{}
		r := p2eResolver(&p2eMemCache{pos: map[string]*protocol.Message{}, neg: map[string]*CacheEntry{}}, f)
		if _, err := r.Resolve(context.Background(), qn, protocol.TypeA); err != nil {
			t.Fatal(err)
		}
		before := f.Calls
		m, err := r.Resolve(context.Background(), qn, protocol.TypeA)
		if err != nil || m.Header.Flags.RCODE != protocol.RcodeSuccess || !p2eHas(m.Answers, "ok.tgt.test.", protocol.TypeA, 0) {
			t.Fatalf("%s warm: resp=%v err=%v, want the full chain ending in the A", qn, m, err)
		}
		if f.Calls != before {
			t.Fatalf("%s warm: %d upstream queries, want 0 (chain served from cache)", qn, f.Calls-before)
		}
	}
	m := p2eResolveTwice(t, "c-nx.src.test.", true)
	if m.Header.Flags.RCODE != protocol.RcodeNameError || !p2eDenial(m) {
		t.Fatalf("warm CNAME->NXDOMAIN: rcode=%d auth=%v", m.Header.Flags.RCODE, m.Authorities)
	}
}
