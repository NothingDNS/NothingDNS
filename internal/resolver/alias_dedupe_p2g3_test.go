package resolver

// Regression tests for P2-G3 (F572–F573): in-zone CNAME targets.
//
//   F572 an authoritative CNAME reply that already carries the in-zone target
//        RRset (RFC 1034 §4.3.2 step 3a) was merged with the separately
//        resolved target answer, duplicating every target record (and, for
//        multi-hop in-zone chains, the CNAMEs and RRSIGs too) — RFC 2181 §5.
//   F573 cacheResponse side-cached the in-bailiwick target A/AAAA records
//        under (owner, type) WITHOUT the RRSIGs covering them, so a later
//        query for the target was served unsigned from the resolver cache.
//
// Reuses the P2-E11 fake network (alias_chain_p2e11_test.go) and adds
// in.test. at 5.5.5.5, whose CNAME replies include the in-zone target RRset:
// two A records and two RRSIG(A) with different key tags (distinct records
// that must survive de-duplication).

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func p2gSig(owner string, covered, keyTag uint16) *protocol.ResourceRecord {
	s := p2eSig(owner, covered, "in.test.")
	s.Data.(*protocol.RDataRRSIG).KeyTag = keyTag
	return s
}

func p2gWWW(owner string) []*protocol.ResourceRecord {
	return []*protocol.ResourceRecord{
		p2eRR(owner, protocol.TypeA, &protocol.RDataA{Address: [4]byte{9, 9, 9, 9}}),
		p2eRR(owner, protocol.TypeA, &protocol.RDataA{Address: [4]byte{9, 9, 9, 8}}),
		p2gSig(owner, protocol.TypeA, 11),
		p2gSig(owner, protocol.TypeA, 22),
	}
}

func p2gCNAME(owner, target string) []*protocol.ResourceRecord {
	return []*protocol.ResourceRecord{
		p2eRR(owner, protocol.TypeCNAME, &protocol.RDataCNAME{CName: p2eN(target)}),
		p2gSig(owner, protocol.TypeCNAME, 11),
	}
}

type p2gNet struct{ p2eNet }

func (f *p2gNet) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	q := msg.Questions[0]
	qn := strings.ToLower(q.Name.String())
	if !strings.HasSuffix(qn, ".in.test.") || (addr != "1.1.1.1:53" && addr != "5.5.5.5:53") {
		return f.p2eNet.QueryContext(ctx, msg, addr)
	}
	f.mu.Lock()
	f.Calls++
	f.mu.Unlock()
	r := &protocol.Message{Header: protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
		Questions: []*protocol.Question{q}}
	if addr == "1.1.1.1:53" {
		r.Authorities = append(r.Authorities, p2eRR("in.test.", protocol.TypeNS, &protocol.RDataNS{NSDName: p2eN("ns.in.test.")}))
		r.Additionals = append(r.Additionals, p2eRR("ns.in.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{5, 5, 5, 5}}))
		return r, nil
	}
	r.Header.Flags.AA = true
	switch qn {
	case "www.in.test.":
		r.Answers = append(r.Answers, p2gWWW("www.in.test.")...)
	case "alias.in.test.":
		r.Answers = append(append(r.Answers, p2gCNAME(qn, "www.in.test.")...), p2gWWW("www.in.test.")...)
	case "mixed.in.test.": // in-reply target spelled with different case
		r.Answers = append(append(r.Answers, p2gCNAME(qn, "www.in.test.")...), p2gWWW("WWW.In.Test.")...)
	case "h1.in.test.":
		r.Answers = append(append(append(r.Answers, p2gCNAME(qn, "h2.in.test.")...), p2gCNAME("h2.in.test.", "www.in.test.")...), p2gWWW("www.in.test.")...)
	case "h2.in.test.":
		r.Answers = append(append(r.Answers, p2gCNAME(qn, "www.in.test.")...), p2gWWW("www.in.test.")...)
	default:
		r.Header.Flags.RCODE = protocol.RcodeNameError
		r.Authorities = append(r.Authorities, p2eSOA("in.test."))
	}
	return r, nil
}

func p2gResolver(c Cache, f *p2gNet) *Resolver {
	cfg := DefaultConfig()
	cfg.Hints = []RootHint{{Name: "a.root.test.", IPv4: []string{"1.1.1.1"}}}
	cfg.DNSSECOK = true
	if c == nil {
		return NewResolver(cfg, nil, f)
	}
	return NewResolver(cfg, c, f)
}

func p2gKey(x *protocol.ResourceRecord) string {
	return fmt.Sprintf("%s|%d|%d|%s", strings.ToLower(x.Name.String()), x.Type, x.Class, x.Data.String())
}

func p2gCheckNoDups(t *testing.T, label string, answers []*protocol.ResourceRecord, wantDistinct int) {
	t.Helper()
	seen := map[string]int{}
	for _, x := range answers {
		seen[p2gKey(x)]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("%s: %dx duplicate %s", label, n, k)
		}
	}
	if len(seen) != wantDistinct || len(answers) != wantDistinct {
		t.Errorf("%s: %d answers (%d distinct), want %d distinct and no duplicates", label, len(answers), len(seen), wantDistinct)
	}
}

func TestResolve_InZoneCNAMETargetNotDuplicated_F572(t *testing.T) {
	for _, c := range []struct {
		qn       string
		distinct int // CNAMEs + RRSIG(CNAME)s + 2 A + 2 RRSIG(A)
	}{{"alias.in.test.", 6}, {"mixed.in.test.", 6}, {"h1.in.test.", 8}, {"c-ok.src.test.", 4}, {"www.in.test.", 4}} {
		for _, warm := range []bool{false, true} {
			var cache Cache
			if warm {
				cache = Newp2eMemCache()
			}
			r := p2gResolver(cache, &p2gNet{})
			m, err := r.Resolve(context.Background(), c.qn, protocol.TypeA)
			if warm && err == nil {
				m, err = r.Resolve(context.Background(), c.qn, protocol.TypeA)
			}
			if err != nil || m == nil || m.Header.Flags.RCODE != protocol.RcodeSuccess {
				t.Fatalf("%s warm=%v: resp=%v err=%v", c.qn, warm, m, err)
			}
			p2gCheckNoDups(t, fmt.Sprintf("%s warm=%v", c.qn, warm), m.Answers, c.distinct)
		}
	}
}

func TestDedupeRRs_F572(t *testing.T) {
	a1 := p2eRR("www.in.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{1, 1, 1, 1}})
	a1dupTTL := p2eRR("WWW.IN.TEST", protocol.TypeA, &protocol.RDataA{Address: [4]byte{1, 1, 1, 1}})
	a1dupTTL.TTL = 60
	a2 := p2eRR("www.in.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{1, 1, 1, 2}})
	sigA := p2gSig("www.in.test.", protocol.TypeA, 11)
	sigAOtherSig := p2gSig("www.in.test.", protocol.TypeA, 11)
	sigAOtherSig.Data.(*protocol.RDataRRSIG).Signature = []byte{9, 9, 9}
	sigADup := p2gSig("www.in.test.", protocol.TypeA, 11)
	otherClass := p2eRR("www.in.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{1, 1, 1, 1}})
	otherClass.Class = protocol.ClassCH
	otherOwner := p2eRR("w2.in.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{1, 1, 1, 1}})

	in := []*protocol.ResourceRecord{a1, sigA, a2, a1dupTTL, sigAOtherSig, sigADup, otherClass, otherOwner, nil}
	got := dedupeRRs(in)
	want := []*protocol.ResourceRecord{a1, sigA, a2, sigAOtherSig, otherClass, otherOwner, nil}
	if len(got) != len(want) {
		t.Fatalf("dedupeRRs kept %d records, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedupeRRs[%d] = %v, want %v (first occurrence, original order)", i, got[i], want[i])
		}
	}
	if got := dedupeRRs(nil); got != nil {
		t.Errorf("dedupeRRs(nil) = %v", got)
	}
}

func TestResolve_SideCachedTargetKeepsRRSIG_F573(t *testing.T) {
	f := &p2gNet{}
	r := p2gResolver(Newp2eMemCache(), f)
	if _, err := r.Resolve(context.Background(), "alias.in.test.", protocol.TypeA); err != nil {
		t.Fatal(err)
	}
	before := f.Calls
	m, err := r.Resolve(context.Background(), "www.in.test.", protocol.TypeA)
	if err != nil || m == nil {
		t.Fatalf("resp=%v err=%v", m, err)
	}
	if f.Calls != before {
		t.Fatalf("expected the target to be served from the side cache, made %d upstream queries", f.Calls-before)
	}
	p2gCheckNoDups(t, "www.in.test. after alias", m.Answers, 4)
	if !p2eHas(m.Answers, "www.in.test.", protocol.TypeRRSIG, protocol.TypeA) {
		t.Errorf("side-cached www.in.test./A lost its RRSIGs: %v", m.Answers)
	}

	// Direct: only RRSIGs over (owner, qtype) are carried; an owner whose
	// answer holds only signatures yields no side record.
	src := &protocol.Message{Answers: []*protocol.ResourceRecord{
		p2eRR("x.in.test.", protocol.TypeA, &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}),
		p2gSig("x.in.test.", protocol.TypeA, 1),
		p2gSig("x.in.test.", protocol.TypeTXT, 2),
		p2gSig("y.in.test.", protocol.TypeA, 3),
	}}
	side := synthesizeSideRecord("x.in.test.", protocol.TypeA, src)
	if side == nil || len(side.Answers) != 2 || side.Answers[0].Type != protocol.TypeA ||
		!isRRSIGCovering(side.Answers[1], protocol.TypeA, side.Answers[1].Name) ||
		side.Answers[1].Data.(*protocol.RDataRRSIG).KeyTag != 1 {
		t.Errorf("synthesizeSideRecord(x, A) = %v, want [A, RRSIG(A) keytag 1]", side)
	}
	if got := synthesizeSideRecord("y.in.test.", protocol.TypeA, src); got != nil {
		t.Errorf("synthesizeSideRecord(y, A) with only an RRSIG = %v, want nil", got.Answers)
	}
}
