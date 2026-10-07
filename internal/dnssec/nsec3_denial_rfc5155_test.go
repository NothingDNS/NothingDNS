package dnssec

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Regression tests for F347 (NSEC3 NODATA accepted a merely covering NSEC3)
// and F348 (a literal "*.zone" owner queried directly was treated as a
// wildcard expansion). Fixtures are signed in-process; IgnoreTime removes
// any wall-clock dependence.

func newNSEC3DenialFixture(t *testing.T) *denialFixture {
	t.Helper()
	f := newDenialFixture(t)
	cfg := DefaultValidatorConfig()
	cfg.IgnoreTime = true
	f.v = NewValidator(cfg, nil, nil)
	return f
}

// nsec3TestZone builds a complete NSEC3 chain (SHA-1, 0 iterations, no salt;
// RFC 9276 parameters) for owner name -> type bitmap under example.com.
// Names listed in optOut get the Opt-Out flag.
func nsec3TestZone(t *testing.T, names map[string][]uint16, optOut ...string) map[string]*protocol.ResourceRecord {
	t.Helper()
	type ent struct {
		name, hash string
		raw        []byte
	}
	var ents []ent
	for n := range names {
		h, err := NSEC3Hash(n, 1, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		ents = append(ents, ent{n, strings.ToUpper(protocol.Base32Encode(h)), h})
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].hash < ents[j].hash })
	out := map[string]*protocol.ResourceRecord{}
	for i, e := range ents {
		var flags uint8
		for _, o := range optOut {
			if o == e.name {
				flags = protocol.NSEC3FlagOptOut
			}
		}
		out[e.name] = &protocol.ResourceRecord{
			Name: mustName(t, strings.ToLower(e.hash)+".example.com."), Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataNSEC3{HashAlgorithm: 1, Flags: flags, HashLength: 20,
				NextHashed: ents[(i+1)%len(ents)].raw, TypeBitMap: names[e.name]},
		}
	}
	return out
}

// nsec3TestCover returns the zone NSEC3 whose range covers hash(name).
func nsec3TestCover(t *testing.T, zone map[string]*protocol.ResourceRecord, name string) *protocol.ResourceRecord {
	t.Helper()
	h, _ := NSEC3Hash(name, 1, 0, nil)
	hs := strings.ToUpper(protocol.Base32Encode(h))
	for _, rr := range zone {
		n := rr.Data.(*protocol.RDataNSEC3)
		if nsec3HashInRange(hs, strings.ToUpper(extractNSEC3Hash(rr.Name.String())), strings.ToUpper(protocol.Base32Encode(n.NextHashed))) {
			return rr
		}
	}
	t.Fatalf("no NSEC3 covers %s", name)
	return nil
}

func nsec3TestAuth(t *testing.T, f *denialFixture, rrs ...*protocol.ResourceRecord) []*protocol.ResourceRecord {
	t.Helper()
	var out []*protocol.ResourceRecord
	seen := map[*protocol.ResourceRecord]bool{}
	for _, rr := range rrs {
		if seen[rr] {
			continue
		}
		seen[rr] = true
		set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{rr})
		out = append(out, set...)
		out = append(out, sig)
	}
	return out
}

func nsec3TestNoData(f *denialFixture, qname string, qtype uint16, auth []*protocol.ResourceRecord) ValidationResult {
	m := negMsg(protocol.RcodeSuccess, qname, auth)
	m.Questions[0].QType = qtype
	return f.v.validateNegativeResponse(m, qname, f.chain)
}

func TestNSEC3NoDataProofRFC5155(t *testing.T) {
	f := newNSEC3DenialFixture(t)
	ds := []uint16{protocol.TypeNS, protocol.TypeDS, protocol.TypeRRSIG}
	names := map[string][]uint16{
		"example.com.":   {protocol.TypeSOA, protocol.TypeNS, protocol.TypeDNSKEY, protocol.TypeRRSIG, protocol.TypeNSEC3PARAM},
		"*.example.com.": {protocol.TypeA, protocol.TypeRRSIG},
		"w.example.com.": {protocol.TypeA, protocol.TypeRRSIG},
		"y.example.com.": {protocol.TypeA, protocol.TypeRRSIG},
		"s.example.com.": ds,
	}
	z := nsec3TestZone(t, names)
	zOpt := nsec3TestZone(t, names, "example.com.", "*.example.com.", "w.example.com.", "y.example.com.", "s.example.com.")
	apex, wild := z["example.com."], z["*.example.com."]
	coverX := nsec3TestCover(t, z, "x.example.com.")

	cases := []struct {
		name  string
		qname string
		qtype uint16
		auth  []*protocol.ResourceRecord
		want  ValidationResult
	}{
		{"exact match, qtype absent", "w.example.com.", protocol.TypeAAAA, nsec3TestAuth(t, f, z["w.example.com."]), ValidationSecure},
		{"exact match, qtype present", "w.example.com.", protocol.TypeA, nsec3TestAuth(t, f, z["w.example.com."]), ValidationBogus},
		{"wildcard NODATA (8.7)", "x.example.com.", protocol.TypeAAAA, nsec3TestAuth(t, f, apex, coverX, wild), ValidationSecure},
		{"cover only erases wildcard answer", "x.example.com.", protocol.TypeA, nsec3TestAuth(t, f, coverX), ValidationBogus},
		{"cover only, other qtype", "x.example.com.", protocol.TypeAAAA, nsec3TestAuth(t, f, coverX), ValidationBogus},
		{"wildcard NSEC3 has qtype", "x.example.com.", protocol.TypeA, nsec3TestAuth(t, f, apex, coverX, wild), ValidationBogus},
		{"wildcard at shallower name than CE", "a.w.example.com.", protocol.TypeAAAA,
			nsec3TestAuth(t, f, z["w.example.com."], nsec3TestCover(t, z, "a.w.example.com."), wild), ValidationBogus},
		{"DS: opt-out cover of next closer (8.6)", "x.example.com.", protocol.TypeDS,
			nsec3TestAuth(t, f, zOpt["example.com."], nsec3TestCover(t, zOpt, "x.example.com.")), ValidationInsecure}, // RFC 5155 §9.2: no AD (F377)
		{"DS: non-opt-out cover", "x.example.com.", protocol.TypeDS, nsec3TestAuth(t, f, apex, coverX), ValidationBogus},
		{"A: opt-out cover is not NODATA", "x.example.com.", protocol.TypeA,
			nsec3TestAuth(t, f, zOpt["example.com."], nsec3TestCover(t, zOpt, "x.example.com.")), ValidationBogus},
		{"DS: exact match without DS", "w.example.com.", protocol.TypeDS, nsec3TestAuth(t, f, z["w.example.com."]), ValidationSecure},
		{"DS: exact match with DS", "s.example.com.", protocol.TypeDS, nsec3TestAuth(t, f, z["s.example.com."]), ValidationBogus},
		{"empty authority", "x.example.com.", protocol.TypeA, nil, ValidationBogus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 2; i++ { // repeated call: no state carried between validations
				if got := nsec3TestNoData(f, tc.qname, tc.qtype, tc.auth); got != tc.want {
					t.Fatalf("call %d: got %v, want %v", i, got, tc.want)
				}
			}
		})
	}
}

func TestLiteralWildcardOwnerRRSIGLabelsRFC4035(t *testing.T) {
	f := newNSEC3DenialFixture(t)
	a := func(owner string) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{Name: mustName(t, owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}}}
	}
	msg := func(qname string, answers ...*protocol.ResourceRecord) *protocol.Message {
		m := negMsg(protocol.RcodeSuccess, qname, nil)
		m.Answers = answers
		return m
	}
	wild := a("*.example.com.")
	wsig := f.keys.sign(t, "example.com.", []*protocol.ResourceRecord{wild})
	if l := wsig.Data.(*protocol.RDataRRSIG).Labels; l != 2 {
		t.Fatalf("wildcard RRSIG Labels = %d, want 2", l)
	}
	sub := a("*.sub.example.com.")
	subSig := f.keys.sign(t, "example.com.", []*protocol.ResourceRecord{sub})
	// sub.example.com. lies between the signer and *.sub.example.com., so the
	// validator needs the parent's proof that it is not a zone cut (F472).
	subNSEC := &protocol.ResourceRecord{Name: mustName(t, "sub.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(t, "*.sub.example.com."), TypeBitMap: []uint16{protocol.TypeRRSIG, protocol.TypeNSEC}}}
	f.v.resolver = &mockResolver{responses: map[string]*protocol.Message{
		"sub.example.com.|43": {Authorities: []*protocol.ResourceRecord{subNSEC, f.keys.sign(t, "example.com.", []*protocol.ResourceRecord{subNSEC})}},
	}}

	cases := []struct {
		name  string
		qname string
		m     *protocol.Message
		want  ValidationResult
	}{
		{"literal *.example.com queried directly", "*.example.com.", msg("*.example.com.", wild, wsig), ValidationSecure},
		{"literal *.sub.example.com queried directly", "*.sub.example.com.", msg("*.sub.example.com.", sub, subSig), ValidationSecure},
		{"expansion onto x.example.com without proof", "x.example.com.", msg("x.example.com.", a("x.example.com."), wsig), ValidationBogus},
		{"*.example.com RRSIG expanded onto literal *.sub.example.com without proof", "*.sub.example.com.",
			msg("*.sub.example.com.", sub, wsig), ValidationBogus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < 2; i++ {
				if got := f.v.validateMessage(context.Background(), tc.m, tc.qname, f.chain); got != tc.want {
					t.Fatalf("call %d: got %v, want %v", i, got, tc.want)
				}
			}
		})
	}
}
