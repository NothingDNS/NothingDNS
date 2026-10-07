package dnssec

// Regression tests for the NSEC3 wildcard-expansion proof (RFC 5155 §8.8,
// §9.2): F522 — the next-closer cover alone suffices (no NSEC3 matching the
// closest encloser is required; RFC 5155 Appendix B.4, BIND, Knot); F523 — an
// Opt-Out next-closer cover makes the answer Insecure, never Secure
// (consistent with F377 for negative answers).

import (
	"context"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

type wcN3Fixture struct {
	t    *testing.T
	k    *keytrapKey
	v    *Validator
	wild *protocol.ResourceRecord
	wsig *protocol.ResourceRecord
}

func newWCN3Fixture(t *testing.T) *wcN3Fixture {
	t.Helper()
	k := newKeytrapKey(t, "example.com.", protocol.DNSKEYFlagZone)
	wild := &protocol.ResourceRecord{Name: mustName(t, "*.example.com."), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 7}}}
	return &wcN3Fixture{t: t, k: k, v: NewValidator(DefaultValidatorConfig(), nil, nil), wild: wild, wsig: k.sign(t, []*protocol.ResourceRecord{wild})}
}

func (f *wcN3Fixture) hash(n string, salt []byte) []byte {
	h, err := NSEC3Hash(n, 1, 5, salt)
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func wcN3Add(b []byte, d int) []byte {
	c := append([]byte(nil), b...)
	c[len(c)-1] += byte(d)
	return c
}

func (f *wcN3Fixture) nsec3(owner, next []byte, flags uint8, salt []byte) []*protocol.ResourceRecord {
	rr := &protocol.ResourceRecord{Name: mustName(f.t, strings.ToLower(protocol.Base32Encode(owner))+".example.com."), Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC3{HashAlgorithm: 1, Flags: flags, Iterations: 5, Salt: salt, HashLength: uint8(len(next)), NextHashed: next, TypeBitMap: []uint16{protocol.TypeA}}}
	return []*protocol.ResourceRecord{rr, f.k.sign(f.t, []*protocol.ResourceRecord{rr})}
}

func (f *wcN3Fixture) run(owner string, auth ...[]*protocol.ResourceRecord) ValidationResult {
	msg := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			{Name: mustName(f.t, owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300, Data: f.wild.Data},
			{Name: mustName(f.t, owner), Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 300, Data: f.wsig.Data}}}
	for _, a := range auth {
		msg.Authorities = append(msg.Authorities, a...)
	}
	return f.v.validateMessage(context.Background(), msg, owner, f.k.chain())
}

func TestWildcardNSEC3NextCloserCoverOnly_F522(t *testing.T) {
	f := newWCN3Fixture(t)
	salt := []byte{9, 9}
	apex := f.hash("example.com", salt)
	ce := f.nsec3(apex, wcN3Add(apex, 1), 0, salt)
	coverOf := func(name string) []*protocol.ResourceRecord {
		h := f.hash(name, salt)
		return f.nsec3(wcN3Add(h, -1), wcN3Add(h, 1), 0, salt)
	}
	sub := f.hash("sub.example.com", salt)
	cases := []struct {
		name  string
		owner string
		auth  [][]*protocol.ResourceRecord
		want  ValidationResult
	}{
		{"cover only, one label below", "a.example.com.", [][]*protocol.ResourceRecord{coverOf("a.example.com")}, ValidationSecure},
		{"cover only, three labels below", "a.b.sub.example.com.", [][]*protocol.ResourceRecord{coverOf("sub.example.com")}, ValidationSecure},
		{"cover only, mixed-case owner", "A.Example.COM.", [][]*protocol.ResourceRecord{coverOf("a.example.com")}, ValidationSecure},
		{"CE match + cover", "a.example.com.", [][]*protocol.ResourceRecord{ce, coverOf("a.example.com")}, ValidationSecure},
		{"no proof", "a.example.com.", nil, ValidationBogus},
		{"CE match only", "a.example.com.", [][]*protocol.ResourceRecord{ce}, ValidationBogus},
		{"cover of the wrong name", "a.example.com.", [][]*protocol.ResourceRecord{coverOf("zz.example.com")}, ValidationBogus},
		{"depth replay: next closer exists (match only)", "a.sub.example.com.", [][]*protocol.ResourceRecord{f.nsec3(sub, wcN3Add(sub, 1), 0, salt)}, ValidationBogus},
		{"depth replay: stale cover beside the next closer's match", "a.sub.example.com.", [][]*protocol.ResourceRecord{f.nsec3(sub, wcN3Add(sub, 1), 0, salt), coverOf("sub.example.com")}, ValidationBogus},
		{"mixed NSEC3 params", "a.example.com.", [][]*protocol.ResourceRecord{coverOf("a.example.com"), f.nsec3(apex, wcN3Add(apex, 1), 0, []byte{1})}, ValidationBogus},
	}
	for i := 0; i < 2; i++ { // repeated calls give the same verdict
		for _, c := range cases {
			if got := f.run(c.owner, c.auth...); got != c.want {
				t.Errorf("%s: got %v, want %v", c.name, got, c.want)
			}
		}
	}
}

func TestWildcardNSEC3OptOutCoverInsecure_F523(t *testing.T) {
	f := newWCN3Fixture(t)
	salt := []byte{9, 9}
	opt := uint8(protocol.NSEC3FlagOptOut)
	apex := f.hash("example.com", salt)
	nc := f.hash("a.example.com", salt)
	cases := []struct {
		name string
		auth [][]*protocol.ResourceRecord
		want ValidationResult
	}{
		{"opt-out cover with CE match", [][]*protocol.ResourceRecord{f.nsec3(apex, wcN3Add(apex, 1), 0, salt), f.nsec3(wcN3Add(nc, -1), wcN3Add(nc, 1), opt, salt)}, ValidationInsecure},
		{"opt-out cover alone", [][]*protocol.ResourceRecord{f.nsec3(wcN3Add(nc, -1), wcN3Add(nc, 1), opt, salt)}, ValidationInsecure},
		{"two covers, one opt-out", [][]*protocol.ResourceRecord{f.nsec3(wcN3Add(nc, -1), wcN3Add(nc, 1), 0, salt), f.nsec3(wcN3Add(nc, -2), wcN3Add(nc, 2), opt, salt)}, ValidationInsecure},
		{"opt-out only on the CE match", [][]*protocol.ResourceRecord{f.nsec3(apex, wcN3Add(apex, 1), opt, salt), f.nsec3(wcN3Add(nc, -1), wcN3Add(nc, 1), 0, salt)}, ValidationSecure},
		{"plain cover", [][]*protocol.ResourceRecord{f.nsec3(wcN3Add(nc, -1), wcN3Add(nc, 1), 0, salt)}, ValidationSecure},
		{"opt-out NSEC3 not covering the next closer", [][]*protocol.ResourceRecord{f.nsec3(wcN3Add(nc, 5), wcN3Add(nc, 6), opt, salt)}, ValidationBogus},
	}
	for _, c := range cases {
		if got := f.run("a.example.com.", c.auth...); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
