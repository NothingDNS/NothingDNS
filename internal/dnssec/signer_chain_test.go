// Regression tests for the 2026-09 false-SERVFAIL fixes seen against live
// resolvers: chains are built to the RRSIG signer instead of the query name,
// empty DS answers below a zone cut are classified (not-a-cut, name error,
// insecure delegation), and out-of-zone CNAME targets validate against their
// own signer's chain.

package dnssec

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestSigningZone(t *testing.T) {
	sigFrom := func(owner, signer string, covered uint16) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{
			Name: mustName(t, owner), Type: protocol.TypeRRSIG,
			Data: &protocol.RDataRRSIG{TypeCovered: covered, SignerName: mustName(t, signer)},
		}
	}
	tests := []struct {
		name  string
		msg   *protocol.Message
		query string
		want  string
	}{
		{
			name:  "answer signed by parent zone",
			msg:   &protocol.Message{Answers: []*protocol.ResourceRecord{sigFrom("www.example.com.", "example.com.", protocol.TypeA)}},
			query: "www.example.com.", want: "example.com.",
		},
		{
			name:  "signer outside bailiwick is ignored",
			msg:   &protocol.Message{Answers: []*protocol.ResourceRecord{sigFrom("www.example.com.", "attacker.net.", protocol.TypeA)}},
			query: "www.example.com.", want: "www.example.com.",
		},
		{
			name:  "RRSIG of another owner is ignored",
			msg:   &protocol.Message{Answers: []*protocol.ResourceRecord{sigFrom("host.example.net.", "example.net.", protocol.TypeA)}},
			query: "www.example.com.", want: "www.example.com.",
		},
		{
			name:  "negative answer uses authority signer",
			msg:   &protocol.Message{Authorities: []*protocol.ResourceRecord{sigFrom("example.com.", "example.com.", protocol.TypeSOA)}},
			query: "missing.example.com.", want: "example.com.",
		},
		{
			name:  "unsigned answer falls back to query name",
			msg:   &protocol.Message{},
			query: "www.example.com.", want: "www.example.com.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := signingZone(tt.msg, tt.query); got != tt.want {
				t.Errorf("signingZone = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNSECDSDenial(t *testing.T) {
	nsec := func(next string, types ...uint16) *protocol.RDataNSEC {
		return &protocol.RDataNSEC{NextDomain: mustName(t, next), TypeBitMap: types}
	}
	tests := []struct {
		name, zone, owner string
		data              *protocol.RDataNSEC
		want              dsDenial
	}{
		{"delegation without DS", "child.example.com.", "child.example.com.", nsec("d.example.com.", protocol.TypeNS, protocol.TypeNSEC), dsDenialInsecureDelegation},
		{"name without NS is not a cut", "www.example.com.", "www.example.com.", nsec("x.example.com.", protocol.TypeA, protocol.TypeNSEC), dsDenialNotZoneCut},
		{"child apex is not a parent proof", "child.example.com.", "child.example.com.", nsec("d.example.com.", protocol.TypeNS, protocol.TypeSOA), dsDenialNone},
		{"empty non-terminal", "b.example.com.", "a.example.com.", nsec("x.b.example.com.", protocol.TypeA), dsDenialNotZoneCut},
		{"name does not exist", "b.example.com.", "a.example.com.", nsec("c.example.com.", protocol.TypeA), dsDenialNameError},
		{"range does not cover name", "b.example.com.", "c.example.com.", nsec("d.example.com.", protocol.TypeA), dsDenialNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nsecDSDenial(tt.owner, tt.zone, tt.data); got != tt.want {
				t.Errorf("nsecDSDenial(%s, %s) = %v, want %v", tt.owner, tt.zone, got, tt.want)
			}
		})
	}
}

// A validating upstream answers the DS query for a CNAME owner with the
// signed CNAME; that proves the name is not a zone cut. An unsigned CNAME
// proves nothing.
func TestClassifyDSDenial_SignedCNAME(t *testing.T) {
	f := newDenialFixture(t)
	cname := &protocol.ResourceRecord{
		Name: mustName(t, "www.example.com."), Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataCNAME{CName: mustName(t, "cdn.example.net.")},
	}
	sig := f.keys.sign(t, "example.com.", []*protocol.ResourceRecord{cname})

	signed := &protocol.Message{Answers: []*protocol.ResourceRecord{cname, sig}}
	if got := f.v.classifyDSDenial(signed, "www.example.com.", f.chain); got != dsDenialNotZoneCut {
		t.Errorf("signed CNAME: got %v, want dsDenialNotZoneCut", got)
	}
	unsigned := &protocol.Message{Answers: []*protocol.ResourceRecord{cname}}
	if got := f.v.classifyDSDenial(unsigned, "www.example.com.", f.chain); got != dsDenialNone {
		t.Errorf("unsigned CNAME: got %v, want dsDenialNone", got)
	}
}

// An authenticated NSEC3 matching the name without NS in its bitmap proves
// the name is not a zone cut.
func TestClassifyDSDenial_NSEC3NotZoneCut(t *testing.T) {
	f := newDenialFixture(t)
	raw, err := NSEC3Hash("www.example.com.", 1, 0, nil)
	if err != nil {
		t.Fatalf("NSEC3Hash: %v", err)
	}
	nsec3 := &protocol.ResourceRecord{
		Name: mustName(t, strings.ToUpper(protocol.Base32Encode(raw))+".example.com."),
		Type: protocol.TypeNSEC3, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC3{
			HashAlgorithm: 1, HashLength: uint8(len(raw)), NextHashed: raw,
			TypeBitMap: []uint16{protocol.TypeA, protocol.TypeRRSIG},
		},
	}
	set, sig := f.signDenialSet(t, []*protocol.ResourceRecord{nsec3})
	msg := negMsg(protocol.RcodeSuccess, "www.example.com.", append(set, sig))
	if got := f.v.classifyDSDenial(msg, "www.example.com.", f.chain); got != dsDenialNotZoneCut {
		t.Errorf("got %v, want dsDenialNotZoneCut", got)
	}
	if f.v.verifyDSDenial(msg, "www.example.com.", f.chain) {
		t.Error("a non-cut proof must not be reported as an insecure delegation")
	}
}

func aRecord(t *testing.T, owner string) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{
		Name: mustName(t, owner), Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}
}

// www.example.com. is a plain name inside example.com. — the old chain
// builder asked for its DS, got an empty answer and returned Bogus
// (downgrade guard). The chain must end at the signer.
func TestValidateResponse_SubdomainSignedByParentZone(t *testing.T) {
	v, keys := buildTwoLevelFixture(t)
	a := aRecord(t, "www.example.com.")
	msg := &protocol.Message{
		Header:  protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{a, keys["example.com."].sign(t, "example.com.", []*protocol.ResourceRecord{a})},
	}
	result, err := v.ValidateResponse(context.Background(), msg, "www.example.com.")
	if err != nil {
		t.Fatalf("ValidateResponse: %v", err)
	}
	if result != ValidationSecure {
		t.Errorf("result = %v, want SECURE", result)
	}
}

// Walking below a signed zone for an unsigned answer: an authenticated NSEC
// saying the name has no NS ends the walk without marking it insecure.
func TestBuildChain_StopsAtNonCut(t *testing.T) {
	v, keys := buildTwoLevelFixture(t)
	nsec := &protocol.ResourceRecord{
		Name: mustName(t, "www.example.com."), Type: protocol.TypeNSEC, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataNSEC{NextDomain: mustName(t, "x.example.com."), TypeBitMap: []uint16{protocol.TypeA, protocol.TypeRRSIG, protocol.TypeNSEC}},
	}
	sig := keys["example.com."].sign(t, "example.com.", []*protocol.ResourceRecord{nsec})
	mock := v.resolver.(*mockResolver)
	mock.responses["www.example.com.|"+strconv.Itoa(int(protocol.TypeDS))] = &protocol.Message{
		Header:      protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Authorities: []*protocol.ResourceRecord{nsec, sig},
	}

	anchor, remaining := v.trustAnchors.FindClosestAnchor("www.example.com.")
	chain, insecure, err := v.buildChain(context.Background(), anchor, remaining)
	if err != nil {
		t.Fatalf("buildChain: %v", err)
	}
	if insecure {
		t.Fatal("a non-cut proof must not make the chain insecure")
	}
	if got := chain[len(chain)-1].zone; got != "example.com." {
		t.Errorf("last link = %q, want example.com.", got)
	}

	delete(mock.responses, "www.example.com.|"+strconv.Itoa(int(protocol.TypeDS)))
	if _, _, err := v.buildChain(context.Background(), anchor, remaining); err == nil {
		t.Error("an empty DS answer without a denial proof must stay an error (downgrade guard)")
	}
}

// A CNAME from example.com. into com. must validate the target RRset against
// com.'s keys instead of example.com.'s.
func TestValidateResponse_CrossZoneCNAME(t *testing.T) {
	v, keys := buildTwoLevelFixture(t)
	cname := &protocol.ResourceRecord{
		Name: mustName(t, "www.example.com."), Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataCNAME{CName: mustName(t, "host.com.")},
	}
	target := aRecord(t, "host.com.")
	msg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		Answers: []*protocol.ResourceRecord{
			cname, keys["example.com."].sign(t, "example.com.", []*protocol.ResourceRecord{cname}),
			target, keys["com."].sign(t, "com.", []*protocol.ResourceRecord{target}),
		},
	}
	result, err := v.ValidateResponse(context.Background(), msg, "www.example.com.")
	if err != nil {
		t.Fatalf("ValidateResponse: %v", err)
	}
	if result != ValidationSecure {
		t.Errorf("result = %v, want SECURE", result)
	}

	// The target signed by the wrong zone's key must not validate.
	msg.Answers[3] = keys["example.com."].sign(t, "com.", []*protocol.ResourceRecord{target})
	if result, _ := v.ValidateResponse(context.Background(), msg, "www.example.com."); result == ValidationSecure {
		t.Error("target RRSIG made with a key outside com.'s chain must not be Secure")
	}
}

// A DS query the upstream SERVFAILs must surface as a fetch error rather than
// an empty (downgradable) DS set.
func TestFetchDS_ServfailIsError(t *testing.T) {
	v, _ := buildTwoLevelFixture(t)
	mock := v.resolver.(*mockResolver)
	mock.responses["example.com.|"+strconv.Itoa(int(protocol.TypeDS))] = &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeServerFailure)},
	}
	if _, _, err := v.fetchDS(context.Background(), "example.com."); err == nil {
		t.Error("SERVFAIL DS answer must return an error")
	}
}
