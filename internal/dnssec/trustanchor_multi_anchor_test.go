package dnssec

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// multiAnchorFor returns a DS-style root anchor for k with the given window.
func multiAnchorFor(k *testZoneKeys, from time.Time, until *time.Time) *TrustAnchor {
	return &TrustAnchor{
		Zone:       ".",
		KeyTag:     k.keyTag,
		Algorithm:  k.dnskey.Algorithm,
		DigestType: 2,
		Digest:     calculateDSDigestFromDNSKEY(".", k.dnskey, 2),
		ValidFrom:  from,
		ValidUntil: until,
	}
}

// multiAnchorChain runs buildChain for a root whose DNSKEY RRset is
// `published`, self-signed only by `signer`, with `anchors` in store order.
func multiAnchorChain(t *testing.T, published []*testZoneKeys, signer *testZoneKeys, anchors ...*TrustAnchor) error {
	t.Helper()
	var rrs []*protocol.ResourceRecord
	for _, k := range published {
		rrs = append(rrs, k.keyRR)
	}
	sig := signer.sign(t, ".", rrs)
	mock := &mockResolver{responses: map[string]*protocol.Message{
		".|" + strconv.Itoa(int(protocol.TypeDNSKEY)): {Answers: append(append([]*protocol.ResourceRecord{}, rrs...), sig)},
	}}
	store := NewTrustAnchorStore()
	for _, a := range anchors {
		store.AddAnchor(a)
	}
	v := NewValidator(DefaultValidatorConfig(), store, mock)
	anchor, remaining := store.FindClosestAnchor(".")
	if anchor == nil {
		return errNoAnchorForTest
	}
	_, _, err := v.buildChain(context.Background(), anchor, remaining)
	return err
}

type testErr string

func (e testErr) Error() string { return string(e) }

const errNoAnchorForTest = testErr("no anchor")

// TestBuildChain_RootKSKRolloverUsesEveryValidAnchor is the F237 regression:
// with the outgoing and incoming root KSK both configured (as in RFC 7958
// root-anchors.xml), a DNSKEY RRset self-signed only by the incoming KSK must
// validate. Previously only the first-listed valid anchor was consulted.
func TestBuildChain_RootKSKRolloverUsesEveryValidAnchor(t *testing.T) {
	oldKSK := newTestZoneKeys(t, ".")
	newKSK := newTestZoneKeys(t, ".")
	attacker := newTestZoneKeys(t, ".")
	past := time.Now().Add(-24 * time.Hour)
	expired := time.Now().Add(-time.Hour)
	oldA := multiAnchorFor(oldKSK, past, nil)
	newA := multiAnchorFor(newKSK, past, nil)

	cases := []struct {
		name      string
		published []*testZoneKeys
		signer    *testZoneKeys
		anchors   []*TrustAnchor
		wantOK    bool
	}{
		{"rollover: both published, new signs", []*testZoneKeys{oldKSK, newKSK}, newKSK, []*TrustAnchor{oldA, newA}, true},
		{"post-rollover: only new published", []*testZoneKeys{newKSK}, newKSK, []*TrustAnchor{oldA, newA}, true},
		{"pre-rollover: old signs", []*testZoneKeys{oldKSK, newKSK}, oldKSK, []*TrustAnchor{oldA, newA}, true},
		{"new anchor expired", []*testZoneKeys{oldKSK, newKSK}, newKSK, []*TrustAnchor{oldA, multiAnchorFor(newKSK, past.Add(-time.Hour), &expired)}, false},
		{"new anchor not yet valid", []*testZoneKeys{oldKSK, newKSK}, newKSK, []*TrustAnchor{oldA, multiAnchorFor(newKSK, time.Now().Add(time.Hour), nil)}, false},
		{"injected key signs the set", []*testZoneKeys{oldKSK, newKSK, attacker}, attacker, []*TrustAnchor{oldA, newA}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := multiAnchorChain(t, tc.published, tc.signer, tc.anchors...)
			if tc.wantOK && err != nil {
				t.Fatalf("buildChain: %v, want success", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("buildChain succeeded, want failure")
			}
		})
	}

	// An anchor for another zone must never authenticate the root.
	store := NewTrustAnchorStore()
	store.AddAnchor(oldA)
	com := multiAnchorFor(newKSK, past, nil)
	com.Zone = "com."
	store.AddAnchor(com)
	if got := store.validAnchorsForZone(".", time.Now()); len(got) != 1 || got[0].KeyTag != oldKSK.keyTag {
		t.Fatalf("validAnchorsForZone(.) = %d anchors, want only the root one", len(got))
	}
}
