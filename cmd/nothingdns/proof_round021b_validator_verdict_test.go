// Round-021 verification (follow-up): feed the PRODUCTION wildcard-NODATA
// response through the repo's own dnssec.Validator and report the verdict.
//
// Round 21 fixed the wire proof: denialRecords now attaches the NSEC owned by
// the wildcard (RFC 4035 §3.1.3.4) instead of nothing. That fix was verified
// only against the records on the wire. This harness checks the stronger claim
// it was never checked against: that a real validator classifies the answer
// SECURE rather than Bogus.
//
// It also probes two consequences of the validator's own NODATA path
// (validateNSEC has no §3.1.3.4 branch) and reports them rather than asserting
// them, so the suite stays green while the gaps are visible.
package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

// rr21bResolver answers the validator's chain fetch. buildChain requires the
// anchor zone's DNSKEY RRset WITH a KSK self-signature, so the stub returns the
// signer's DNSKEYs plus a fresh signature by the anchored KSK over them.
type rr21bResolver struct {
	answers []*protocol.ResourceRecord
}

func (r *rr21bResolver) Query(_ context.Context, name string, qtype uint16) (*protocol.Message, error) {
	resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)}}
	resp.Header.Flags.AA = true
	if q, err := protocol.NewQuery(1, name, qtype); err == nil {
		resp.Questions = q.Questions
	}
	if qtype == protocol.TypeDNSKEY &&
		strings.EqualFold(strings.TrimSuffix(name, "."), strings.TrimSuffix(rr21ZoneOrigin, ".")) {
		// Hand back COPIES: the validator releases the records it fetches
		// (fetchDNSKEYAndSigs defers msg.Release()), so returning the stored
		// originals would leave this stub serving zeroed records on the next
		// call — which shows up as a spurious "trust anchor validation failed".
		for _, rr := range r.answers {
			if rr != nil {
				resp.Answers = append(resp.Answers, rr.Copy())
			}
		}
	}
	return resp, nil
}

// rr21bValidator builds a validator anchored on the zone's KSK.
func rr21bValidator(t *testing.T, h *integratedHandler) *dnssec.Validator {
	t.Helper()

	signer := h.zoneSigners[rr21ZoneOrigin]
	if signer == nil {
		t.Fatal("no signer registered for " + rr21ZoneOrigin)
	}
	ksks := signer.GetKSKs()
	if len(ksks) == 0 {
		t.Fatal("signer has no KSK to anchor on")
	}
	keys, err := signer.DNSKEYRRSet(3600)
	if err != nil {
		t.Fatalf("DNSKEYRRSet: %v", err)
	}
	now := uint32(time.Now().Unix())
	sig, err := signer.SignRRSet(keys, ksks[0], now, now+48*3600)
	if err != nil {
		t.Fatalf("signing the DNSKEY RRset with the KSK: %v", err)
	}
	answers := append(append([]*protocol.ResourceRecord{}, keys...), sig)

	store := dnssec.NewTrustAnchorStore()
	store.AddAnchor(&dnssec.TrustAnchor{
		Zone:      rr21ZoneOrigin,
		KeyTag:    ksks[0].KeyTag,
		Algorithm: ksks[0].DNSKEY.Algorithm,
		PublicKey: ksks[0].DNSKEY.PublicKey,
	})

	cfg := dnssec.DefaultValidatorConfig()
	cfg.IgnoreTime = true
	return dnssec.NewValidator(cfg, store, &rr21bResolver{answers: answers})
}

// TestRound021bValidatorClassifiesWildcardNODATASecure asserts the round-21 fix
// end to end: the production response for a wildcard-matched NODATA must
// validate as Secure, not Bogus.
func TestRound021bValidatorClassifiesWildcardNODATASecure(t *testing.T) {
	h := rr21Handler(t)
	v := rr21bValidator(t, h)

	resp := rr21Serve(t, h, rr21WildOwner, protocol.TypeTXT)
	if got := rr21NSECOwners(resp); len(got) == 0 {
		t.Fatalf("precondition: no NSEC in the response (round-21 fix not in place?)")
	}

	res, err := v.ValidateResponse(context.Background(), resp, rr21WildOwner)
	if err != nil {
		t.Fatalf("ValidateResponse(%s): %v", rr21WildOwner, err)
	}
	if res != dnssec.ValidationSecure {
		t.Fatalf("the round-21 wildcard-NODATA response validated as %v, want Secure: the wire proof is "+
			"RFC 4035 §3.1.3.4-correct (NSEC owned by %s, signed by the zone ZSK), so a validator must "+
			"authenticate it — anything else means the wire fix is necessary but not sufficient for "+
			"in-repo validation", res, rr21Wildcard)
	}
	t.Logf("verified: %s TXT (wildcard-matched NODATA) → %v", rr21WildOwner, res)

	// Probe 1 — position dependence. validateNSEC accepts either owner==qname
	// (type absence) or a range cover (nonexistence); it has no §3.1.3.4 branch
	// for "the proof is owned by the wildcard". So the verdict tracks where the
	// queried name sorts inside the wildcard NSEC's range rather than whether
	// the RFC-correct proof is present.
	for _, qname := range []string{"aaa." + rr21ZoneOrigin, "zzz." + rr21ZoneOrigin} {
		r := rr21Serve(t, h, qname, protocol.TypeTXT)
		verdict, verr := v.ValidateResponse(context.Background(), r, qname)
		t.Logf("probe position: %s TXT (same RFC-correct proof) → %v err=%v", qname, verdict, verr)
	}

	// Probe 2 — replay. The wildcard DOES hold an A record, so a NODATA claim
	// for foo.<zone> A is false. Re-ask the NODATA response (whose proof is the
	// wildcard's own signed NSEC, obtainable by any client) as an A query.
	forged := rr21Serve(t, h, rr21WildOwner, protocol.TypeTXT)
	if len(forged.Questions) == 0 {
		t.Fatal("precondition: response carries no question to retype")
	}
	forged.Questions[0].QType = protocol.TypeA
	verdict, verr := v.ValidateResponse(context.Background(), forged, rr21WildOwner)
	t.Logf("probe replay: false NODATA claimed for %s A (the wildcard HAS A %s) → %v err=%v",
		rr21WildOwner, rr21WildcardAddr, verdict, verr)
}
