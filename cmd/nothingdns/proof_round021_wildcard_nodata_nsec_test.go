// Round-021 proof: a wildcard-expanded NODATA answer from a signed zone must
// carry the NSEC owned by the WILDCARD, or a validator cannot prove the type is
// absent and rejects the answer.
//
// CONTRACT. RFC 4035 §3.1.3.4 (Wildcard No Data): when a wildcard match supplies
// no records of the requested type, the server must include the NSEC RR that
// proves the type does not exist at the wildcard owner name — the owner of that
// NSEC is the wildcard itself (e.g. "*.example.com."), not the queried name.
// §3.1.3.1 (plain No Data) covers the different case where the queried name is a
// node in the zone: there the NSEC matching the query name carries the proof.
//
// DEFECT. denialRecords (cmd/nothingdns/denial_proof.go:97-102) handles No Data
// with `z.NSECForName(qname)` alone. NSECForName returns false when the name is
// not a node (internal/zone/nsec.go:40-42), and a wildcard-matched name is
// precisely not a node — only "*.example.com." is. So for foo.example.com. TXT
// against a zone holding "*.example.com. A", addDenialProof attaches a signed
// SOA and NO NSEC at all, and the NODATA answer is unprovable: a validating
// resolver returns SERVFAIL. The zone's own wildcard NODATA detection is
// correct (LookupWildcard reports found=true with an empty match set, RFC 4592
// §2.2.1) — only the proof selection is missing.
package main

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	rr21ZoneOrigin   = "signed21.test."
	rr21Wildcard     = "*." + rr21ZoneOrigin
	rr21WildOwner    = "foo." + rr21ZoneOrigin
	rr21NodeOwner    = "www." + rr21ZoneOrigin
	rr21WildcardAddr = "192.0.2.1"
	rr21NodeAddr     = "192.0.2.2"
)

// rr21Handler builds a signed zone holding a wildcard plus one ordinary node,
// with an active ZSK registered for it so addDenialProof proceeds.
func rr21Handler(t *testing.T) *integratedHandler {
	t.Helper()

	signer := dnssec.NewSigner(rr21ZoneOrigin, dnssec.DefaultSignerConfig())
	for _, isKSK := range []bool{true, false} {
		key, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, isKSK)
		if err != nil {
			t.Fatalf("GenerateKeyPair(ksk=%v): %v", isKSK, err)
		}
		signer.AddKey(key)
		signer.SetKeyState(key.KeyTag, dnssec.KeyStateActive)
	}

	z := &zone.Zone{
		Origin: rr21ZoneOrigin,
		SOA: &zone.SOARecord{
			Name: rr21ZoneOrigin, TTL: 3600,
			MName: "ns1." + rr21ZoneOrigin, RName: "hostmaster." + rr21ZoneOrigin,
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300,
		},
		Records: map[string][]zone.Record{
			rr21Wildcard:  {{Name: rr21Wildcard, TTL: 300, Class: "IN", Type: "A", RData: rr21WildcardAddr}},
			rr21NodeOwner: {{Name: rr21NodeOwner, TTL: 300, Class: "IN", Type: "A", RData: rr21NodeAddr}},
		},
	}

	h := newTestHandler()
	h.zones = map[string]*zone.Zone{rr21ZoneOrigin: z}
	h.zoneProvider = NewMultiZoneProvider(h.zones, nil, nil, nil)
	h.zoneSigners = map[string]*dnssec.Signer{rr21ZoneOrigin: signer}
	return h
}

// rr21Query builds a DO=1 query, which is what makes addDenialProof run.
func rr21Query(t *testing.T, qname string, qtype uint16) *protocol.Message {
	t.Helper()
	msg := newTestQuery(t, qname, qtype)
	msg.SetEDNS0(4096, true)
	return msg
}

func rr21NSECOwners(resp *protocol.Message) []string {
	var owners []string
	for _, rr := range resp.Authorities {
		if rr != nil && rr.Type == protocol.TypeNSEC && rr.Name != nil {
			owners = append(owners, rr.Name.String())
		}
	}
	return owners
}

func rr21Serve(t *testing.T, h *integratedHandler, qname string, qtype uint16) *protocol.Message {
	t.Helper()
	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, rr21Query(t, qname, qtype))
	if w.msg == nil {
		t.Fatalf("no response for %s/%s", qname, protocol.TypeString(qtype))
	}
	return w.msg
}

// TestRound021WildcardNODATACarriesWildcardNSEC is the defect case: the wildcard
// matches foo.signed21.test. but has no TXT, so the response must carry the NSEC
// owned by *.signed21.test. (RFC 4035 §3.1.3.4).
func TestRound021WildcardNODATACarriesWildcardNSEC(t *testing.T) {
	h := rr21Handler(t)

	resp := rr21Serve(t, h, rr21WildOwner, protocol.TypeTXT)
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("wildcard NODATA: rcode = %d (%s), want NOERROR",
			resp.Header.Flags.RCODE, protocol.RcodeString(int(resp.Header.Flags.RCODE)))
	}
	owners := rr21NSECOwners(resp)
	if len(owners) == 0 {
		t.Fatalf("a DO=1 client asked %s TXT in a signed zone; the wildcard %s matched but has no TXT, "+
			"so this NODATA answer must carry the NSEC owned by the wildcard itself (RFC 4035 §3.1.3.4). "+
			"The authority section carries no NSEC at all, so a validating resolver cannot prove the type "+
			"is absent and answers SERVFAIL. denialRecords looks up NSECForName(%s), which returns false "+
			"because a wildcard-matched name is not a zone node (internal/zone/nsec.go:40-42).",
			rr21WildOwner, rr21Wildcard, rr21WildOwner)
	}
	for _, owner := range owners {
		if owner == rr21Wildcard {
			return // the wildcard's own NSEC is the required proof
		}
	}
	t.Fatalf("wildcard NODATA proof is owned by %v, want the wildcard owner %q (RFC 4035 §3.1.3.4)",
		owners, rr21Wildcard)
}

// TestRound021WildcardNODATAControls pins the neighbouring cases: a plain
// (non-wildcard) NODATA at an existing node still proves itself with the NSEC at
// that node, and the positive wildcard answer is unaffected.
func TestRound021WildcardNODATAControls(t *testing.T) {
	h := rr21Handler(t)

	// Plain NODATA: www.signed21.test. exists as a node but has no TXT.
	resp := rr21Serve(t, h, rr21NodeOwner, protocol.TypeTXT)
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("control: plain NODATA rcode = %d, want NOERROR", resp.Header.Flags.RCODE)
	}
	owners := rr21NSECOwners(resp)
	found := false
	for _, owner := range owners {
		if owner == rr21NodeOwner {
			found = true
		}
	}
	if !found {
		t.Fatalf("control: plain NODATA must carry the NSEC owned by %s (§3.1.3.1); got %v",
			rr21NodeOwner, owners)
	}

	// Positive wildcard answer: A at the wildcard-matched name.
	resp = rr21Serve(t, h, rr21WildOwner, protocol.TypeA)
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("control: wildcard A rcode = %d, want NOERROR", resp.Header.Flags.RCODE)
	}
	got := ""
	for _, rr := range resp.Answers {
		if rr != nil && rr.Type == protocol.TypeA {
			if a, ok := rr.Data.(*protocol.RDataA); ok && a != nil {
				got = net.IP(a.Address[:]).String()
			}
		}
	}
	if got != rr21WildcardAddr {
		t.Fatalf("control: wildcard A answer = %q, want %q", got, rr21WildcardAddr)
	}
}
