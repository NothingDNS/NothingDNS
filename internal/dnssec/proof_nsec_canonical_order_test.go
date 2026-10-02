package dnssec

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// proofNSECARecord builds a minimal A record for the given owner name.
func proofNSECARecord(t *testing.T, owner string) *protocol.ResourceRecord {
	t.Helper()
	name, err := protocol.ParseName(owner)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", owner, err)
	}
	return &protocol.ResourceRecord{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}
}

// proofWalkNSECChain walks the NSEC chain in the signed output (following
// NextDomain links once each) and returns the lowercased owner names in
// chain order. A broken chain fails the test.
func proofWalkNSECChain(t *testing.T, signed []*protocol.ResourceRecord) []string {
	t.Helper()
	byOwner := make(map[string]*protocol.RDataNSEC)
	var owners []string
	for _, rr := range signed {
		if rr == nil || rr.Type != protocol.TypeNSEC || rr.Data == nil {
			continue
		}
		owner := strings.ToLower(rr.Name.String())
		nsec, ok := rr.Data.(*protocol.RDataNSEC)
		if !ok {
			t.Fatalf("NSEC record has non-NSEC RData at %q", owner)
		}
		byOwner[owner] = nsec
		owners = append(owners, owner)
	}
	if len(owners) == 0 {
		t.Fatalf("no NSEC records in signed zone")
	}
	start := owners[0]
	var walked []string
	cur := start
	for {
		walked = append(walked, cur)
		nsec, ok := byOwner[cur]
		if !ok {
			t.Fatalf("NSEC chain broken: owner %q has no NSEC record", cur)
		}
		next := strings.ToLower(nsec.NextDomain.String())
		if next == start {
			return walked
		}
		if _, seen := byOwner[next]; !seen {
			t.Fatalf("NSEC chain broken: next %q is not an NSEC owner", next)
		}
		cur = next
		if len(walked) > len(owners) {
			t.Fatalf("NSEC chain does not close the loop")
		}
	}
}

// proofAssertCanonicalAscending fails the test unless every consecutive pair
// in the walked chain is in strict canonical (RFC 4034 §6.1) order, allowing
// the final wrap-around step back to the chain start.
func proofAssertCanonicalAscending(t *testing.T, walked []string) {
	t.Helper()
	if len(walked) < 2 {
		return
	}
	// The walk starts at an arbitrary NSEC (SignZone randomizes group
	// order), so the one wrap-around descent can appear anywhere in the
	// walked sequence. Rotate the cycle to its canonical minimum, then
	// require strict ascent — exactly "the chain is in canonical order".
	minIdx := 0
	for i := 1; i < len(walked); i++ {
		if canonicalNameCompare(walked[i], walked[minIdx]) < 0 {
			minIdx = i
		}
	}
	rotated := append(append([]string(nil), walked[minIdx:]...), walked[:minIdx]...)
	for i := 0; i+1 < len(rotated); i++ {
		if canonicalNameCompare(rotated[i], rotated[i+1]) >= 0 {
			t.Fatalf("NSEC chain not in canonical order: %q >= %q (chain %v, rotated from %q)",
				rotated[i], rotated[i+1], walked, rotated[0])
		}
	}
}

// TestProofNSECCanonicalOrderMixedCase pins RFC 4034 §6.1 canonical ordering
// of the NSEC chain for mixed-case owner names. generateNSEC previously
// ordered the chain with sort.Strings — case-sensitive presentation-format
// order ('B'=0x42 sorts before 'a'=0x61) — so the signed chain was not in
// canonical (lowercased wire) order and validators that walk NSEC chains in
// canonical order (RFC 4035 §5.4) mis-evaluate authentic-denial proofs.
func TestProofNSECCanonicalOrderMixedCase(t *testing.T) {
	signer := NewSigner("example.com.", DefaultSignerConfig())
	if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true); err != nil {
		t.Fatalf("KSK generation: %v", err)
	}
	if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false); err != nil {
		t.Fatalf("ZSK generation: %v", err)
	}

	records := []*protocol.ResourceRecord{
		proofNSECARecord(t, "BBB.example.com."),
		proofNSECARecord(t, "aaa.example.com."),
		proofNSECARecord(t, "b.example.com."),
		proofNSECARecord(t, "aa.example.com."),
	}
	signed, err := signer.SignZone(records)
	if err != nil {
		t.Fatalf("SignZone: %v", err)
	}

	proofAssertCanonicalAscending(t, proofWalkNSECChain(t, signed))
}

// TestProofNSECCanonicalOrderLowercaseControl is the control: an
// all-lowercase zone must produce a canonical chain both before and after
// the fix, proving the harness rather than masking the defect.
func TestProofNSECCanonicalOrderLowercaseControl(t *testing.T) {
	signer := NewSigner("example.com.", DefaultSignerConfig())
	if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, true); err != nil {
		t.Fatalf("KSK generation: %v", err)
	}
	if _, err := signer.GenerateKeyPair(protocol.AlgorithmECDSAP256SHA256, false); err != nil {
		t.Fatalf("ZSK generation: %v", err)
	}

	records := []*protocol.ResourceRecord{
		proofNSECARecord(t, "bbb.example.com."),
		proofNSECARecord(t, "aaa.example.com."),
	}
	signed, err := signer.SignZone(records)
	if err != nil {
		t.Fatalf("SignZone: %v", err)
	}

	proofAssertCanonicalAscending(t, proofWalkNSECChain(t, signed))
}
