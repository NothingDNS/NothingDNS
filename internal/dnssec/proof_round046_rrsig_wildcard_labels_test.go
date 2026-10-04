// CONTRACT. RFC 4034 §3.1.3 (Labels field): the value is the number of labels
// in the original RRSIG RR owner name and MUST NOT count the leftmost label
// when it is a wildcard. A signature over `*.example.com.` therefore carries
// Labels=2, not 3. Validators depend on it: RFC 4035 §5.3.2 reconstructs the
// original owner of a wildcard-expanded answer as "*." plus the rightmost
// Labels labels of the queried name, and this repo already encodes that
// expectation — internal/dnssec/wildcard_depth_test.go:12 calls a genuine
// `*.example.com` signature "(Labels=2)" and :17 names "the wildcard's 2-label
// closest encloser example.com", while its fixture passes labels=2 by hand.
//
// DEFECT. Signer.SignRRSet (internal/dnssec/signer.go:436-440) sets
//
//	labelCount := len(splitLabels(ownerName))
//	labels := uint8(labelCount)
//
// with no wildcard adjustment, and nothing else in the signer mentions "*"
// (the only non-test occurrence in package dnssec is the validator's
// reconstruction at validator.go:1063). So a wildcard RRset is signed with
// Labels=3, and every wildcard-expanded answer from this signer fails
// validation: the reconstructed owner becomes "*.foo.example.com." instead of
// the "*.example.com." that was actually signed, so the signature does not
// verify and the zone's wildcard records are Bogus.
//
// The tests below pin the field value and the reconstruction it drives, plus
// controls that the non-wildcard cases must not move.
package dnssec

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// rr046Signer builds a real signer over example.com. with one generated ZSK.
func rr046Signer(t *testing.T) (*Signer, *SigningKey) {
	t.Helper()
	s := NewSigner("example.com.", DefaultSignerConfig())
	key, err := s.GenerateKeyPair(protocol.AlgorithmED25519, false)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	return s, key
}

// rr046RRSet builds a one-record A RRset owned by owner.
func rr046RRSet(t *testing.T, owner string) []*protocol.ResourceRecord {
	t.Helper()
	name, err := protocol.ParseName(owner)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", owner, err)
	}
	return []*protocol.ResourceRecord{{
		Name:  name,
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}}
}

// TestRound046WildcardRRSIGLabelsExcludesWildcard is the defect case: the RRSIG
// over a wildcard owner must not count the wildcard label.
func TestRound046WildcardRRSIGLabelsExcludesWildcard(t *testing.T) {
	s, key := rr046Signer(t)

	rrsig, err := s.SignRRSet(rr046RRSet(t, "*.example.com."), key, 1000, 2000)
	if err != nil {
		t.Fatalf("SignRRSet(*.example.com.): %v", err)
	}
	data, ok := rrsig.Data.(*protocol.RDataRRSIG)
	if !ok {
		t.Fatalf("RRSIG record data is %T, want *protocol.RDataRRSIG", rrsig.Data)
	}

	if data.Labels != 2 {
		t.Errorf("wildcard RRSIG Labels = %d, want 2: RFC 4034 §3.1.3 does not count "+
			"the leftmost label when it is a wildcard, and this repo's own validator "+
			"expects the 2-label form (wildcard_depth_test.go:12,17). The signer counted "+
			"all %d labels of %q.", data.Labels, len(splitLabels("*.example.com.")),
			rrsig.Name.String())
	}

	// The impact, stated the way a validator applies it (RFC 4035 §5.3.2): the
	// original owner of a wildcard-expanded answer is "*." + the rightmost
	// Labels labels of the queried name.
	const qname = "foo.example.com." // answered by *.example.com.
	qlabels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	wantOwner := "*." + strings.Join(qlabels[len(qlabels)-2:], ".") + "."
	reconstructed := "*." + strings.Join(qlabels[len(qlabels)-int(data.Labels):], ".") + "."
	if reconstructed != wantOwner {
		t.Errorf("a validator reconstructs the signed owner as %q, but the signature "+
			"covers %q: with Labels=%d every wildcard-expanded answer from this signer "+
			"is Bogus (the reconstructed name is not the name that was signed)",
			reconstructed, rrsig.Name.String(), data.Labels)
	}
}

// TestRound046RRSIGLabelsControls pins the non-wildcard neighbours the fix must
// not move. The wildcard boundary cases live in
// TestRound046WildcardLabelBoundaries: they legitimately change with the fix,
// so they cannot serve as controls.
func TestRound046RRSIGLabelsControls(t *testing.T) {
	s, key := rr046Signer(t)

	cases := []struct {
		owner string
		want  uint8
		why   string
	}{
		{"www.example.com.", 3, "an ordinary name counts every label (RFC 4034 §3.1.3)"},
		{"example.com.", 2, "the apex counts its own labels"},
	}
	for _, tc := range cases {
		t.Run(tc.owner, func(t *testing.T) {
			rrsig, err := s.SignRRSet(rr046RRSet(t, tc.owner), key, 1000, 2000)
			if err != nil {
				t.Fatalf("SignRRSet(%q): %v", tc.owner, err)
			}
			data, ok := rrsig.Data.(*protocol.RDataRRSIG)
			if !ok {
				t.Fatalf("RRSIG record data is %T, want *protocol.RDataRRSIG", rrsig.Data)
			}
			if data.Labels != tc.want {
				t.Errorf("Labels for %q = %d, want %d (%s)", tc.owner, data.Labels, tc.want, tc.why)
			}
			if rrsig.Name.String() != tc.owner {
				t.Errorf("RRSIG owner = %q, want %q", rrsig.Name.String(), tc.owner)
			}
		})
	}
}

// TestRound046WildcardLabelBoundaries pins the other wildcard shapes: only the
// leftmost wildcard label is excluded (RFC 4034 §3.1.3), and a root wildcard
// has no non-wildcard labels left.
func TestRound046WildcardLabelBoundaries(t *testing.T) {
	s, key := rr046Signer(t)

	cases := []struct {
		owner string
		want  uint8
		why   string
	}{
		{"*.sub.example.com.", 3, "only the wildcard label is excluded, not the rest"},
		{"*.", 0, "a root wildcard has no non-wildcard labels left"},
	}
	for _, tc := range cases {
		t.Run(tc.owner, func(t *testing.T) {
			rrsig, err := s.SignRRSet(rr046RRSet(t, tc.owner), key, 1000, 2000)
			if err != nil {
				t.Fatalf("SignRRSet(%q): %v", tc.owner, err)
			}
			data, ok := rrsig.Data.(*protocol.RDataRRSIG)
			if !ok {
				t.Fatalf("RRSIG record data is %T, want *protocol.RDataRRSIG", rrsig.Data)
			}
			if data.Labels != tc.want {
				t.Errorf("Labels for %q = %d, want %d (%s)", tc.owner, data.Labels, tc.want, tc.why)
			}
		})
	}
}
