package zone

// Round-12 proof: RFC 4034 §6.2 canonical RR form requires an RRSIG's TTL
// field to carry the *Signer's TTL* (the "original TTL" carried inside the
// RRSIG RDATA), not the RRSIG RR's own TTL header. This is exactly why an
// operator may LOWER an RRSIG's RR TTL during key rollover without
// invalidating the signature.
//
// collectZoneRRsets() unconditionally uses rec.TTL for every RRset,
// including type RRSIG, so an RRSIG whose RR TTL differs from its Signer's
// TTL is digested with the wrong TTL and the ZONEMD no longer matches an
// RFC-compliant peer (BIND/Knot).
//
// The proof does not assert a hardcoded digest: it independently rebuilds
// the expected digest from the wire RDATA, substituting the Signer's TTL
// for the RRSIG RR's TTL, and compares.

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

const wantSignerTTL = 3600

// rrsigRDATA builds wire RRSIG RDATA whose 4th field ("original TTL" /
// Signer's TTL) is wantSignerTTL, per the parseRRSIGRData field order:
// type-covered algorithm labels original-ttl expiration inception key-tag
// signer signature.
func rrsigRDATA(t *testing.T) []byte {
	t.Helper()
	rd := protocol.ParseRDataText("RRSIG", "A 8 3 3600 20260101000000 20250101000000 12345 example.com. AAAA")
	if rd == nil {
		t.Fatalf("FAIL: harness setup: could not build RRSIG RDATA fixture")
	}
	buf := make([]byte, rd.Len())
	if _, err := rd.Pack(buf, 0); err != nil {
		t.Fatalf("FAIL: harness setup: packing RRSIG RDATA: %v", err)
	}
	// Confirm the fixture really does carry the Signer's TTL at offset 4.
	if got := binary.BigEndian.Uint32(buf[4:8]); got != wantSignerTTL {
		t.Fatalf("FAIL: harness setup: RRSIG RDATA original-TTL = %d, want %d", got, wantSignerTTL)
	}
	return buf
}

// expectedRRSetBytes rebuilds the canonical RR bytes for a single (name,
// type, rdata) triple, independently of buildCanonicalRRset. When the type
// is RRSIG, the RFC 4034 §6.2 Signer's TTL is substituted for the RR TTL.
func expectedRRSetBytes(t *testing.T, name string, rtype uint16, rrTTL uint32, rdata []byte, signerTTL uint32) []byte {
	t.Helper()
	ttl := rrTTL
	if rtype == protocol.TypeRRSIG {
		ttl = signerTTL
	}
	var out []byte
	out = append(out, protocol.CanonicalWireName(name)...)
	out = append(out, byte(rtype>>8), byte(rtype&0xff))
	out = append(out, 0, 1) // class IN
	out = append(out, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl&0xff))
	out = append(out, byte(len(rdata)>>8), byte(len(rdata)&0xff))
	out = append(out, rdata...)
	return out
}

// digestOf hashes the given RR byte blocks in sorted order.
func digestOf(rrs [][]byte) []byte {
	sorted := make([][]byte, len(rrs))
	copy(sorted, rrs)
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })
	h := sha256.New()
	for _, rr := range sorted {
		h.Write(rr)
	}
	return h.Sum(nil)
}

func TestProofRound012ZoneMDRRSIGUsesSignerTTLInCanonicalForm(t *testing.T) {
	// The RRSIG RR's OWN TTL is deliberately LOWER than the Signer's TTL,
	// which is the normal, valid key-rollover configuration.
	const rrOwnTTL = 300

	z := NewZone("example.com.")
	// One ordinary A record so the zone is non-degenerate.
	z.Records["www.example.com."] = []Record{{
		Name:  "www.example.com.",
		Type:  "A",
		Class: "IN",
		TTL:   300,
		RData: "192.0.2.1",
	}}
	// The RRSIG: RR TTL 300, Signer's TTL 3600.
	z.Records["www.example.com."] = append(z.Records["www.example.com."], Record{
		Name:  "www.example.com.",
		Type:  "RRSIG",
		Class: "IN",
		TTL:   rrOwnTTL,
		RData: "A 8 3 3600 20260101000000 20250101000000 12345 example.com. AAAA",
	})

	// CONTROL: a zone with no RRSIG at all. Its digest must already match
	// the independent reference builder; this proves the harness and the
	// reference construction agree independent of the RRSIG rule.
	control := NewZone("example.com.")
	control.Records["www.example.com."] = []Record{{
		Name:  "www.example.com.",
		Type:  "A",
		Class: "IN",
		TTL:   300,
		RData: "192.0.2.1",
	}}
	gotControl, err := ComputeZoneMD(control, ZONEMDSHA256)
	if err != nil {
		t.Fatalf("FAIL: harness setup: control ComputeZoneMD: %v", err)
	}
	aRDATA, err := expectedA("192.0.2.1")
	if err != nil {
		t.Fatalf("FAIL: harness setup: %v", err)
	}
	wantControl := digestOf([][]byte{
		expectedRRSetBytes(t, "www.example.com.", protocol.TypeA, 300, aRDATA, 0),
	})
	if !equalDigest(gotControl.Hash, wantControl) {
		t.Fatalf("FAIL: harness setup: control zone (no RRSIG) digest mismatch; "+
			"the reference builder does not agree with production on the unaffected path")
	}

	// SUBJECT: compute the production digest for the signed zone.
	got, err := ComputeZoneMD(z, ZONEMDSHA256)
	if err != nil {
		t.Fatalf("FAIL: production ComputeZoneMD returned an error: %v", err)
	}

	want := digestOf([][]byte{
		expectedRRSetBytes(t, "www.example.com.", protocol.TypeA, 300, aRDATA, 0),
		// RRSIG: RFC 4034 §6.2 => TTL field must be the Signer's TTL (3600).
		expectedRRSetBytes(t, "www.example.com.", protocol.TypeRRSIG, rrOwnTTL, rrsigRDATA(t), wantSignerTTL),
	})

	if equalDigest(got.Hash, want) {
		t.Logf("PASS: ZONEMD digest uses the Signer's TTL for the RRSIG canonical form")
		return
	}

	// Show the specific wrongness: digest built with the RR's own TTL.
	wrong := digestOf([][]byte{
		expectedRRSetBytes(t, "www.example.com.", protocol.TypeA, 300, aRDATA, 0),
		expectedRRSetBytes(t, "www.example.com.", protocol.TypeRRSIG, rrOwnTTL, rrsigRDATA(t), rrOwnTTL),
	})
	t.Fatalf("FAIL: RFC 4034 §6.2 violation in collectZoneRRsets: RRSIG canonical form must use the "+
		"Signer's TTL (%d), not the RRSIG RR's own TTL (%d).\n"+
		"  production digest       = %x\n"+
		"  RFC-correct digest     = %x\n"+
		"  digest w/ RR TTL (%3d) = %x  <-- matches production: TTL came from the RR header\n",
		wantSignerTTL, rrOwnTTL, got.Hash, want, rrOwnTTL, wrong)
}

func expectedA(ip string) ([]byte, error) {
	rd := protocol.ParseRDataText("A", ip)
	if rd == nil {
		return nil, errBadA
	}
	buf := make([]byte, rd.Len())
	if _, err := rd.Pack(buf, 0); err != nil {
		return nil, err
	}
	return buf, nil
}

var errBadA = &aFixtureError{}

type aFixtureError struct{}

func (e *aFixtureError) Error() string { return "could not build A RDATA fixture" }

func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
