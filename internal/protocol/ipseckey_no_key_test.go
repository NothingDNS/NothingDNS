package protocol

import "testing"

// RFC 4025 §2.4: with algorithm 0 no public key is present. Such a record
// unpacked from the wire prints as `10 0 0 .` (no key text), and that text must
// parse back, or a record that came in over AXFR or the KV/Raft text path can
// never be served again.
func TestParseIPSECKEYWithoutPublicKey(t *testing.T) {
	for _, text := range []string{"10 0 0 .", "10 1 0 192.0.2.1", "10 2 0 2001:db8::1", "10 3 0 gw.example.com."} {
		rd := ParseRDataText("IPSECKEY", text)
		if rd == nil {
			t.Errorf("FAIL: keyless IPSECKEY %q rejected", text)
			continue
		}
		// The text form round-trips and packs.
		again := ParseRDataText("IPSECKEY", rd.String())
		if again == nil || again.String() != rd.String() {
			t.Errorf("%q: String() %q does not parse back", text, rd.String())
		}
		buf := make([]byte, 512)
		if _, err := rd.Pack(buf, 0); err != nil {
			t.Errorf("%q: pack: %v", text, err)
		}
	}

	// Control: a key is still required when an algorithm is named.
	if rd := ParseRDataText("IPSECKEY", "10 1 2 192.0.2.1"); rd != nil {
		t.Errorf("algorithm 2 without a key accepted: %s", rd)
	}
	if rd := ParseRDataText("IPSECKEY", "10 1 2 192.0.2.1 AQID"); rd == nil {
		t.Error("control: record with a key rejected")
	}
}
