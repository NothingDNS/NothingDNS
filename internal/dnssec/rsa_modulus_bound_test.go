package dnssec

import (
	"crypto/rsa"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// rsaWireKey builds RFC 3110 DNSKEY key data with a 1-byte exponent length
// and a modBytes-long odd modulus whose top bit is set.
func rsaWireKey(modBytes int) []byte {
	out := []byte{3, 0x01, 0x00, 0x01}
	mod := make([]byte, modBytes)
	for i := range mod {
		mod[i] = byte(0xA5 ^ i)
	}
	mod[0] |= 0x80
	mod[len(mod)-1] |= 1
	return append(out, mod...)
}

// TestParseRSAPublicKeyRejectsOversizedModulus is the F227 regression: RFC 5702
// §2 caps RSASHA256/RSASHA512 moduli at 4096 bits. Without the cap an
// attacker-controlled DNSKEY with a ~500,000-bit modulus made each RRSIG
// verification on the validator cost seconds of CPU.
func TestParseRSAPublicKeyRejectsOversizedModulus(t *testing.T) {
	for _, alg := range []uint8{protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512} {
		// Boundary: exactly 4096 bits is accepted.
		pk, err := ParseDNSKEYPublicKey(alg, rsaWireKey(512))
		if err != nil {
			t.Fatalf("alg %d: 4096-bit modulus rejected: %v", alg, err)
		}
		if got := pk.Key.(*rsa.PublicKey).N.BitLen(); got != 4096 {
			t.Fatalf("alg %d: modulus bits = %d, want 4096", alg, got)
		}
		// A leading zero octet does not change the modulus size.
		withZero := append([]byte{3, 0x01, 0x00, 0x01, 0x00}, rsaWireKey(512)[4:]...)
		if _, err := ParseDNSKEYPublicKey(alg, withZero); err != nil {
			t.Fatalf("alg %d: 4096-bit modulus with leading zero rejected: %v", alg, err)
		}
		for _, modBytes := range []int{513, 8192, 62000} {
			if _, err := ParseDNSKEYPublicKey(alg, rsaWireKey(modBytes)); err == nil {
				t.Fatalf("alg %d: %d-bit modulus accepted, want error", alg, modBytes*8)
			}
		}
	}
}
