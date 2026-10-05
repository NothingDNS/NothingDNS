package protocol

import (
	"encoding/base64"
	"testing"
)

// RFC 4034 Appendix B.1 with verified erratum 193: algorithm 1 uses
// the third- and second-to-last public-key modulus octets, not a checksum.
func TestCalculateKeyTagAlgorithm1(t *testing.T) {
	key, err := base64.StdEncoding.DecodeString("AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==")
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range []uint16{0, 256, 257, 384} {
		if got := CalculateKeyTag(flags, AlgorithmRSAMD5, key); got != 15407 {
			t.Fatalf("flags %d: tag=%d, want 15407", flags, got)
		}
		r := &RDataDNSKEY{Flags: flags, Protocol: 3, Algorithm: AlgorithmRSAMD5, PublicKey: key}
		if got := r.CalculateKeyTag(); got != 15407 {
			t.Fatalf("method tag=%d, want 15407", got)
		}
	}
	if got := CalculateKeyTag(256, AlgorithmRSASHA1, key); got != 60485 {
		t.Fatalf("ordinary checksum tag=%d, want 60485", got)
	}
	if IsAlgorithmSupported(AlgorithmRSAMD5) {
		t.Fatal("metadata tag calculation must not enable algorithm 1")
	}
}
func TestCalculateKeyTagAlgorithm1ShortKey(t *testing.T) {
	for _, key := range [][]byte{nil, {}, {1}, {1, 2}} {
		if got := CalculateKeyTag(256, AlgorithmRSAMD5, key); got != 0 {
			t.Fatalf("short key %x: tag=%d, want 0", key, got)
		}
	}
}
