package dns64

import (
	"net"
	"testing"
)

func TestExtractIPv4RejectsRFC6052ReservedBits_F825(t *testing.T) {
	v4 := net.ParseIP("192.0.2.1").To4()
	for _, prefixLen := range []int{32, 40, 48, 56, 64} {
		s, err := NewSynthesizer("2001:db8::", prefixLen)
		if err != nil {
			t.Fatalf("/%d: %v", prefixLen, err)
		}
		valid := s.SynthesizeAAAA(v4)
		if got := s.ExtractIPv4(valid); got == nil || !got.Equal(v4) {
			t.Fatalf("/%d valid round-trip = %v, want %v", prefixLen, got, v4)
		}

		badU := append(net.IP(nil), valid...)
		badU[8] = 1
		if got := s.ExtractIPv4(badU); got != nil {
			t.Errorf("/%d non-zero u octet extracted %v", prefixLen, got)
		}

		suffixStart := 9 + (prefixLen-32)/8
		badSuffix := append(net.IP(nil), valid...)
		badSuffix[suffixStart] = 1
		if got := s.ExtractIPv4(badSuffix); got != nil {
			t.Errorf("/%d non-zero suffix extracted %v", prefixLen, got)
		}
	}
}
