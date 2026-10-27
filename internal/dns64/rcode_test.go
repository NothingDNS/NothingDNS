package dns64

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// RFC 6147 §5.1.2: an AAAA answer with any RCODE but NXDOMAIN counts as an
// empty NOERROR answer, so synthesis is attempted (F740).
func TestShouldSynthesizeTreatsErrorRcodesAsEmpty(t *testing.T) {
	s, err := NewSynthesizer("", 0)
	if err != nil {
		t.Fatal(err)
	}
	q := &protocol.Question{Name: mustParseName(t, "v4only.example."), QType: protocol.TypeAAAA, QClass: protocol.ClassIN}
	for rcode, want := range map[uint8]bool{
		protocol.RcodeSuccess:        true,
		protocol.RcodeServerFailure:  true,
		protocol.RcodeRefused:        true,
		protocol.RcodeNotImplemented: true,
		protocol.RcodeNameError:      false,
	} {
		resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(rcode)}}
		if got := s.ShouldSynthesize(q, resp); got != want {
			t.Errorf("rcode %d: ShouldSynthesize = %v, want %v", rcode, got, want)
		}
	}
}

func mustParseName(t *testing.T, s string) *protocol.Name {
	t.Helper()
	n, err := protocol.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
