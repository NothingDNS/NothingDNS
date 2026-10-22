package dns64

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func excludeAAAAFixture(t *testing.T, cidrs ...string) *Synthesizer {
	t.Helper()
	s, err := NewSynthesizer("", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cidrs {
		if err := s.AddExcludeNet(c); err != nil {
			t.Fatalf("AddExcludeNet(%q): %v", c, err)
		}
	}
	return s
}

func aaaaQuestion(t *testing.T) *protocol.Question {
	t.Helper()
	return &protocol.Question{Name: mustName(t, "example.com."), QType: protocol.TypeAAAA, QClass: protocol.ClassIN}
}

func aaaaRecord(t *testing.T, owner, ip string) *protocol.ResourceRecord {
	t.Helper()
	var addr [16]byte
	copy(addr[:], net.ParseIP(ip).To16())
	return &protocol.ResourceRecord{
		Name: mustName(t, owner), Type: protocol.TypeAAAA, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataAAAA{Address: addr},
	}
}

func rrsigRecord(t *testing.T, owner string, covered uint16) *protocol.ResourceRecord {
	t.Helper()
	return &protocol.ResourceRecord{
		Name: mustName(t, owner), Type: protocol.TypeRRSIG, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataRRSIG{TypeCovered: covered, SignerName: mustName(t, "example.com.")},
	}
}

func answerAddrs(m *protocol.Message) []string {
	var out []string
	for _, rr := range m.Answers {
		if a, ok := rr.Data.(*protocol.RDataAAAA); ok {
			out = append(out, net.IP(a.Address[:]).String())
		}
	}
	return out
}

// RFC 6147 §5.1.4: an IPv4-mapped AAAA (::ffff:a.b.c.d) is the example the RFC
// gives of an unusable address. It has a 4-byte form, which IsExcluded
// deliberately skips for IPv6 ranges, so the AAAA check must compare in IPv6
// space.
func TestIsExcludedAAAA(t *testing.T) {
	s := excludeAAAAFixture(t, "::ffff:0:0/96", "2001:db8::/32", "10.0.0.0/8")

	for ip, want := range map[string]bool{
		"::ffff:192.0.2.9": true,  // IPv4-mapped, the RFC's own example
		"::ffff:0.0.0.0":   true,  // range start
		"2001:db8::1":      true,  // ordinary IPv6 range
		"2001:db8:ffff::1": true,  // range end side
		"2001:db9::1":      false, // just outside the /32
		"2606:4700::1":     false, // unrelated global address
		"::192.0.2.9":      false, // IPv4-compatible is not IPv4-mapped
		"::ffff:ffff:0:0":  false, // neighbouring /96
	} {
		var addr [16]byte
		copy(addr[:], net.ParseIP(ip).To16())
		if got := s.IsExcludedAAAA(addr); got != want {
			t.Errorf("IsExcludedAAAA(%s) = %v, want %v", ip, got, want)
		}
	}

	// An IPv4-form range describes A records; it must not swallow AAAA data
	// whose last 32 bits happen to fall in it.
	var mapped [16]byte
	copy(mapped[:], net.ParseIP("::ffff:10.1.2.3").To16())
	onlyV4 := excludeAAAAFixture(t, "10.0.0.0/8")
	if onlyV4.IsExcludedAAAA(mapped) {
		t.Error("an IPv4-form exclusion range must not apply to AAAA records")
	}

	var nilSynth *Synthesizer
	if nilSynth.IsExcludedAAAA(mapped) {
		t.Error("nil synthesizer must exclude nothing")
	}
}

func TestFilterExcludedAAAA(t *testing.T) {
	s := excludeAAAAFixture(t, "::ffff:0:0/96", "2001:db8::/32")

	t.Run("control: nothing excluded leaves the answer untouched", func(t *testing.T) {
		resp := &protocol.Message{Answers: []*protocol.ResourceRecord{aaaaRecord(t, "example.com.", "2606:4700::1")}}
		if s.FilterExcludedAAAA(aaaaQuestion(t), resp) {
			t.Fatal("reported a change when nothing was excluded")
		}
		if got := answerAddrs(resp); len(got) != 1 {
			t.Fatalf("answers = %v, want the one usable AAAA", got)
		}
	})

	t.Run("only excluded records leave an empty answer", func(t *testing.T) {
		resp := &protocol.Message{Answers: []*protocol.ResourceRecord{
			aaaaRecord(t, "example.com.", "::ffff:192.0.2.9"),
			aaaaRecord(t, "example.com.", "2001:db8::1"),
		}}
		resp.Header.ANCount = 2
		if !s.FilterExcludedAAAA(aaaaQuestion(t), resp) {
			t.Fatal("expected the excluded records to be removed")
		}
		if len(resp.Answers) != 0 || resp.Header.ANCount != 0 {
			t.Fatalf("answers=%d ANCount=%d, want an empty answer", len(resp.Answers), resp.Header.ANCount)
		}
	})

	t.Run("mixed answer keeps the usable record and the CNAME chain", func(t *testing.T) {
		cname := &protocol.ResourceRecord{
			Name: mustName(t, "www.example.com."), Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 300,
			Data: &protocol.RDataCNAME{CName: mustName(t, "example.com.")},
		}
		resp := &protocol.Message{Answers: []*protocol.ResourceRecord{
			cname,
			aaaaRecord(t, "example.com.", "2001:db8::1"),
			aaaaRecord(t, "example.com.", "2606:4700::1"),
		}}
		resp.Header.ANCount = 3
		s.FilterExcludedAAAA(aaaaQuestion(t), resp)
		if got := answerAddrs(resp); len(got) != 1 || got[0] != "2606:4700::1" {
			t.Fatalf("AAAA answers = %v, want only 2606:4700::1", got)
		}
		if len(resp.Answers) != 2 || resp.Answers[0].Type != protocol.TypeCNAME || resp.Header.ANCount != 2 {
			t.Fatalf("CNAME chain lost or ANCount stale: %d answers, ANCount=%d", len(resp.Answers), resp.Header.ANCount)
		}
	})

	t.Run("RRSIG over a shrunken AAAA RRset is dropped, other signatures stay", func(t *testing.T) {
		resp := &protocol.Message{Answers: []*protocol.ResourceRecord{
			aaaaRecord(t, "example.com.", "2001:db8::1"),
			aaaaRecord(t, "example.com.", "2606:4700::1"),
			rrsigRecord(t, "example.com.", protocol.TypeAAAA),
			rrsigRecord(t, "example.com.", protocol.TypeA),
			aaaaRecord(t, "other.example.com.", "2606:4700::2"),
			rrsigRecord(t, "other.example.com.", protocol.TypeAAAA),
		}}
		s.FilterExcludedAAAA(aaaaQuestion(t), resp)
		var aaaaSigs, otherSigs int
		for _, rr := range resp.Answers {
			if sig, ok := rr.Data.(*protocol.RDataRRSIG); ok {
				switch {
				case sig.TypeCovered == protocol.TypeAAAA && rr.Name.String() == "example.com.":
					aaaaSigs++
				default:
					otherSigs++
				}
			}
		}
		if aaaaSigs != 0 {
			t.Errorf("stale RRSIG over the shrunken example.com. AAAA RRset kept (%d)", aaaaSigs)
		}
		if otherSigs != 2 {
			t.Errorf("unrelated signatures removed: %d kept, want 2 (A-covering and other owner's AAAA)", otherSigs)
		}
	})

	t.Run("only AAAA queries with NOERROR are filtered", func(t *testing.T) {
		mk := func() *protocol.Message {
			return &protocol.Message{Answers: []*protocol.ResourceRecord{aaaaRecord(t, "example.com.", "2001:db8::1")}}
		}
		aQ := &protocol.Question{Name: mustName(t, "example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}
		if resp := mk(); s.FilterExcludedAAAA(aQ, resp) || len(resp.Answers) != 1 {
			t.Error("a non-AAAA query must be left alone")
		}
		nx := mk()
		nx.Header.Flags.RCODE = protocol.RcodeNameError
		if s.FilterExcludedAAAA(aaaaQuestion(t), nx) || len(nx.Answers) != 1 {
			t.Error("a non-NOERROR response must be left alone")
		}
		s2 := excludeAAAAFixture(t, "2001:db8::/32")
		s2.SetEnabled(false)
		if resp := mk(); s2.FilterExcludedAAAA(aaaaQuestion(t), resp) || len(resp.Answers) != 1 {
			t.Error("a disabled synthesizer must not touch the answer")
		}
	})

	t.Run("nil and empty inputs are safe", func(t *testing.T) {
		var nilSynth *Synthesizer
		if nilSynth.FilterExcludedAAAA(aaaaQuestion(t), &protocol.Message{}) {
			t.Error("nil synthesizer reported a change")
		}
		if s.FilterExcludedAAAA(nil, &protocol.Message{}) || s.FilterExcludedAAAA(aaaaQuestion(t), nil) {
			t.Error("nil question/response reported a change")
		}
		if s.FilterExcludedAAAA(aaaaQuestion(t), &protocol.Message{}) {
			t.Error("empty answer reported a change")
		}
	})
}
