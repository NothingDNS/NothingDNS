package dns64

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ---------------------------------------------------------------------------
// TestNewSynthesizer
// ---------------------------------------------------------------------------

func TestNewSynthesizer(t *testing.T) {
	// Valid default prefix.
	s, err := NewSynthesizer("", 0)
	if err != nil {
		t.Fatalf("default prefix: unexpected error: %v", err)
	}
	if s.prefixLen != 96 {
		t.Fatalf("default prefix length: got %d, want 96", s.prefixLen)
	}
	if !s.prefix.Equal(net.ParseIP("64:ff9b::")) {
		t.Fatalf("default prefix: got %v, want 64:ff9b::", s.prefix)
	}

	// Explicit valid prefix.
	s, err = NewSynthesizer("2001:db8::", 64)
	if err != nil {
		t.Fatalf("explicit prefix: unexpected error: %v", err)
	}
	if s.prefixLen != 64 {
		t.Fatalf("explicit prefix length: got %d, want 64", s.prefixLen)
	}

	// Invalid prefix string.
	_, err = NewSynthesizer("not-an-ip", 96)
	if err == nil {
		t.Fatal("expected error for invalid prefix, got nil")
	}

	// Invalid prefix length.
	_, err = NewSynthesizer("64:ff9b::", 72)
	if err == nil {
		t.Fatal("expected error for invalid prefix length 72, got nil")
	}

	// All valid prefix lengths.
	for _, pl := range []int{32, 40, 48, 56, 64, 96} {
		_, err := NewSynthesizer("64:ff9b::", pl)
		if err != nil {
			t.Fatalf("prefix length %d: unexpected error: %v", pl, err)
		}
	}
}

// ---------------------------------------------------------------------------
// TestSynthesizeAAAA_Prefix96
// ---------------------------------------------------------------------------

func TestSynthesizeAAAA_Prefix96(t *testing.T) {
	s, err := NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatal(err)
	}

	ipv4 := net.ParseIP("192.0.2.1").To4()
	got := s.SynthesizeAAAA(ipv4)
	want := net.ParseIP("64:ff9b::c000:201")
	if !got.Equal(want) {
		t.Fatalf("SynthesizeAAAA(/96): got %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// TestSynthesizeAAAA_Prefix64
// ---------------------------------------------------------------------------

func TestSynthesizeAAAA_Prefix64(t *testing.T) {
	s, err := NewSynthesizer("2001:db8::", 64)
	if err != nil {
		t.Fatal(err)
	}

	ipv4 := net.ParseIP("192.0.2.33").To4()
	got := s.SynthesizeAAAA(ipv4)

	// /64: bytes 0-7 prefix, byte 8=0, bytes 9-12=IPv4, bytes 13-15=0
	expected := make(net.IP, 16)
	copy(expected, net.ParseIP("2001:db8::").To16())
	expected[8] = 0
	expected[9] = 192
	expected[10] = 0
	expected[11] = 2
	expected[12] = 33
	expected[13] = 0
	expected[14] = 0
	expected[15] = 0

	if !got.Equal(expected) {
		t.Fatalf("SynthesizeAAAA(/64): got %v, want %v", got, expected)
	}
}

// ---------------------------------------------------------------------------
// TestSynthesizeAAAA_Prefix48
// ---------------------------------------------------------------------------

func TestSynthesizeAAAA_Prefix48(t *testing.T) {
	s, err := NewSynthesizer("2001:db8::", 48)
	if err != nil {
		t.Fatal(err)
	}

	ipv4 := net.ParseIP("192.0.2.33").To4()
	got := s.SynthesizeAAAA(ipv4)

	// /48: bytes 0-5 prefix, bytes 6-7 = IPv4[0:2], byte 8=0,
	//      bytes 9-10 = IPv4[2:4], bytes 11-15=0
	expected := make(net.IP, 16)
	copy(expected, net.ParseIP("2001:db8::").To16())
	expected[6] = 192
	expected[7] = 0
	expected[8] = 0
	expected[9] = 2
	expected[10] = 33
	expected[11] = 0
	expected[12] = 0
	expected[13] = 0
	expected[14] = 0
	expected[15] = 0

	if !got.Equal(expected) {
		t.Fatalf("SynthesizeAAAA(/48): got %v, want %v", got, expected)
	}
}

// ---------------------------------------------------------------------------
// TestExtractIPv4
// ---------------------------------------------------------------------------

func TestExtractIPv4(t *testing.T) {
	prefixes := []int{32, 40, 48, 56, 64, 96}

	for _, pl := range prefixes {
		s, err := NewSynthesizer("64:ff9b::", pl)
		if err != nil {
			t.Fatal(err)
		}

		original := net.ParseIP("198.51.100.7").To4()
		synthesized := s.SynthesizeAAAA(original)
		if synthesized == nil {
			t.Fatalf("/%d: SynthesizeAAAA returned nil", pl)
		}

		extracted := s.ExtractIPv4(synthesized)
		if extracted == nil {
			t.Fatalf("/%d: ExtractIPv4 returned nil", pl)
		}
		if !extracted.Equal(original) {
			t.Fatalf("/%d: round-trip failed: got %v, want %v", pl, extracted, original)
		}
	}

	// Non-matching prefix returns nil.
	s, err := NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatal(err)
	}
	nonMatch := net.ParseIP("2001:db8::1")
	if v4 := s.ExtractIPv4(nonMatch); v4 != nil {
		t.Fatalf("expected nil for non-matching prefix, got %v", v4)
	}
}

// ---------------------------------------------------------------------------
// TestShouldSynthesize
// ---------------------------------------------------------------------------

func TestShouldSynthesize(t *testing.T) {
	s, err := NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatal(err)
	}

	aaaaQuestion := &protocol.Question{
		Name:   protocol.NewName([]string{"example", "com"}, true),
		QType:  protocol.TypeAAAA,
		QClass: protocol.ClassIN,
	}
	aQuestion := &protocol.Question{
		Name:   protocol.NewName([]string{"example", "com"}, true),
		QType:  protocol.TypeA,
		QClass: protocol.ClassIN,
	}

	// AAAA query with no AAAA answers -> true
	emptyResp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
	}
	if !s.ShouldSynthesize(aaaaQuestion, emptyResp) {
		t.Fatal("expected ShouldSynthesize=true for AAAA query with no AAAA answers")
	}

	// AAAA query with existing AAAA answers -> false
	aaaaResp := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  protocol.NewName([]string{"example", "com"}, true),
				Type:  protocol.TypeAAAA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataAAAA{},
			},
		},
	}
	if s.ShouldSynthesize(aaaaQuestion, aaaaResp) {
		t.Fatal("expected ShouldSynthesize=false when AAAA answers exist")
	}

	// A query -> false
	if s.ShouldSynthesize(aQuestion, emptyResp) {
		t.Fatal("expected ShouldSynthesize=false for A query")
	}

	// Disabled -> false
	s.SetEnabled(false)
	if s.ShouldSynthesize(aaaaQuestion, emptyResp) {
		t.Fatal("expected ShouldSynthesize=false when disabled")
	}
}

// ---------------------------------------------------------------------------
// TestSynthesizeResponse
// ---------------------------------------------------------------------------

func TestSynthesizeResponse(t *testing.T) {
	s, err := NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatal(err)
	}

	question := &protocol.Question{
		Name:   protocol.NewName([]string{"example", "com"}, true),
		QType:  protocol.TypeAAAA,
		QClass: protocol.ClassIN,
	}

	// Build an A response with multiple answers.
	aResp := &protocol.Message{
		Header: protocol.Header{
			ID:    0x1234,
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess, RA: true, RD: true},
		},
		Questions:   make([]*protocol.Question, 0),
		Answers:     make([]*protocol.ResourceRecord, 0),
		Authorities: make([]*protocol.ResourceRecord, 0),
		Additionals: make([]*protocol.ResourceRecord, 0),
	}

	ips := []net.IP{
		net.ParseIP("192.0.2.1").To4(),
		net.ParseIP("198.51.100.2").To4(),
		net.ParseIP("203.0.113.3").To4(),
	}
	ttls := []uint32{300, 600, 120}

	for i, ip := range ips {
		var addr [4]byte
		copy(addr[:], ip)
		rr := &protocol.ResourceRecord{
			Name:  protocol.NewName([]string{"example", "com"}, true),
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   ttls[i],
			Data:  &protocol.RDataA{Address: addr},
		}
		aResp.Answers = append(aResp.Answers, rr)
	}
	aResp.Header.ANCount = uint16(len(aResp.Answers))

	synResp := s.SynthesizeResponse(question, aResp)
	if synResp == nil {
		t.Fatal("SynthesizeResponse returned nil")
	}

	// Check header ID preserved.
	if synResp.Header.ID != 0x1234 {
		t.Fatalf("header ID: got 0x%04x, want 0x1234", synResp.Header.ID)
	}

	// Check question section.
	if len(synResp.Questions) != 1 {
		t.Fatalf("question count: got %d, want 1", len(synResp.Questions))
	}
	if synResp.Questions[0].QType != protocol.TypeAAAA {
		t.Fatalf("question type: got %d, want %d", synResp.Questions[0].QType, protocol.TypeAAAA)
	}

	// Check answer count matches.
	if len(synResp.Answers) != len(ips) {
		t.Fatalf("answer count: got %d, want %d", len(synResp.Answers), len(ips))
	}

	// Verify each synthesized answer.
	for i, rr := range synResp.Answers {
		if rr.Type != protocol.TypeAAAA {
			t.Fatalf("answer[%d] type: got %d, want %d", i, rr.Type, protocol.TypeAAAA)
		}
		if rr.TTL != ttls[i] {
			t.Fatalf("answer[%d] TTL: got %d, want %d", i, rr.TTL, ttls[i])
		}

		aaaaData, ok := rr.Data.(*protocol.RDataAAAA)
		if !ok {
			t.Fatalf("answer[%d] data: expected *RDataAAAA", i)
		}
		synthesizedIP := net.IP(aaaaData.Address[:])

		// Verify round-trip extraction.
		extracted := s.ExtractIPv4(synthesizedIP)
		if !extracted.Equal(ips[i]) {
			t.Fatalf("answer[%d] round-trip: extracted %v, want %v", i, extracted, ips[i])
		}
	}
}

// ---------------------------------------------------------------------------
// TestExcludeNets
// ---------------------------------------------------------------------------

func TestExcludeNets(t *testing.T) {
	s, err := NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.AddExcludeNet("2001:db8::/32"); err != nil {
		t.Fatalf("AddExcludeNet: %v", err)
	}

	// IP inside excluded network.
	excluded := net.ParseIP("2001:db8::1")
	if !s.IsExcluded(excluded) {
		t.Fatal("expected 2001:db8::1 to be excluded")
	}

	// IP outside excluded network.
	notExcluded := net.ParseIP("2001:470::1")
	if s.IsExcluded(notExcluded) {
		t.Fatal("expected 2001:470::1 to NOT be excluded")
	}

	// Invalid CIDR returns error.
	if err := s.AddExcludeNet("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR, got nil")
	}
}

// ---------------------------------------------------------------------------
// TestSynthesizeAAAA_AllPrefixLengths
// ---------------------------------------------------------------------------

func TestSynthesizeAAAA_AllPrefixLengths(t *testing.T) {
	ipv4 := net.ParseIP("203.0.113.42").To4()

	for _, pl := range []int{32, 40, 48, 56, 64, 96} {
		s, err := NewSynthesizer("64:ff9b::", pl)
		if err != nil {
			t.Fatalf("/%d: NewSynthesizer: %v", pl, err)
		}

		synthesized := s.SynthesizeAAAA(ipv4)
		if synthesized == nil {
			t.Fatalf("/%d: SynthesizeAAAA returned nil", pl)
		}
		if len(synthesized) != 16 {
			t.Fatalf("/%d: synthesized length: got %d, want 16", pl, len(synthesized))
		}

		// Byte 8 must always be 0 (the "u" byte per RFC 6052).
		if synthesized[8] != 0 {
			t.Fatalf("/%d: byte 8 (u-byte) is %d, want 0", pl, synthesized[8])
		}

		// Verify round-trip.
		extracted := s.ExtractIPv4(synthesized)
		if !extracted.Equal(ipv4) {
			t.Fatalf("/%d: round-trip failed: got %v, want %v", pl, extracted, ipv4)
		}
	}
}

// ---------------------------------------------------------------------------
// TestEnabledDisabled
// ---------------------------------------------------------------------------

func TestEnabledDisabled(t *testing.T) {
	s, err := NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatal(err)
	}

	if !s.IsEnabled() {
		t.Fatal("expected enabled by default")
	}

	s.SetEnabled(false)
	if s.IsEnabled() {
		t.Fatal("expected disabled after SetEnabled(false)")
	}

	s.SetEnabled(true)
	if !s.IsEnabled() {
		t.Fatal("expected enabled after SetEnabled(true)")
	}
}

// ---------------------------------------------------------------------------
// TestSynthesizeAAAA_NilInput
// ---------------------------------------------------------------------------

func TestSynthesizeAAAA_NilInput(t *testing.T) {
	s, err := NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatal(err)
	}

	if got := s.SynthesizeAAAA(nil); got != nil {
		t.Fatalf("expected nil for nil input, got %v", got)
	}

	// IPv6 address passed as ipv4 should return nil (not a valid v4).
	if got := s.SynthesizeAAAA(net.ParseIP("2001:db8::1")); got != nil {
		t.Fatalf("expected nil for IPv6 input, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// TestSynthesizeResponse_NilInputs
// ---------------------------------------------------------------------------

func TestSynthesizeResponse_NilInputs(t *testing.T) {
	s, err := NewSynthesizer("64:ff9b::", 96)
	if err != nil {
		t.Fatal(err)
	}

	if got := s.SynthesizeResponse(nil, nil); got != nil {
		t.Fatal("expected nil for nil inputs")
	}

	q := &protocol.Question{
		Name:   protocol.NewName([]string{"example", "com"}, true),
		QType:  protocol.TypeAAAA,
		QClass: protocol.ClassIN,
	}
	if got := s.SynthesizeResponse(q, nil); got != nil {
		t.Fatal("expected nil for nil response")
	}
	if got := s.SynthesizeResponse(nil, &protocol.Message{}); got != nil {
		t.Fatal("expected nil for nil question")
	}
}
