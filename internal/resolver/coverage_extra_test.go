package resolver

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ============================================================================
// resolver.go - unexported helpers
// ============================================================================

func TestToUpper(t *testing.T) {
	tests := []struct {
		input byte
		want  byte
	}{
		{'a', 'A'},
		{'z', 'Z'},
		{'A', 'A'}, // already upper
		{'Z', 'Z'},
		{'0', '0'}, // non-alpha
		{'.', '.'},
	}
	for _, tt := range tests {
		got := toUpper(tt.input)
		if got != tt.want {
			t.Errorf("toUpper(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		input byte
		want  byte
	}{
		{'A', 'a'},
		{'Z', 'z'},
		{'a', 'a'}, // already lower
		{'z', 'z'},
		{'0', '0'}, // non-alpha
		{'.', '.'},
	}
	for _, tt := range tests {
		got := toLower(tt.input)
		if got != tt.want {
			t.Errorf("toLower(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWithPort_AlreadyHasPort(t *testing.T) {
	got := withPort("1.2.3.4:5353", "53")
	if got != "1.2.3.4:5353" {
		t.Errorf("withPort with existing port = %q, want %q", got, "1.2.3.4:5353")
	}
}

func TestWithPort_NeedsPort(t *testing.T) {
	got := withPort("1.2.3.4", "53")
	if got != "1.2.3.4:53" {
		t.Errorf("withPort without port = %q, want %q", got, "1.2.3.4:53")
	}
}

func TestHasAnyAddress_Empty(t *testing.T) {
	d := &delegation{
		nsNames: []string{"ns1.example.com."},
		addrs:   map[string][]string{},
	}
	if hasAnyAddress(d) {
		t.Error("hasAnyAddress should return false for delegation with no addresses")
	}
}

func TestHasAnyAddress_NilDelegation(t *testing.T) {
	d := &delegation{
		nsNames: nil,
		addrs:   map[string][]string{},
	}
	if hasAnyAddress(d) {
		t.Error("hasAnyAddress should return false for nil nsNames")
	}
}

func TestHasAnyAddress_WithAddresses(t *testing.T) {
	d := &delegation{
		nsNames: []string{"ns1.example.com."},
		addrs: map[string][]string{
			"ns1.example.com.": {"1.2.3.4:53"},
		},
	}
	if !hasAnyAddress(d) {
		t.Error("hasAnyAddress should return true when addresses exist")
	}
}

func TestContainsString_EmptySlice(t *testing.T) {
	if containsString(nil, "a") {
		t.Error("containsString(nil, 'a') should be false")
	}
	if containsString([]string{}, "a") {
		t.Error("containsString([], 'a') should be false")
	}
}

func TestIsAnswer(t *testing.T) {
	tests := []struct {
		name string
		msg  *protocol.Message
		want bool
	}{
		{
			name: "success with answers",
			msg: &protocol.Message{
				Header:   protocol.Header{Flags: protocol.Flags{RCODE: protocol.RcodeSuccess}},
				Answers:  []*protocol.ResourceRecord{makeARR("example.com.", "1.2.3.4")},
			},
			want: true,
		},
		{
			name: "success but no answers",
			msg: &protocol.Message{
				Header:  protocol.Header{Flags: protocol.Flags{RCODE: protocol.RcodeSuccess}},
				Answers: []*protocol.ResourceRecord{},
			},
			want: false,
		},
		{
			name: "non-success rcode with answers",
			msg: &protocol.Message{
				Header:  protocol.Header{Flags: protocol.Flags{RCODE: protocol.RcodeServerFailure}},
				Answers: []*protocol.ResourceRecord{makeARR("example.com.", "1.2.3.4")},
			},
			want: false,
		},
		{
			name: "nil answers",
			msg: &protocol.Message{
				Header: protocol.Header{Flags: protocol.Flags{RCODE: protocol.RcodeSuccess}},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAnswer(tt.msg); got != tt.want {
				t.Errorf("isAnswer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNXDomain(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{RCODE: protocol.RcodeNameError}},
	}
	if !isNXDomain(msg) {
		t.Error("isNXDomain should be true for NXDOMAIN")
	}

	msg.Header.Flags.RCODE = protocol.RcodeSuccess
	if isNXDomain(msg) {
		t.Error("isNXDomain should be false for NOERROR")
	}
}

func TestFindCNAME_NoCNAME(t *testing.T) {
	answers := []*protocol.ResourceRecord{
		makeARR("example.com.", "1.2.3.4"),
	}
	if got := findCNAME(answers, "example.com."); got != "" {
		t.Errorf("findCNAME with no CNAME = %q, want empty", got)
	}
}

func TestFindCNAME_NilAnswers(t *testing.T) {
	if got := findCNAME(nil, "example.com."); got != "" {
		t.Errorf("findCNAME(nil) = %q, want empty", got)
	}
}

func TestFindCNAME_WithCNAME(t *testing.T) {
	answers := []*protocol.ResourceRecord{
		makeCNAMERR("www.example.com.", "example.com."),
	}
	got := findCNAME(answers, "www.example.com.")
	if got != "example.com." {
		t.Errorf("findCNAME = %q, want %q", got, "example.com.")
	}
}

// ============================================================================
// findDNAME coverage
// ============================================================================

func TestFindDNAME_NoDNAME(t *testing.T) {
	answers := []*protocol.ResourceRecord{
		makeARR("example.com.", "1.2.3.4"),
	}
	result := findDNAME(answers, "www.example.com.")
	if result.found {
		t.Error("findDNAME should not find anything when no DNAME records exist")
	}
}

func TestFindDNAME_NilAnswers(t *testing.T) {
	result := findDNAME(nil, "www.example.com.")
	if result.found {
		t.Error("findDNAME should not find anything with nil answers")
	}
}

func TestFindDNAME_ExactMatchOwner(t *testing.T) {
	// DNAME owner equals query name - should not match (exact match is not a suffix)
	dnameTarget, _ := protocol.ParseName("example.net.")
	answers := []*protocol.ResourceRecord{
		{
			Name:  mustName("example.com."),
			Type:  protocol.TypeDNAME,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataDNAME{DName: dnameTarget},
		},
	}
	result := findDNAME(answers, "example.com.")
	if result.found {
		t.Error("findDNAME should not match when query name equals DNAME owner")
	}
}

func TestFindDNAME_SuffixMatch(t *testing.T) {
	dnameTarget, _ := protocol.ParseName("example.net.")
	answers := []*protocol.ResourceRecord{
		{
			Name:  mustName("example.com."),
			Type:  protocol.TypeDNAME,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataDNAME{DName: dnameTarget},
		},
	}
	result := findDNAME(answers, "www.example.com.")
	if !result.found {
		t.Fatal("findDNAME should find DNAME for suffix match")
	}
	// Synthesized target: replace "example.com." suffix with "example.net."
	// "www.example.com." -> "www.example.net."
	if result.synthTarget != "www.example.net." {
		t.Errorf("synthTarget = %q, want %q", result.synthTarget, "www.example.net.")
	}
	if result.dnameRR == nil {
		t.Error("dnameRR should not be nil when found")
	}
}

func TestFindDNAME_DeepSubdomain(t *testing.T) {
	dnameTarget, _ := protocol.ParseName("other.org.")
	answers := []*protocol.ResourceRecord{
		{
			Name:  mustName("example.com."),
			Type:  protocol.TypeDNAME,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataDNAME{DName: dnameTarget},
		},
	}
	result := findDNAME(answers, "a.b.c.example.com.")
	if !result.found {
		t.Fatal("findDNAME should find DNAME for deep subdomain")
	}
	if result.synthTarget != "a.b.c.other.org." {
		t.Errorf("synthTarget = %q, want %q", result.synthTarget, "a.b.c.other.org.")
	}
}

func TestFindDNAME_NotSuffix(t *testing.T) {
	dnameTarget, _ := protocol.ParseName("example.net.")
	answers := []*protocol.ResourceRecord{
		{
			Name:  mustName("example.com."),
			Type:  protocol.TypeDNAME,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataDNAME{DName: dnameTarget},
		},
	}
	result := findDNAME(answers, "www.example.org.")
	if result.found {
		t.Error("findDNAME should not match when query name is not a suffix of DNAME owner")
	}
}

func TestFindDNAME_WrongDataType(t *testing.T) {
	// DNAME record with wrong data type (not RDataDNAME)
	answers := []*protocol.ResourceRecord{
		{
			Name:  mustName("example.com."),
			Type:  protocol.TypeDNAME,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // Wrong type
		},
	}
	result := findDNAME(answers, "www.example.com.")
	if result.found {
		t.Error("findDNAME should not match when data type assertion fails")
	}
}

// ============================================================================
// NewResolver defaults
// ============================================================================

func TestNewResolver_ZeroConfig(t *testing.T) {
	cfg := Config{} // All zero values
	transport := newMockTransport()
	r := NewResolver(cfg, nil, transport)
	if r.config.MaxDepth != 30 {
		t.Errorf("MaxDepth = %d, want 30", r.config.MaxDepth)
	}
	if r.config.MaxCNAMEDepth != 16 {
		t.Errorf("MaxCNAMEDepth = %d, want 16", r.config.MaxCNAMEDepth)
	}
	if r.config.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", r.config.Timeout)
	}
	if r.config.EDNS0BufSize != 4096 {
		t.Errorf("EDNS0BufSize = %d, want 4096", r.config.EDNS0BufSize)
	}
	if len(r.hints) != 13 {
		t.Errorf("len(hints) = %d, want 13 (IANA defaults)", len(r.hints))
	}
}

func TestNewResolver_CustomHints(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Hints = []RootHint{
		{Name: "custom.root.", IPv4: []string{"10.0.0.1"}},
	}
	r := NewResolver(cfg, nil, newMockTransport())
	if len(r.hints) != 1 {
		t.Errorf("len(hints) = %d, want 1", len(r.hints))
	}
	if r.hints[0].Name != "custom.root." {
		t.Errorf("hints[0].Name = %q, want %q", r.hints[0].Name, "custom.root.")
	}
}

// ============================================================================
// CNAME depth limit
// ============================================================================

func TestResolver_CNAMEChainTooDeep(t *testing.T) {
	transport := newMockTransport()

	// All servers return a CNAME pointing to the next name
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
		qname := ""
		if len(msg.Questions) > 0 {
			qname = msg.Questions[0].Name.String()
		}
		// CNAME: current -> current + "a."
		target := "a" + qname
		resp.AddAnswer(makeCNAMERR(qname, target))
		return resp
	})

	cfg := DefaultConfig()
	cfg.MaxCNAMEDepth = 3
	r := NewResolver(cfg, newMockCache(), transport)

	// CNAME chain too deep: the resolver catches the recursive error and
	// returns the CNAME chain accumulated so far (not an error from Resolve).
	resp, err := r.Resolve(context.Background(), "deep.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response (CNAME chain returned)")
	}
	// Should have at least one CNAME record (the partial chain)
	if len(resp.Answers) == 0 {
		t.Error("expected at least one CNAME in answer")
	}
}

// ============================================================================
// DNAME synthesis during resolution
// ============================================================================

func TestResolver_DNAMESynthesis(t *testing.T) {
	transport := newMockTransport()

	// Root server gives referral to example.com NS
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
			Questions: msg.Questions,
		}
		resp.AddAuthority(makeNSRR("example.com.", "ns1.example.com."))
		resp.AddAdditional(makeARR("ns1.example.com.", "10.0.0.1"))
		return resp
	})

	nsAddr := "10.0.0.1:53"
	transport.setHandler(nsAddr, func(msg *protocol.Message) *protocol.Message {
		qname := ""
		if len(msg.Questions) > 0 {
			qname = msg.Questions[0].Name.String()
		}
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}

		if qname == "www.example.com." {
			// Return DNAME: example.com. DNAME example.net.
			dnameTarget, _ := protocol.ParseName("example.net.")
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  mustName("example.com."),
				Type:  protocol.TypeDNAME,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataDNAME{DName: dnameTarget},
			})
		} else if qname == "www.example.net." {
			// Return final A record
			resp.AddAnswer(makeARR("www.example.net.", "5.5.5.5"))
		}
		return resp
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)
	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	// Should have DNAME + synthesized CNAME + A record
	if len(resp.Answers) < 2 {
		t.Fatalf("Expected at least 2 answers (DNAME + CNAME/A), got %d", len(resp.Answers))
	}

	hasDNAME := false
	hasCNAME := false
	hasA := false
	for _, rr := range resp.Answers {
		switch rr.Type {
		case protocol.TypeDNAME:
			hasDNAME = true
		case protocol.TypeCNAME:
			hasCNAME = true
		case protocol.TypeA:
			hasA = true
		}
	}
	if !hasDNAME {
		t.Error("Expected DNAME record in answers")
	}
	if !hasCNAME {
		t.Error("Expected synthesized CNAME record in answers")
	}
	if !hasA {
		t.Error("Expected A record in answers from synthesized target")
	}
}

// ============================================================================
// extractDelegation
// ============================================================================

func TestExtractDelegation_NoNS(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			makeARR("example.com.", "1.2.3.4"), // Not an NS record
		},
	}
	deleg, _ := r.extractDelegation(resp, ".")
	if len(deleg.nsNames) != 0 {
		t.Errorf("nsNames = %d, want 0", len(deleg.nsNames))
	}
}

func TestExtractDelegation_WithGlue(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			makeNSRR("example.com.", "ns1.example.com."),
			makeNSRR("example.com.", "ns2.example.com."),
		},
		Additionals: []*protocol.ResourceRecord{
			makeARR("ns1.example.com.", "1.2.3.4"),
			{
				Name:  mustName("ns2.example.com."),
				Type:  protocol.TypeAAAA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataAAAA{Address: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			},
		},
	}
	deleg, _ := r.extractDelegation(resp, ".")
	if len(deleg.nsNames) != 2 {
		t.Errorf("nsNames = %d, want 2", len(deleg.nsNames))
	}
	if len(deleg.addrs["ns1.example.com."]) != 1 {
		t.Errorf("ns1 addrs = %d, want 1", len(deleg.addrs["ns1.example.com."]))
	}
	if len(deleg.addrs["ns2.example.com."]) != 1 {
		t.Errorf("ns2 addrs = %d, want 1", len(deleg.addrs["ns2.example.com."]))
	}
}

func TestExtractDelegation_DuplicateNS(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			makeNSRR("example.com.", "ns1.example.com."),
			makeNSRR("example.com.", "ns1.example.com."), // Duplicate
		},
	}
	deleg, _ := r.extractDelegation(resp, ".")
	if len(deleg.nsNames) != 1 {
		t.Errorf("nsNames = %d, want 1 (dedup)", len(deleg.nsNames))
	}
}

func TestExtractDelegation_AdditionalNonMatch(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			makeNSRR("example.com.", "ns1.example.com."),
		},
		Additionals: []*protocol.ResourceRecord{
			makeARR("unrelated.example.com.", "9.9.9.9"), // Not matching any NS
		},
	}
	deleg, _ := r.extractDelegation(resp, ".")
	if len(deleg.nsNames) != 1 {
		t.Errorf("nsNames = %d, want 1", len(deleg.nsNames))
	}
	// ns1 should have no addresses since glue doesn't match
	if len(deleg.addrs["ns1.example.com."]) != 0 {
		t.Errorf("ns1 addrs = %d, want 0", len(deleg.addrs["ns1.example.com."]))
	}
	// The non-matching Additional must also not leak into the map.
	if len(deleg.addrs["unrelated.example.com."]) != 0 {
		t.Errorf("unrelated.example.com addrs = %d, want 0 (non-NS-target glue must be dropped)",
			len(deleg.addrs["unrelated.example.com."]))
	}
}

// ============================================================================
// lookupNSAddresses - 0% coverage
// ============================================================================

func TestLookupNSAddresses_CacheHit(t *testing.T) {
	cache := newMockCache()
	// Pre-populate cache with A record for ns1.example.com.
	aMsg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	aMsg.AddAnswer(makeARR("ns1.example.com.", "10.0.0.1"))
	cache.Set("ns1.example.com.:1", aMsg, 300)

	r := NewResolver(DefaultConfig(), cache, newMockTransport())
	addrs := r.lookupNSAddresses(context.Background(), "ns1.example.com.")
	if len(addrs) != 1 {
		t.Fatalf("lookupNSAddresses len = %d, want 1", len(addrs))
	}
	if addrs[0] != "10.0.0.1:53" {
		t.Errorf("addr = %q, want %q", addrs[0], "10.0.0.1:53")
	}
}

func TestLookupNSAddresses_CacheHitAAAA(t *testing.T) {
	cache := newMockCache()
	aaaaMsg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	aaaaMsg.AddAnswer(&protocol.ResourceRecord{
		Name:  mustName("ns1.example.com."),
		Type:  protocol.TypeAAAA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataAAAA{Address: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	})
	cache.Set("ns1.example.com.:28", aaaaMsg, 300)

	r := NewResolver(DefaultConfig(), cache, newMockTransport())
	addrs := r.lookupNSAddresses(context.Background(), "ns1.example.com.")
	if len(addrs) != 1 {
		t.Fatalf("lookupNSAddresses len = %d, want 1", len(addrs))
	}
}

func TestLookupNSAddresses_CacheNegative(t *testing.T) {
	cache := newMockCache()
	// Set negative entry
	cache.SetNegative("ns1.example.com.:1", protocol.RcodeNameError)

	r := NewResolver(DefaultConfig(), cache, newMockTransport())
	addrs := r.lookupNSAddresses(context.Background(), "ns1.example.com.")
	if len(addrs) != 0 {
		t.Errorf("lookupNSAddresses with negative cache = %d addrs, want 0", len(addrs))
	}
}

func TestLookupNSAddresses_NilCache(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	addrs := r.lookupNSAddresses(context.Background(), "ns1.example.com.")
	if len(addrs) != 0 {
		t.Errorf("lookupNSAddresses with nil cache = %d addrs, want 0", len(addrs))
	}
}

func TestLookupNSAddresses_CacheHitButWrongType(t *testing.T) {
	cache := newMockCache()
	// Cache entry has a message but with CNAME not A/AAAA
	cnameMsg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	cnameMsg.AddAnswer(makeCNAMERR("ns1.example.com.", "alias.example.com."))
	cache.Set("ns1.example.com.:1", cnameMsg, 300)

	r := NewResolver(DefaultConfig(), cache, newMockTransport())
	addrs := r.lookupNSAddresses(context.Background(), "ns1.example.com.")
	if len(addrs) != 0 {
		t.Errorf("lookupNSAddresses with CNAME-only cache = %d addrs, want 0", len(addrs))
	}
}

func TestLookupNSAddresses_CacheNilMessage(t *testing.T) {
	cache := newMockCache()
	// Manually insert entry with nil message (edge case)
	cache.entries["ns1.example.com.:1"] = &CacheEntry{Message: nil, IsNegative: false}

	r := NewResolver(DefaultConfig(), cache, newMockTransport())
	addrs := r.lookupNSAddresses(context.Background(), "ns1.example.com.")
	if len(addrs) != 0 {
		t.Errorf("lookupNSAddresses with nil message = %d addrs, want 0", len(addrs))
	}
}

// ============================================================================
// resolveNSAddresses - 56.2% coverage
// ============================================================================

func TestResolveNSAddresses_WithGlue(t *testing.T) {
	transport := newMockTransport()
	r := NewResolver(DefaultConfig(), nil, transport)
	deleg := &delegation{
		nsNames: []string{"ns1.example.com."},
		addrs: map[string][]string{
			"ns1.example.com.": {"10.0.0.1:53"},
		},
	}
	r.resolveNSAddresses(context.Background(), deleg)
	// Should not change anything since glue already exists
	if len(deleg.addrs["ns1.example.com."]) != 1 {
		t.Error("resolveNSAddresses should keep existing glue")
	}
}

func TestResolveNSAddresses_NoGlueWithCache(t *testing.T) {
	cache := newMockCache()
	aMsg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	aMsg.AddAnswer(makeARR("ns2.example.org.", "10.0.0.2"))
	cache.Set("ns2.example.org.:1", aMsg, 300)

	r := NewResolver(DefaultConfig(), cache, newMockTransport())
	deleg := &delegation{
		nsNames: []string{"ns2.example.org."},
		addrs:   map[string][]string{},
	}
	r.resolveNSAddresses(context.Background(), deleg)
	if len(deleg.addrs["ns2.example.org."]) == 0 {
		t.Error("resolveNSAddresses should resolve NS name via cache")
	}
}

func TestResolveNSAddresses_NoGlueNoCache(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	deleg := &delegation{
		nsNames: []string{"ns3.example.net."},
		addrs:   map[string][]string{},
	}
	r.resolveNSAddresses(context.Background(), deleg)
	if len(deleg.addrs["ns3.example.net."]) != 0 {
		t.Error("resolveNSAddresses with no cache should not resolve")
	}
}

// ============================================================================
// cacheResponse / cacheNegative with nil cache
// ============================================================================

func TestCacheResponse_NilCache(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	// Should not panic
	r.cacheResponse("example.com.", protocol.TypeA, &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
		Answers: []*protocol.ResourceRecord{
			makeARR("example.com.", "1.2.3.4"),
		},
	}, ".")
}

func TestCacheResponse_ZeroTTL(t *testing.T) {
	cache := newMockCache()
	r := NewResolver(DefaultConfig(), cache, newMockTransport())

	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	// Answer with TTL=0
	rr := makeARR("example.com.", "1.2.3.4")
	rr.TTL = 0
	resp.AddAnswer(rr)

	r.cacheResponse("example.com.", protocol.TypeA, resp, ".")
	// Should use default TTL of 300
	if len(cache.sets) == 0 {
		t.Error("cacheResponse should cache even with zero TTL (uses default)")
	}
}

func TestCacheResponse_WithAAAARecord(t *testing.T) {
	cache := newMockCache()
	r := NewResolver(DefaultConfig(), cache, newMockTransport())

	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	resp.AddAnswer(&protocol.ResourceRecord{
		Name:  mustName("example.com."),
		Type:  protocol.TypeAAAA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataAAAA{Address: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	})

	r.cacheResponse("example.com.", protocol.TypeAAAA, resp, ".")
	if len(cache.sets) < 1 {
		t.Error("cacheResponse should cache AAAA records")
	}
}

func TestCacheNegative_NilCache(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	// Should not panic
	r.cacheNegative("example.com.", protocol.TypeA, protocol.RcodeNameError)
}

// ============================================================================
// sendQuery error paths
// ============================================================================

func TestSendQuery_InvalidName(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	// Use a name with a label exceeding 63 bytes, which should fail in ParseName
	longLabel := make([]byte, 70)
	for i := range longLabel {
		longLabel[i] = 'a'
	}
	invalidName := string(longLabel) + ".example.com."
	_, err := r.sendQuery(context.Background(), invalidName, protocol.TypeA, "1.2.3.4:53")
	if err == nil {
		t.Error("sendQuery with invalid name should fail")
	}
}

// ============================================================================
// queryDelegation with 0x20 verification failure
// ============================================================================

func TestQueryDelegation_0x20VerificationFail(t *testing.T) {
	transport := newMockTransport()

	// All servers respond with a different name (case mismatch)
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    msg.Header.ID,
				Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess},
			},
		}
		// Return a question with different case
		q, _ := protocol.NewQuestion("example.com.", protocol.TypeA, protocol.ClassIN)
		resp.Questions = []*protocol.Question{q}
		resp.AddAnswer(makeARR("example.com.", "1.2.3.4"))
		return resp
	})

	cfg := DefaultConfig()
	cfg.Use0x20 = true
	r := NewResolver(cfg, newMockCache(), transport)

	deleg := &delegation{
		nsNames: []string{"a.root-servers.net."},
		addrs: map[string][]string{
			"a.root-servers.net.": {"198.41.0.4:53"},
		},
	}

	_, err := r.queryDelegation(context.Background(), "EXAMPLE.COM.", protocol.TypeA, deleg)
	if err == nil {
		t.Error("queryDelegation with 0x20 mismatch should fail")
	}
}

// ============================================================================
// queryDelegation with nil response
// ============================================================================

func TestQueryDelegation_NilResponse(t *testing.T) {
	transport := newMockTransport()

	// Handler returns nil
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		return nil
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)
	deleg := &delegation{
		nsNames: []string{"a.root-servers.net."},
		addrs: map[string][]string{
			"a.root-servers.net.": {"198.41.0.4:53"},
		},
	}

	_, err := r.queryDelegation(context.Background(), "example.com.", protocol.TypeA, deleg)
	if err == nil {
		t.Error("queryDelegation with nil response should fail")
	}
}

// ============================================================================
// LogTransport - 0% coverage
// ============================================================================

func TestNewLogTransport(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	inner := newMockTransport()
	lt := NewLogTransport(inner, logger)
	if lt == nil {
		t.Fatal("NewLogTransport returned nil")
	}
}

func TestLogTransport_QueryContext(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	inner := newMockTransport()

	// Set up a handler that returns an answer
	inner.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		return &protocol.Message{
			Header: protocol.Header{
				ID:    msg.Header.ID,
				Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess},
			},
			Questions: msg.Questions,
			Answers:   []*protocol.ResourceRecord{makeARR("example.com.", "1.2.3.4")},
		}
	})

	lt := NewLogTransport(inner, logger)

	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.Flags{RD: true}},
		Questions: []*protocol.Question{{Name: mustName("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}

	resp, err := lt.QueryContext(context.Background(), msg, "198.41.0.4:53")
	if err != nil {
		t.Fatalf("LogTransport QueryContext error: %v", err)
	}
	if resp == nil {
		t.Fatal("LogTransport QueryContext returned nil response")
	}

	logOutput := buf.String()
	if logOutput == "" {
		t.Error("LogTransport should have logged the query")
	}
}

func TestLogTransport_QueryContextError(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	// Inner transport that always errors
	inner := &errorTransport{}

	lt := NewLogTransport(inner, logger)

	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.Flags{RD: true}},
		Questions: []*protocol.Question{{Name: mustName("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}

	_, err := lt.QueryContext(context.Background(), msg, "1.2.3.4:53")
	if err == nil {
		t.Error("expected error from errorTransport")
	}

	logOutput := buf.String()
	if logOutput == "" {
		t.Error("LogTransport should have logged the error")
	}
}

func TestLogTransport_NilLogger(t *testing.T) {
	inner := newMockTransport()
	inner.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		return &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
	})

	lt := NewLogTransport(inner, nil)
	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.Flags{RD: true}},
		Questions: []*protocol.Question{{Name: mustName("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}

	// Should not panic with nil logger
	resp, err := lt.QueryContext(context.Background(), msg, "198.41.0.4:53")
	if err != nil {
		t.Fatalf("LogTransport with nil logger error: %v", err)
	}
	if resp == nil {
		t.Fatal("LogTransport with nil logger should still forward")
	}
}

func TestLogTransport_NilResponse(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	inner := &nilResponseTransport{}
	lt := NewLogTransport(inner, logger)

	msg := &protocol.Message{
		Header:    protocol.Header{ID: 1, Flags: protocol.Flags{RD: true}},
		Questions: []*protocol.Question{{Name: mustName("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN}},
	}

	resp, _ := lt.QueryContext(context.Background(), msg, "1.2.3.4:53")
	if resp != nil {
		t.Error("expected nil response from nilResponseTransport")
	}
}

// ============================================================================
// readFull - 0% coverage
// ============================================================================

func TestReadFull_ExactRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	data := []byte{1, 2, 3, 4}
	go func() {
		server.Write(data)
		server.Close()
	}()

	buf := make([]byte, 4)
	n, err := readFull(client, buf)
	if err != nil {
		t.Fatalf("readFull error: %v", err)
	}
	if n != 4 {
		t.Errorf("readFull n = %d, want 4", n)
	}
	if !bytes.Equal(buf, data) {
		t.Errorf("readFull buf = %v, want %v", buf, data)
	}
}

func TestReadFull_PartialReads(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		// Write in two chunks
		server.Write([]byte{1, 2})
		time.Sleep(10 * time.Millisecond)
		server.Write([]byte{3, 4})
		server.Close()
	}()

	buf := make([]byte, 4)
	n, err := readFull(client, buf)
	if err != nil {
		t.Fatalf("readFull error: %v", err)
	}
	if n != 4 {
		t.Errorf("readFull n = %d, want 4", n)
	}
}

func TestReadFull_ConnectionClose(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		server.Write([]byte{1, 2})
		server.Close()
	}()

	buf := make([]byte, 4)
	_, err := readFull(client, buf)
	if err == nil {
		t.Error("readFull should error when connection closes before buf is full")
	}
}

func TestReadFull_EmptyBuffer(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	buf := make([]byte, 0)
	n, err := readFull(client, buf)
	if err != nil {
		t.Errorf("readFull with empty buffer should succeed, got error: %v", err)
	}
	if n != 0 {
		t.Errorf("readFull n = %d, want 0", n)
	}
}

// ============================================================================
// serializeExtended with IPv6 upstreams
// ============================================================================

func TestSerializeExtended_IPv6Upstream(t *testing.T) {
	info := ExtendedResolverInfo("test", "1.0", false, true, 0, []string{"2001:db8::1"})
	data := info.serializeExtended()
	if len(data) == 0 {
		t.Error("serializeExtended should produce data for IPv6 upstream")
	}
}

func TestSerializeExtended_MixedUpstreams(t *testing.T) {
	info := ExtendedResolverInfo("test", "1.0", false, true, 5000, []string{"1.2.3.4", "2001:db8::1", "dns.example.com"})
	data := info.serializeExtended()
	if len(data) == 0 {
		t.Error("serializeExtended should produce data for mixed upstreams")
	}
}

func TestSerializeExtended_EmptyUpstreams(t *testing.T) {
	info := ExtendedResolverInfo("test", "1.0", false, false, 100, nil)
	data := info.serializeExtended()
	if len(data) == 0 {
		t.Error("serializeExtended should produce data with no upstreams")
	}
}

// ============================================================================
// parseExtendedRESPInfo with IPv6 upstreams
// ============================================================================

func TestParseExtendedRESPInfo_IPv6Upstream(t *testing.T) {
	info := ExtendedResolverInfo("test", "1.0", true, false, 1000, []string{"2001:db8::1"})
	wire, err := info.ToWire(ResponderOptionCodeExtendedInfo, 300)
	if err != nil {
		t.Fatalf("ToWire failed: %v", err)
	}
	parsed, err := parseExtendedRESPInfo(wire.Data)
	if err != nil {
		t.Fatalf("parseExtendedRESPInfo failed: %v", err)
	}
	if len(parsed.Upstreams) != 1 {
		t.Fatalf("Upstreams len = %d, want 1", len(parsed.Upstreams))
	}
	// The parsed IP should be the canonical form
	if parsed.Upstreams[0] != "2001:db8::1" {
		t.Errorf("Upstream[0] = %q, want %q", parsed.Upstreams[0], "2001:db8::1")
	}
}

func TestParseExtendedRESPInfo_MixedUpstreams(t *testing.T) {
	info := ExtendedResolverInfo("test", "1.0", true, false, 1000, []string{"1.2.3.4", "2001:db8::1", "dns.example.com"})
	wire, err := info.ToWire(ResponderOptionCodeExtendedInfo, 300)
	if err != nil {
		t.Fatalf("ToWire failed: %v", err)
	}
	parsed, err := parseExtendedRESPInfo(wire.Data)
	if err != nil {
		t.Fatalf("parseExtendedRESPInfo failed: %v", err)
	}
	if len(parsed.Upstreams) != 3 {
		t.Fatalf("Upstreams len = %d, want 3", len(parsed.Upstreams))
	}
}

func TestParseExtendedRESPInfo_TruncatedUpstreamIPv4(t *testing.T) {
	// Build extended data manually with truncated IPv4 upstream
	data := []byte{
		4, 't', 'e', 's', 't', // ID
		1, 'v',                   // Version
		1,                        // DNSSEC
		0,                        // Filtering
		0, 0, 0, 100,             // Cache size
		1,                        // 1 upstream
		4,                        // IPv4 marker
		1, 2,                     // Truncated (only 2 of 4 bytes)
	}
	// Pad to minimum length
	for len(data) < 4 {
		data = append(data, 0)
	}
	// Should not crash, just skip the truncated upstream
	parsed, err := parseExtendedRESPInfo(data)
	if err != nil {
		// Error is acceptable for truncated data
		t.Logf("parseExtendedRESPInfo with truncated IPv4 returned: %v", err)
	} else {
		// If no error, upstreams should be empty (truncated was skipped)
		if parsed == nil {
			t.Fatal("parsed should not be nil")
		}
	}
}

func TestParseExtendedRESPInfo_TruncatedUpstreamIPv6(t *testing.T) {
	// Build extended data with truncated IPv6 upstream
	data := []byte{
		4, 't', 'e', 's', 't', // ID
		1, 'v',                   // Version
		1,                        // DNSSEC
		0,                        // Filtering
		0, 0, 0, 100,             // Cache size
		1,                        // 1 upstream
		6,                        // IPv6 marker
		0x20, 0x01, 0x0d, 0xb8,   // Only 4 of 16 bytes
	}
	for len(data) < 4 {
		data = append(data, 0)
	}
	parsed, err := parseExtendedRESPInfo(data)
	if err != nil {
		t.Logf("parseExtendedRESPInfo with truncated IPv6 returned: %v", err)
	} else if parsed != nil && len(parsed.Upstreams) != 0 {
		t.Errorf("Upstreams should be empty for truncated IPv6, got %d", len(parsed.Upstreams))
	}
}

func TestParseExtendedRESPInfo_TruncatedHostname(t *testing.T) {
	data := []byte{
		4, 't', 'e', 's', 't', // ID
		1, 'v',                   // Version
		0,                        // DNSSEC
		1,                        // Filtering
		0, 0, 0, 50,              // Cache size
		1,                        // 1 upstream
		10,                       // Hostname length marker = 10
		'h', 'o', 's', 't',       // Only 4 of 10 bytes
	}
	for len(data) < 4 {
		data = append(data, 0)
	}
	parsed, err := parseExtendedRESPInfo(data)
	if err != nil {
		t.Logf("parseExtendedRESPInfo with truncated hostname returned: %v", err)
	} else if parsed != nil && len(parsed.Upstreams) != 0 {
		t.Errorf("Upstreams should be empty for truncated hostname, got %d", len(parsed.Upstreams))
	}
}

func TestParseExtendedRESPInfo_MultipleUpstreams(t *testing.T) {
	info := ExtendedResolverInfo("r", "2.0", true, true, 999, []string{"1.2.3.4", "2001:db8::1", "hostname.example.com"})
	wire, err := info.ToWire(ResponderOptionCodeExtendedInfo, 60)
	if err != nil {
		t.Fatalf("ToWire failed: %v", err)
	}
	parsed, err := parseExtendedRESPInfo(wire.Data)
	if err != nil {
		t.Fatalf("parseExtendedRESPInfo failed: %v", err)
	}
	if len(parsed.Upstreams) != 3 {
		t.Errorf("Upstreams len = %d, want 3", len(parsed.Upstreams))
	}
	if !parsed.DNSSecValidation {
		t.Error("DNSSecValidation should be true")
	}
	if !parsed.FilteringEnabled {
		t.Error("FilteringEnabled should be true")
	}
	if parsed.CacheSize != 999 {
		t.Errorf("CacheSize = %d, want 999", parsed.CacheSize)
	}
}

// ============================================================================
// parseBasicRESPInfo edge cases
// ============================================================================

func TestParseBasicRESPInfo_TooShort(t *testing.T) {
	_, err := parseBasicRESPInfo(nil)
	if err == nil {
		t.Error("parseBasicRESPInfo(nil) should fail")
	}

	_, err = parseBasicRESPInfo([]byte{1})
	if err == nil {
		t.Error("parseBasicRESPInfo with 1 byte should fail")
	}
}

func TestParseBasicRESPInfo_TruncatedID(t *testing.T) {
	// ID length byte says 10, but only 3 bytes available
	data := []byte{10, 'a', 'b'}
	_, err := parseBasicRESPInfo(data)
	if err == nil {
		t.Error("parseBasicRESPInfo with truncated ID should fail")
	}
}

func TestParseBasicRESPInfo_TruncatedVersionLength(t *testing.T) {
	// ID is valid but no version length byte
	data := []byte{3, 'a', 'b', 'c'}
	_, err := parseBasicRESPInfo(data)
	if err == nil {
		t.Error("parseBasicRESPInfo with no version length should fail")
	}
}

func TestParseBasicRESPInfo_TruncatedVersion(t *testing.T) {
	// ID is valid, version length says 5, but only 2 bytes available
	data := []byte{3, 'a', 'b', 'c', 5, 'v', '1'}
	_, err := parseBasicRESPInfo(data)
	if err == nil {
		t.Error("parseBasicRESPInfo with truncated version should fail")
	}
}

func TestParseBasicRESPInfo_Valid(t *testing.T) {
	data := []byte{
		4, 't', 'e', 's', 't', // ID
		3, '1', '.', '0', // Version
	}
	parsed, err := parseBasicRESPInfo(data)
	if err != nil {
		t.Fatalf("parseBasicRESPInfo failed: %v", err)
	}
	if parsed.ID != "test" {
		t.Errorf("ID = %q, want %q", parsed.ID, "test")
	}
	if parsed.Version != "1.0" {
		t.Errorf("Version = %q, want %q", parsed.Version, "1.0")
	}
}

func TestParseBasicRESPInfo_EmptyStrings(t *testing.T) {
	data := []byte{
		0,   // Empty ID
		0,   // Empty version
	}
	// Minimum length is 2 (just the two length bytes)
	parsed, err := parseBasicRESPInfo(data)
	if err != nil {
		t.Fatalf("parseBasicRESPInfo failed: %v", err)
	}
	if parsed.ID != "" {
		t.Errorf("ID = %q, want empty", parsed.ID)
	}
	if parsed.Version != "" {
		t.Errorf("Version = %q, want empty", parsed.Version)
	}
}

// ============================================================================
// ParseRESPInfo unknown type
// ============================================================================

func TestParseRESPInfo_UnknownType(t *testing.T) {
	_, err := ParseRESPInfo(99, []byte{1, 2, 3})
	if err == nil {
		t.Error("ParseRESPInfo with unknown type should fail")
	}
}

// ============================================================================
// ResolverInfo String() with all fields
// ============================================================================

func TestResolverInfoString_AllFields(t *testing.T) {
	info := &ResolverInfo{
		ID:               "full-resolver",
		Version:          "3.0",
		DNSSecValidation: true,
		FilteringEnabled: true,
		Capabilities:     []string{"dnssec", "edns"},
		Upstreams:        []string{"8.8.8.8:53"},
	}
	s := info.String()
	if s == "" {
		t.Error("String() should not be empty")
	}
	// Should contain all major parts
	if !containsSubstring(s, "id=") {
		t.Error("String() should contain 'id='")
	}
	if !containsSubstring(s, "version=") {
		t.Error("String() should contain 'version='")
	}
	if !containsSubstring(s, "dnssec") {
		t.Error("String() should contain 'dnssec'")
	}
	if !containsSubstring(s, "filtering") {
		t.Error("String() should contain 'filtering'")
	}
	if !containsSubstring(s, "caps=") {
		t.Error("String() should contain 'caps='")
	}
	if !containsSubstring(s, "upstreams=") {
		t.Error("String() should contain 'upstreams='")
	}
}

func TestResolverInfoString_Minimal(t *testing.T) {
	info := &ResolverInfo{}
	s := info.String()
	if s == "" {
		t.Error("String() should not be empty even for zero-value info")
	}
}

// ============================================================================
// RDNSS Validate - loopback (91.7% -> need loopback check)
// ============================================================================

func TestRDNSSValidate_Loopback(t *testing.T) {
	opt := NewRDNSSOption(time.Minute, []net.IP{net.ParseIP("::1")})
	if err := opt.Validate(); err == nil {
		t.Error("Validate() with loopback address should fail")
	}
}

// ============================================================================
// DNSSL Validate - domain too long
// ============================================================================

func TestDNSSLValidate_DomainTooLong(t *testing.T) {
	longDomain := make([]byte, 256)
	for i := range longDomain {
		longDomain[i] = 'a'
	}
	opt := NewDNSSLOption(time.Minute, []string{string(longDomain)})
	if err := opt.Validate(); err == nil {
		t.Error("Validate() with domain > 255 chars should fail")
	}
}

// ============================================================================
// DNSSL RemainingLifetime - normal case
// ============================================================================

func TestDNSSLRemainingLifetime_Normal(t *testing.T) {
	opt := NewDNSSLOption(10*time.Minute, []string{"example.com"})
	// Received just now, so remaining should be close to 10 minutes
	rem := opt.RemainingLifetime(time.Now())
	if rem < 9*time.Minute || rem > 10*time.Minute {
		t.Errorf("RemainingLifetime = %v, want ~10m", rem)
	}
}

// ============================================================================
// RDNSS RemainingLifetime - normal case
// ============================================================================

func TestRDNSSRemainingLifetime_Normal(t *testing.T) {
	opt := NewRDNSSOption(10*time.Minute, []net.IP{net.ParseIP("2001:db8::1")})
	rem := opt.RemainingLifetime(time.Now())
	if rem < 9*time.Minute || rem > 10*time.Minute {
		t.Errorf("RemainingLifetime = %v, want ~10m", rem)
	}
}

// ============================================================================
// DNSConfig GetServers with duplicates
// ============================================================================

func TestDNSConfigGetServers_DuplicateDedup(t *testing.T) {
	cfg := NewDNSConfig()
	ip := net.ParseIP("2001:db8::1")
	cfg.AddRDNSS(NewRDNSSOption(time.Minute, []net.IP{ip}))
	cfg.AddRDNSS(NewRDNSSOption(time.Minute, []net.IP{ip})) // Same IP

	servers := cfg.GetServers()
	if len(servers) != 1 {
		t.Errorf("GetServers() with duplicates = %d, want 1", len(servers))
	}
}

func TestDNSConfigGetSearchDomains_DuplicateDedup(t *testing.T) {
	cfg := NewDNSConfig()
	cfg.AddDNSSL(NewDNSSLOption(time.Minute, []string{"example.com"}))
	cfg.AddDNSSL(NewDNSSLOption(time.Minute, []string{"example.com"})) // Same domain

	domains := cfg.GetSearchDomains()
	if len(domains) != 1 {
		t.Errorf("GetSearchDomains() with duplicates = %d, want 1", len(domains))
	}
}

// ============================================================================
// DNSConfig GetServers/GetSearchDomains empty
// ============================================================================

func TestDNSConfigGetServers_Empty(t *testing.T) {
	cfg := NewDNSConfig()
	servers := cfg.GetServers()
	if len(servers) != 0 {
		t.Errorf("GetServers() on empty config = %d, want 0", len(servers))
	}
}

func TestDNSConfigGetSearchDomains_Empty(t *testing.T) {
	cfg := NewDNSConfig()
	domains := cfg.GetSearchDomains()
	if len(domains) != 0 {
		t.Errorf("GetSearchDomains() on empty config = %d, want 0", len(domains))
	}
}

// ============================================================================
// DNSConfig RemoveExpired all expired
// ============================================================================

func TestDNSConfigRemoveExpired_AllExpired(t *testing.T) {
	cfg := NewDNSConfig()
	cfg.AddRDNSS(NewRDNSSOption(0, []net.IP{net.ParseIP("2001:db8::1")}))
	cfg.AddDNSSL(NewDNSSLOption(0, []string{"example.com"}))

	cfg.RemoveExpired()

	if !cfg.IsEmpty() {
		t.Error("RemoveExpired should remove all expired entries, leaving config empty")
	}
}

// ============================================================================
// Referral with no usable NS (empty delegation) - SERVFAIL
// ============================================================================

func TestResolver_ReferralNoNS(t *testing.T) {
	transport := newMockTransport()

	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
			Questions: msg.Questions,
		}
		// Return referral with no NS records in authority, only SOA
		resp.AddAuthority(&protocol.ResourceRecord{
			Name:  mustName("com."),
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   900,
			Data: &protocol.RDataSOA{
				MName: mustName("a.gtld-servers.net."),
				RName: mustName("nstld.verisign-grs.com."),
			},
		})
		return resp
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)
	resp, err := r.Resolve(context.Background(), "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	// The response is classified as neither answer, NXDOMAIN, nor referral.
	// The loop continues until max depth is exhausted -> SERVFAIL
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// ============================================================================
// Referral where NS has no addresses (resolveNSAddresses needed)
// ============================================================================

func TestResolver_ReferralNSNoGlue(t *testing.T) {
	transport := newMockTransport()
	cache := newMockCache()

	// Root server returns referral with NS but no glue
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true}},
			Questions: msg.Questions,
		}
		resp.AddAuthority(makeNSRR("example.com.", "ns1.example.com."))
		// No additional records (no glue)
		return resp
	})

	// Pre-populate cache with NS address
	aMsg := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	aMsg.AddAnswer(makeARR("ns1.example.com.", "10.0.0.5"))
	cache.Set("ns1.example.com.:1", aMsg, 300)

	// Set handler for the resolved NS address
	transport.setHandler("10.0.0.5:53", func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
		resp.AddAnswer(makeARR("example.com.", "7.7.7.7"))
		return resp
	})

	r := NewResolver(DefaultConfig(), cache, transport)
	resp, err := r.Resolve(context.Background(), "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}
	a, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatal("Expected A record")
	}
	if net.IP(a.Address[:]).String() != "7.7.7.7" {
		t.Errorf("IP = %v, want 7.7.7.7", a.Address)
	}
}

// ============================================================================
// Resolver: answer from root directly (no delegation)
// ============================================================================

func TestResolver_DirectAnswerFromRoot(t *testing.T) {
	transport := newMockTransport()
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
		resp.AddAnswer(makeARR("root.example.com.", "10.0.0.1"))
		return resp
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)
	resp, err := r.Resolve(context.Background(), "root.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}
}

// ============================================================================
// Resolver: query for CNAME type directly
// ============================================================================

func TestResolver_QueryCNAMEType(t *testing.T) {
	transport := newMockTransport()
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
		resp.AddAnswer(makeCNAMERR("alias.example.com.", "target.example.com."))
		return resp
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)
	resp, err := r.Resolve(context.Background(), "alias.example.com.", protocol.TypeCNAME)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].Type != protocol.TypeCNAME {
		t.Errorf("Answer type = %d, want CNAME", resp.Answers[0].Type)
	}
}

// ============================================================================
// Resolver: DNAME resolution failure (DNAME target unreachable)
// ============================================================================

func TestResolver_DNAMESynthesis_TargetUnreachable(t *testing.T) {
	transport := newMockTransport()

	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		qname := ""
		if len(msg.Questions) > 0 {
			qname = msg.Questions[0].Name.String()
		}
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}

		if qname == "www.example.com." {
			// Return DNAME only
			dnameTarget, _ := protocol.ParseName("example.net.")
			resp.AddAnswer(&protocol.ResourceRecord{
				Name:  mustName("example.com."),
				Type:  protocol.TypeDNAME,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataDNAME{DName: dnameTarget},
			})
		} else {
			// All other queries fail (target unreachable)
			resp.Header.Flags.RCODE = protocol.RcodeServerFailure
			resp.Header.Flags.AA = false
			resp.Answers = nil
		}
		return resp
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)
	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	// Should still return a response (with the DNAME at least)
	if resp == nil {
		t.Fatal("expected non-nil response even when target unreachable")
	}
}

// ============================================================================
// Resolver: QNAME minimization with NXDOMAIN from minimized query
// ============================================================================

func TestResolver_QminNXDomainFromMinimized(t *testing.T) {
	transport := &mockQminTransport{}
	transport.handler = func(name string, qtype uint16) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeNameError},
			},
		}
		q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
		resp.Questions = []*protocol.Question{q}
		return resp
	}

	cfg := DefaultConfig()
	cfg.QnameMinimization = true
	r := NewResolver(cfg, newMockCache(), transport)

	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// ============================================================================
// Resolver: TC bit in response
// ============================================================================

func TestResolver_TCBitResponse(t *testing.T) {
	transport := newMockTransport()
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    msg.Header.ID,
				Flags: protocol.Flags{QR: true, TC: true, RCODE: protocol.RcodeSuccess},
			},
			Questions: msg.Questions,
		}
		return resp
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)
	// sendQuery should return the TC response (transport handles fallback)
	resp, err := r.sendQuery(context.Background(), "example.com.", protocol.TypeA, "198.41.0.4:53")
	if err != nil {
		t.Fatalf("sendQuery error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if !resp.Header.Flags.TC {
		t.Error("expected TC bit to be set in response")
	}
}

// ============================================================================
// Helper transport implementations
// ============================================================================

// errorTransport always returns an error.
type errorTransport struct{}

func (t *errorTransport) QueryContext(_ context.Context, _ *protocol.Message, _ string) (*protocol.Message, error) {
	return nil, fmt.Errorf("transport error")
}

// nilResponseTransport returns nil response with no error.
type nilResponseTransport struct{}

func (t *nilResponseTransport) QueryContext(_ context.Context, _ *protocol.Message, _ string) (*protocol.Message, error) {
	return nil, nil
}

// ============================================================================
// String helper
// ============================================================================

func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && containsStr(s, sub)
}

// containsStr is a simple substring search.
func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ============================================================================
// servfail helper test
// ============================================================================

func TestServfail(t *testing.T) {
	msg := servfail("example.com.", protocol.TypeA)
	if msg == nil {
		t.Fatal("servfail returned nil")
	}
	if msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Errorf("RCODE = %d, want SERVFAIL", msg.Header.Flags.RCODE)
	}
	if !msg.Header.Flags.QR {
		t.Error("QR should be true")
	}
	if !msg.Header.Flags.RA {
		t.Error("RA should be true")
	}
	if len(msg.Questions) != 1 {
		t.Errorf("Questions len = %d, want 1", len(msg.Questions))
	}
}

// ============================================================================
// RootHint structure
// ============================================================================

func TestRootHints_AllHaveIPv6(t *testing.T) {
	hints := RootHints()
	for _, h := range hints {
		if len(h.IPv6) == 0 {
			t.Errorf("Root hint %s has no IPv6 address", h.Name)
		}
	}
}

// ============================================================================
// Resolver: resolve with cache nil message entry
// ============================================================================

func TestResolver_CacheNilMessage(t *testing.T) {
	cache := newMockCache()
	transport := newMockTransport()

	// Insert cache entry with nil message and not negative
	cache.entries["test.example.com.:1"] = &CacheEntry{
		Message:    nil,
		IsNegative: false,
	}

	r := NewResolver(DefaultConfig(), cache, transport)

	// Should proceed to actual resolution since cache entry has no usable message
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
		resp.AddAnswer(makeARR("test.example.com.", "5.5.5.5"))
		return resp
	})

	resp, err := r.Resolve(context.Background(), "test.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}
}

// ============================================================================
// Resolver: AAAA query type
// ============================================================================

func TestResolver_AAAAQuery(t *testing.T) {
	transport := newMockTransport()
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
		resp.AddAnswer(&protocol.ResourceRecord{
			Name:  mustName("example.com."),
			Type:  protocol.TypeAAAA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataAAAA{Address: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		})
		return resp
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)
	resp, err := r.Resolve(context.Background(), "example.com.", protocol.TypeAAAA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}
	if resp.Answers[0].Type != protocol.TypeAAAA {
		t.Errorf("Answer type = %d, want AAAA", resp.Answers[0].Type)
	}
}

// ============================================================================
// Resolver: use 0x20 encoding with successful verification
// ============================================================================

func TestResolver_Use0x20Success(t *testing.T) {
	transport := newMockTransport()
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions, // Echo back same questions
		}
		resp.AddAnswer(makeARR("example.com.", "1.2.3.4"))
		return resp
	})

	cfg := DefaultConfig()
	cfg.Use0x20 = true
	r := NewResolver(cfg, newMockCache(), transport)

	resp, err := r.Resolve(context.Background(), "example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answers))
	}
}

// ============================================================================
// extractDelegation with wrong data types
// ============================================================================

func TestExtractDelegation_NSWithWrongData(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  mustName("example.com."),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // Wrong data type
			},
		},
	}
	deleg, _ := r.extractDelegation(resp, ".")
	if len(deleg.nsNames) != 0 {
		t.Errorf("nsNames = %d, want 0 (data type mismatch)", len(deleg.nsNames))
	}
}

func TestExtractDelegation_AdditionalWithWrongData(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())
	resp := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{
				Name:  mustName("ns1.example.com."),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataNS{NSDName: mustName("wrong.example.com.")}, // Wrong type for A
			},
		},
	}
	deleg, _ := r.extractDelegation(resp, ".")
	// Should not crash, just skip the bad data
	if deleg == nil {
		t.Error("extractDelegation should not return nil")
	}
}

// ============================================================================
// Resolver: concurrent resolve calls (basic sanity)
// ============================================================================

func TestResolver_ConcurrentResolve(t *testing.T) {
	transport := newMockTransport()
	transport.setAllRootHandlers(func(msg *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: msg.Header.ID, Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess}},
			Questions: msg.Questions,
		}
		resp.AddAnswer(makeARR("example.com.", "1.2.3.4"))
		return resp
	})

	r := NewResolver(DefaultConfig(), newMockCache(), transport)

	var wg sync.WaitGroup
	errors := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := r.Resolve(context.Background(), "example.com.", protocol.TypeA)
			if err != nil {
				errors <- err
				return
			}
			if len(resp.Answers) != 1 {
				errors <- fmt.Errorf("expected 1 answer, got %d", len(resp.Answers))
			}
		}()
	}
	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent resolve error: %v", err)
	}
}

// ============================================================================
// fmt import is needed for errorTransport
// ============================================================================

// Need fmt for error transport - already imported above
var _ = fmt.Sprintf // ensure fmt is used

// ============================================================================
// VULN-039: bailiwick enforcement
// ============================================================================

func TestInBailiwick(t *testing.T) {
	tests := []struct {
		name string
		zone string
		want bool
	}{
		// root contains everything
		{"example.com.", ".", true},
		{"example.com.", "", true},
		{".", ".", true},

		// exact match and subdomain
		{"example.com.", "example.com.", true},
		{"www.example.com.", "example.com.", true},
		{"a.b.c.example.com.", "example.com.", true},

		// case insensitive
		{"EXAMPLE.com.", "example.com.", true},
		{"example.com.", "EXAMPLE.COM.", true},

		// trailing dot tolerance
		{"www.example.com", "example.com.", true},
		{"www.example.com.", "example.com", true},

		// siblings must NOT match
		{"other.com.", "example.com.", false},
		{"evil.net.", "com.", false},
		// partial label suffix must NOT match (the leading-dot rule)
		{"notexample.com.", "example.com.", false},
		{"myexample.com.", "example.com.", false},
	}
	for _, tt := range tests {
		got := inBailiwick(tt.name, tt.zone)
		if got != tt.want {
			t.Errorf("inBailiwick(%q, %q) = %v, want %v", tt.name, tt.zone, got, tt.want)
		}
	}
}

// Core Kaminsky defense: a response with Answer records for out-of-bailiwick
// names must not poison the cache under those names' keys.
func TestCacheResponse_SideRecord_OutOfBailiwickRejected(t *testing.T) {
	cache := newMockCache()
	r := NewResolver(DefaultConfig(), cache, newMockTransport())

	// Simulate: we queried ns.attacker.com (authoritative for attacker.com)
	// for the name attacker.com/A. The evil response answers attacker.com
	// correctly AND bundles a poison A record for victim-bank.com.
	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	resp.AddAnswer(makeARR("attacker.com.", "1.2.3.4"))           // in-bailiwick: legit
	resp.AddAnswer(makeARR("www.victim-bank.com.", "6.6.6.6"))    // out-of-bailiwick: poison

	r.cacheResponse("attacker.com.", protocol.TypeA, resp, "attacker.com.")

	// Primary key (the query we actually asked) must be cached.
	mainKey := cacheKey("attacker.com.", protocol.TypeA)
	found := false
	for _, k := range cache.sets {
		if k == mainKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("primary cache entry missing for %s", mainKey)
	}

	// Poison side-record key must NOT have been cached.
	poisonKey := cacheKey("www.victim-bank.com.", protocol.TypeA)
	for _, k := range cache.sets {
		if k == poisonKey {
			t.Fatalf("out-of-bailiwick side record was cached under key %q (Kaminsky-class bug)", k)
		}
	}
}

// In-bailiwick side records (typical: A records bundled with a CNAME answer
// that resolve to the same zone) should still be cached, so the fix preserves
// the resolution-speed optimization for legitimate cases.
func TestCacheResponse_SideRecord_InBailiwickAccepted(t *testing.T) {
	cache := newMockCache()
	r := NewResolver(DefaultConfig(), cache, newMockTransport())

	resp := &protocol.Message{
		Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess}},
	}
	resp.AddAnswer(makeARR("example.com.", "1.2.3.4"))
	resp.AddAnswer(makeARR("www.example.com.", "5.6.7.8")) // same zone, legit

	r.cacheResponse("example.com.", protocol.TypeA, resp, "example.com.")

	wantKey := cacheKey("www.example.com.", protocol.TypeA)
	found := false
	for _, k := range cache.sets {
		if k == wantKey {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("in-bailiwick side record %q should have been cached; keys=%v", wantKey, cache.sets)
	}
}

// extractDelegation must reject NS records whose owner is not in bailiwick of
// the querier's current zone cut — a .com server cannot delegate .net.
func TestExtractDelegation_RejectsOutOfBailiwickNS(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())

	// Querier believes it is at a .com server (zoneCut = "com.").
	// An evil referral tries to redirect resolution of evil.net.
	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			makeNSRR("evil.net.", "ns.attacker.example."), // out-of-bailiwick for .com
			makeNSRR("example.com.", "ns1.example.com."),  // in-bailiwick: legit
		},
		Additionals: []*protocol.ResourceRecord{
			makeARR("ns1.example.com.", "1.2.3.4"),
			makeARR("ns.attacker.example.", "6.6.6.6"), // should never be collected
		},
	}

	deleg, newZoneCut := r.extractDelegation(resp, "com.")

	// Only the in-bailiwick delegation survives.
	if len(deleg.nsNames) != 1 {
		t.Fatalf("nsNames = %d, want 1 (out-of-bailiwick NS must be dropped). got=%v",
			len(deleg.nsNames), deleg.nsNames)
	}
	if deleg.nsNames[0] != "ns1.example.com." {
		t.Errorf("surviving nsName = %q, want %q", deleg.nsNames[0], "ns1.example.com.")
	}
	if newZoneCut != "example.com." {
		t.Errorf("newZoneCut = %q, want %q", newZoneCut, "example.com.")
	}

	// The attacker's glue must not be in the address map under any key.
	if _, ok := deleg.addrs["ns.attacker.example."]; ok {
		t.Error("attacker glue was accepted into delegation (should be dropped)")
	}
}

// extractDelegation must also reject Additional records whose owner is in
// bailiwick but is NOT actually a listed NS target (drive-by records).
func TestExtractDelegation_RejectsNonNSTargetAdditional(t *testing.T) {
	r := NewResolver(DefaultConfig(), nil, newMockTransport())

	resp := &protocol.Message{
		Authorities: []*protocol.ResourceRecord{
			makeNSRR("example.com.", "ns1.example.com."),
		},
		Additionals: []*protocol.ResourceRecord{
			makeARR("ns1.example.com.", "1.2.3.4"),        // legit glue
			makeARR("www.example.com.", "6.6.6.6"),        // in-bailiwick, but not an NS target: drive-by
		},
	}

	deleg, _ := r.extractDelegation(resp, "com.")

	if len(deleg.addrs["ns1.example.com."]) != 1 {
		t.Errorf("ns1 glue = %v, want one entry", deleg.addrs["ns1.example.com."])
	}
	if _, ok := deleg.addrs["www.example.com."]; ok {
		t.Error("non-NS-target Additional was accepted (drive-by drop failed)")
	}
}
