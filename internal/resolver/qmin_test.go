package resolver

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func mustParseName(s string) *protocol.Name {
	n, err := protocol.ParseName(s)
	if err != nil {
		panic("mustParseName: " + err.Error())
	}
	return n
}

func TestMinimizedName(t *testing.T) {
	tests := []struct {
		target  string
		zoneCut string
		want    string
	}{
		// Root zone cut: reveal only TLD
		{"www.example.com.", ".", "com."},
		// TLD zone cut: reveal SLD
		{"www.example.com.", "com.", "example.com."},
		// SLD zone cut: reveal full name (we're there)
		{"www.example.com.", "example.com.", "www.example.com."},
		// Already at target
		{"example.com.", "example.com.", "example.com."},
		// Deep subdomain
		{"a.b.c.d.example.com.", "com.", "example.com."},
		{"a.b.c.d.example.com.", "example.com.", "d.example.com."},
		{"a.b.c.d.example.com.", "d.example.com.", "c.d.example.com."},
		// Single-label target from root
		{"com.", ".", "com."},
		// Target not under zone cut
		{"example.org.", "com.", "example.org."},
		// DNS names are case-insensitive; mixed-case input must still minimize.
		{"WWW.Example.COM.", "com.", "example.com."},
		{"WWW.Example.COM.", "Example.COM.", "www.example.com."},
	}

	for _, tt := range tests {
		got := minimizedName(tt.target, tt.zoneCut)
		if got != tt.want {
			t.Errorf("minimizedName(%q, %q) = %q, want %q",
				tt.target, tt.zoneCut, got, tt.want)
		}
	}
}

func TestIsMinimizedTarget(t *testing.T) {
	if !isMinimizedTarget("www.example.com.", "www.example.com.") {
		t.Error("expected true for matching names")
	}
	if !isMinimizedTarget("WWW.Example.COM.", "www.example.com.") {
		t.Error("expected true for case-insensitive match")
	}
	if isMinimizedTarget("example.com.", "www.example.com.") {
		t.Error("expected false for non-matching names")
	}
}

// mockQminTransport records queries to verify minimization behavior.
type mockQminTransport struct {
	queries []qminQuery
	handler func(name string, qtype uint16) *protocol.Message
}

type qminQuery struct {
	name  string
	qtype uint16
}

func (t *mockQminTransport) QueryContext(_ context.Context, msg *protocol.Message, _ string) (*protocol.Message, error) {
	q := msg.Questions[0]
	t.queries = append(t.queries, qminQuery{name: q.Name.String(), qtype: q.QType})
	if t.handler != nil {
		resp := t.handler(q.Name.String(), q.QType)
		// Echo the query's transaction ID. sendQuery() now rejects
		// mismatched TXIDs (security: prevents spoofed/replayed responses
		// from being accepted as the answer to a chain-of-trust fetch).
		if resp != nil {
			resp.Header.ID = msg.Header.ID
		}
		return resp, nil
	}
	return nil, nil
}

func TestResolverQnameMinimization(t *testing.T) {
	transport := &mockQminTransport{}

	// Simulate the delegation chain:
	// Query: www.example.com. A
	// Step 1: query "com." NS → referral to com. servers
	// Step 2: query "example.com." NS → referral to example.com. servers
	// Step 3: query "www.example.com." A → answer
	transport.handler = func(name string, qtype uint16) *protocol.Message {
		switch {
		case name == "com." && qtype == protocol.TypeNS:
			// Referral to com. servers
			resp := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{QR: true},
				},
			}
			q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
			resp.Questions = []*protocol.Question{q}
			resp.Authorities = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("com."),
					Type:  protocol.TypeNS,
					Class: protocol.ClassIN,
					TTL:   86400,
					Data:  &protocol.RDataNS{NSDName: mustParseName("a.gtld-servers.net.")},
				},
			}
			resp.Additionals = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("a.gtld-servers.net."),
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   86400,
					Data:  &protocol.RDataA{Address: [4]byte{192, 5, 6, 30}},
				},
			}
			return resp

		case name == "example.com." && qtype == protocol.TypeNS:
			// Referral to example.com. servers
			resp := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{QR: true},
				},
			}
			q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
			resp.Questions = []*protocol.Question{q}
			resp.Authorities = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("example.com."),
					Type:  protocol.TypeNS,
					Class: protocol.ClassIN,
					TTL:   86400,
					Data:  &protocol.RDataNS{NSDName: mustParseName("ns1.example.com.")},
				},
			}
			resp.Additionals = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("ns1.example.com."),
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   86400,
					Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
				},
			}
			return resp

		case name == "www.example.com." && qtype == protocol.TypeA:
			// Final answer
			resp := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{QR: true, AA: true},
				},
			}
			q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
			resp.Questions = []*protocol.Question{q}
			resp.Answers = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("www.example.com."),
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
				},
			}
			return resp
		}

		// Default: SERVFAIL
		resp := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeServerFailure},
			},
		}
		return resp
	}

	cfg := DefaultConfig()
	cfg.QnameMinimization = true

	r := NewResolver(cfg, nil, transport)

	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	// Verify the queries were minimized
	if len(transport.queries) < 3 {
		t.Fatalf("expected at least 3 queries, got %d: %+v", len(transport.queries), transport.queries)
	}

	// First query should be for "com." NS (minimized from root)
	if transport.queries[0].name != "com." || transport.queries[0].qtype != protocol.TypeNS {
		t.Errorf("query[0] = %s %d, want com. NS",
			transport.queries[0].name, transport.queries[0].qtype)
	}

	// Second query should be for "example.com." NS (minimized from com.)
	if transport.queries[1].name != "example.com." || transport.queries[1].qtype != protocol.TypeNS {
		t.Errorf("query[1] = %s %d, want example.com. NS",
			transport.queries[1].name, transport.queries[1].qtype)
	}

	// Final query should be for "www.example.com." A (full name, original type)
	last := transport.queries[len(transport.queries)-1]
	if last.name != "www.example.com." || last.qtype != protocol.TypeA {
		t.Errorf("last query = %s %d, want www.example.com. A",
			last.name, last.qtype)
	}

	// Verify we got the right answer
	if len(resp.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answers))
	}
	a, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok {
		t.Fatal("expected A record answer")
	}
	if a.Address != [4]byte{93, 184, 216, 34} {
		t.Errorf("answer IP = %v, want 93.184.216.34", a.Address)
	}
}

func TestResolverQnameMinimizationNSAnswerRequeriesFullName(t *testing.T) {
	transport := &mockQminTransport{}

	transport.handler = func(name string, qtype uint16) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.Flags{QR: true, AA: true},
			},
		}
		q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
		resp.Questions = []*protocol.Question{q}

		switch {
		case name == "com." && qtype == protocol.TypeNS:
			resp.Authorities = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("com."),
					Type:  protocol.TypeNS,
					Class: protocol.ClassIN,
					TTL:   86400,
					Data:  &protocol.RDataNS{NSDName: mustParseName("a.gtld-servers.net.")},
				},
			}
			resp.Additionals = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("a.gtld-servers.net."),
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   86400,
					Data:  &protocol.RDataA{Address: [4]byte{192, 5, 6, 30}},
				},
			}
			return resp

		case name == "example.com." && qtype == protocol.TypeNS:
			resp.Answers = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("example.com."),
					Type:  protocol.TypeNS,
					Class: protocol.ClassIN,
					TTL:   3600,
					Data:  &protocol.RDataNS{NSDName: mustParseName("ns1.example.com.")},
				},
			}
			return resp

		case name == "www.example.com." && qtype == protocol.TypeA:
			resp.Answers = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("www.example.com."),
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
				},
			}
			return resp
		}

		resp.Header.Flags.RCODE = protocol.RcodeServerFailure
		return resp
	}

	cfg := DefaultConfig()
	cfg.QnameMinimization = true

	r := NewResolver(cfg, nil, transport)
	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}

	if len(transport.queries) != 3 {
		t.Fatalf("queries = %+v, want exactly 3 minimized/full queries", transport.queries)
	}
	last := transport.queries[2]
	if last.name != "www.example.com." || last.qtype != protocol.TypeA {
		t.Fatalf("last query = %s %d, want www.example.com. A", last.name, last.qtype)
	}
	if len(resp.Answers) != 1 || resp.Answers[0].Type != protocol.TypeA {
		t.Fatalf("response answers = %+v, want final A answer not minimized NS answer", resp.Answers)
	}
}

func TestResolverWithoutQnameMinimization(t *testing.T) {
	transport := &mockQminTransport{}
	transport.handler = func(name string, qtype uint16) *protocol.Message {
		if name == "www.example.com." && qtype == protocol.TypeA {
			resp := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{QR: true, AA: true},
				},
			}
			q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
			resp.Questions = []*protocol.Question{q}
			resp.Answers = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("www.example.com."),
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
				},
			}
			return resp
		}
		// Return answer for any name (simple case: root server returns answer directly)
		resp := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.Flags{QR: true, AA: true},
			},
		}
		q, _ := protocol.NewQuestion(name, qtype, protocol.ClassIN)
		resp.Questions = []*protocol.Question{q}
		resp.Answers = []*protocol.ResourceRecord{
			{
				Name:  mustParseName(name),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
			},
		}
		return resp
	}

	cfg := DefaultConfig()
	cfg.QnameMinimization = false

	r := NewResolver(cfg, nil, transport)
	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}

	// Without QMIN, the first query reveals the full name
	if len(transport.queries) == 0 {
		t.Fatal("expected at least 1 query")
	}
	if transport.queries[0].name != "www.example.com." {
		t.Errorf("without QMIN, first query should be full name, got %q",
			transport.queries[0].name)
	}
	if resp == nil || len(resp.Answers) == 0 {
		t.Fatal("expected answer")
	}
}

// TestResolverQnameMinimizationENTNodata verifies that a NODATA reply to an
// intermediate minimized NS probe (an empty non-terminal, RFC 7816 §3) does
// NOT terminate resolution: the resolver must step one label deeper and
// eventually answer the full query, instead of returning the probe's NODATA
// and poisoning the negative cache for the full name.
func TestResolverQnameMinimizationENTNodata(t *testing.T) {
	transport := &mockQminTransport{}

	referral := func(zone, ns string, ip [4]byte) *protocol.Message {
		resp := &protocol.Message{
			Header: protocol.Header{Flags: protocol.Flags{QR: true}},
		}
		resp.Authorities = []*protocol.ResourceRecord{
			{
				Name:  mustParseName(zone),
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   86400,
				Data:  &protocol.RDataNS{NSDName: mustParseName(ns)},
			},
		}
		resp.Additionals = []*protocol.ResourceRecord{
			{
				Name:  mustParseName(ns),
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   86400,
				Data:  &protocol.RDataA{Address: ip},
			},
		}
		return resp
	}

	transport.handler = func(name string, qtype uint16) *protocol.Message {
		switch {
		case name == "com." && qtype == protocol.TypeNS:
			return referral("com.", "a.gtld-servers.net.", [4]byte{192, 5, 6, 30})
		case name == "example.com." && qtype == protocol.TypeNS:
			return referral("example.com.", "ns1.example.com.", [4]byte{93, 184, 216, 1})
		case name == "dept.example.com." && qtype == protocol.TypeNS:
			// Empty non-terminal: the name exists but has no NS RRset.
			// Authoritative NODATA — NOERROR, zero answers, SOA authority.
			resp := &protocol.Message{
				Header: protocol.Header{Flags: protocol.Flags{QR: true, AA: true}},
			}
			resp.Authorities = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("example.com."),
					Type:  protocol.TypeSOA,
					Class: protocol.ClassIN,
					TTL:   900,
					Data: &protocol.RDataSOA{
						MName: mustParseName("ns1.example.com."),
						RName: mustParseName("hostmaster.example.com."),
					},
				},
			}
			return resp
		case name == "www.dept.example.com." && qtype == protocol.TypeA:
			resp := &protocol.Message{
				Header: protocol.Header{Flags: protocol.Flags{QR: true, AA: true}},
			}
			resp.Answers = []*protocol.ResourceRecord{
				{
					Name:  mustParseName("www.dept.example.com."),
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
				},
			}
			return resp
		}
		return &protocol.Message{
			Header: protocol.Header{Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeServerFailure}},
		}
	}

	cfg := DefaultConfig()
	cfg.QnameMinimization = true
	r := NewResolver(cfg, nil, transport)

	resp, err := r.Resolve(context.Background(), "www.dept.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("RCODE = %d, want NOERROR", resp.Header.Flags.RCODE)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("answers = %d, want 1 (intermediate NODATA must not terminate resolution)", len(resp.Answers))
	}
	a, ok := resp.Answers[0].Data.(*protocol.RDataA)
	if !ok || a.Address != [4]byte{93, 184, 216, 34} {
		t.Fatalf("unexpected answer data: %+v", resp.Answers[0].Data)
	}
}

// TestResolverQnameMinimizationNXDomainQuestionRewrite verifies that when an
// intermediate minimized probe gets NXDOMAIN (terminal per RFC 8020), the
// returned response carries the client's original question, not the probe's.
func TestResolverQnameMinimizationNXDomainQuestionRewrite(t *testing.T) {
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
	r := NewResolver(cfg, nil, transport)

	resp, err := r.Resolve(context.Background(), "www.gone.example.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeNameError {
		t.Fatalf("RCODE = %d, want NXDOMAIN", resp.Header.Flags.RCODE)
	}
	if len(resp.Questions) != 1 {
		t.Fatalf("questions = %d, want 1", len(resp.Questions))
	}
	if got := resp.Questions[0].Name.String(); got != "www.gone.example." {
		t.Fatalf("question name = %q, want client's original %q", got, "www.gone.example.")
	}
	if resp.Questions[0].QType != protocol.TypeA {
		t.Fatalf("question qtype = %d, want A", resp.Questions[0].QType)
	}
}
