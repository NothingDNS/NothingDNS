package resolver

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Regression coverage for the findCNAME owner-matching fix: the function
// must return the target of the CNAME RRset OWNED by the queried name, not
// the first CNAME record in the answer section. An unrelated CNAME (multi-
// name answers, additional data, hostile injection) must never redirect the
// chase (RFC 1034 §4.3.2).

func TestFindCNAME_IgnoresUnrelatedOwner(t *testing.T) {
	answers := []*protocol.ResourceRecord{
		makeCNAMERR("other.example.com.", "attacker.example.net."),
		makeCNAMERR("www.example.com.", "real.example.net."),
	}
	if got := findCNAME(answers, "www.example.com."); got != "real.example.net." {
		t.Errorf("findCNAME = %q, want %q (must match the queried name's owner)", got, "real.example.net.")
	}
}

func TestFindCNAME_NoOwnerMatch(t *testing.T) {
	answers := []*protocol.ResourceRecord{
		makeCNAMERR("other.example.com.", "attacker.example.net."),
	}
	if got := findCNAME(answers, "www.example.com."); got != "" {
		t.Errorf("findCNAME = %q, want empty (no CNAME owned by the queried name)", got)
	}
}

func TestFindCNAME_OwnerMatchCaseInsensitive(t *testing.T) {
	// RFC 4343: domain names compare case-insensitively.
	answers := []*protocol.ResourceRecord{
		makeCNAMERR("WWW.Example.COM.", "real.example.net."),
	}
	if got := findCNAME(answers, "www.example.com."); got != "real.example.net." {
		t.Errorf("findCNAME = %q, want %q (owner match is case-insensitive)", got, "real.example.net.")
	}
}

func TestFindCNAME_OwnerMatchTrailingDotTolerant(t *testing.T) {
	answers := []*protocol.ResourceRecord{
		makeCNAMERR("www.example.com.", "real.example.net."),
	}
	if got := findCNAME(answers, "www.example.com"); got != "real.example.net." {
		t.Errorf("findCNAME = %q, want %q (queried name without trailing dot)", got, "real.example.net.")
	}
}

// TestResolver_CNAMEChaseIgnoresUnrelatedOwner exercises the full production
// path (Resolve -> iterative resolve -> CNAME chase): an authority answer
// that lists an unrelated CNAME ahead of the queried name's CNAME must not
// cause the resolver to query the unrelated target, and the final answer
// must still carry the terminal A record of the queried name's real chain.
func TestResolver_CNAMEChaseIgnoresUnrelatedOwner(t *testing.T) {
	transport := &recordingTransport{}

	r := NewResolver(DefaultConfig(), newMockCache(), transport)

	resp, err := r.Resolve(context.Background(), "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	for _, q := range transport.queries {
		if q == "attacker.example.net." {
			t.Errorf("resolver issued an upstream query for unrelated CNAME target %q; query log: %v", q, transport.queries)
		}
	}

	var sawCNAME, sawTerminalA bool
	for _, rr := range resp.Answers {
		if rr == nil || rr.Name == nil {
			continue
		}
		switch rr.Type {
		case protocol.TypeCNAME:
			if rr.Name.String() == "www.example.com." {
				if cn, ok := rr.Data.(*protocol.RDataCNAME); ok && cn != nil && cn.CName != nil {
					if cn.CName.String() == "real.example.net." {
						sawCNAME = true
					}
				}
			}
		case protocol.TypeA:
			if rr.Name.String() == "real.example.net." {
				sawTerminalA = true
			}
		}
	}
	if !sawCNAME {
		t.Error("final answer is missing the queried name's CNAME (www.example.com -> real.example.net)")
	}
	if !sawTerminalA {
		t.Error("final answer is missing the terminal A record for real.example.net")
	}
}

// recordingTransport answers every upstream query out of a fixed map and
// records the question names it was asked. It stands in for the root/authority
// chain: the resolver starts every resolution at the root hints, so this
// transport answers for whatever name the resolver asks about.
type recordingTransport struct {
	queries []string
}

func (t *recordingTransport) QueryContext(_ context.Context, msg *protocol.Message, _ string) (*protocol.Message, error) {
	qname := ""
	if len(msg.Questions) > 0 && msg.Questions[0] != nil && msg.Questions[0].Name != nil {
		qname = msg.Questions[0].Name.String()
	}
	t.queries = append(t.queries, qname)

	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    msg.Header.ID,
			Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess},
		},
		Questions: msg.Questions,
	}
	switch qname {
	case "www.example.com.":
		// Unrelated CNAME listed FIRST; the queried name's CNAME second.
		resp.AddAnswer(makeCNAMERR("other.example.com.", "attacker.example.net."))
		resp.AddAnswer(makeCNAMERR("www.example.com.", "real.example.net."))
	case "real.example.net.":
		resp.AddAnswer(makeARR("real.example.net.", "1.2.3.4"))
	case "attacker.example.net.":
		resp.AddAnswer(makeARR("attacker.example.net.", "6.6.6.6"))
	}
	return resp, nil
}