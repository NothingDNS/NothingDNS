package main

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestLoopbackReverseNamesNeverFallThrough(t *testing.T) {
	names := []string{
		"1.0.0.127.in-addr.arpa.",
		"1." + strings.Repeat("0.", 31) + "ip6.arpa.",
	}
	for _, name := range names {
		for _, qtype := range []uint16{protocol.TypeA, protocol.TypeAAAA, protocol.TypeTXT} {
			q := newTestQuery(t, name, qtype)
			resp := specialUseAnswer(q, q.Questions[0], name)
			if resp == nil {
				t.Fatalf("%s type %d fell through to upstream", name, qtype)
			}
			if resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 0 || len(resp.Authorities) != 1 {
				t.Fatalf("%s type %d = rcode %d, %d answers, %d authorities; want authoritative NODATA with SOA",
					name, qtype, resp.Header.Flags.RCODE, len(resp.Answers), len(resp.Authorities))
			}
		}
	}
}

func TestNonLoopbackReverseNameStillFallsThrough(t *testing.T) {
	name := "2.0.0.127.in-addr.arpa."
	q := newTestQuery(t, name, protocol.TypeA)
	if resp := specialUseAnswer(q, q.Questions[0], name); resp != nil {
		t.Fatalf("ordinary reverse name was handled locally: %#v", resp)
	}
}
