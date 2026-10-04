// Round-020 proof: a server with no upstream and no iterative resolver cannot
// know whether an out-of-zone name exists, so it must answer SERVFAIL (RCODE 2)
// — not NXDOMAIN.
//
// CONTRACT. RFC 1035 §4.1.1 defines RCODE 2 (SERVFAIL) as "the name server was
// unable to process this query due to a problem with the name server", and
// RCODE 3 (NXDOMAIN) as a definitive "the domain name referenced in the query
// does not exist". A server that has no path to resolve a name has no basis for
// the second claim, and the claim is not harmless: RFC 2308 §5 makes negative
// answers cacheable, and RFC 8020 resolvers extend a cached NXDOMAIN to every
// name below it — exactly the harm this package's own empty-non-terminal
// comment warns about ("a cached NXDOMAIN for b.example.com makes them refuse
// a.b.example.com too", zone.go NodeExists).
//
// The rest of this pipeline already follows the rule: when the upstream is
// unavailable, upstreamStage answers SERVFAIL + EDE Network Error
// (pipeline_stages.go:632), because "cannot resolve right now" is a transient
// failure, not a nonexistence proof.
//
// DEFECT. noUpstreamStage (pipeline_stages.go:874-883) — the terminal stage that
// runs when neither an upstream nor an iterative resolver is configured —
// answers RcodeNameError (NXDOMAIN) with EDE Not Authoritative for every name
// outside the server's own zones. A pure authoritative deployment (or one whose
// upstream config was lost) therefore tells every client, and every downstream
// cache, that real names do not exist.
package main

import (
	"context"
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	rr20InZoneOwner  = "www.example.com."
	rr20InZoneAddr   = "192.0.2.9"
	rr20OutsideOwner = "www.other.example.net."
)

// rr20Writer captures the response the pipeline hands to the transport.
type rr20Writer struct {
	got *protocol.Message
}

func (w *rr20Writer) Write(msg *protocol.Message) (int, error) {
	w.got = msg
	return 0, nil
}

func (w *rr20Writer) ClientInfo() *server.ClientInfo {
	return &server.ClientInfo{
		Addr:     &net.UDPAddr{IP: net.ParseIP("10.1.2.3"), Port: 12345},
		Protocol: "udp",
	}
}

func (w *rr20Writer) MaxSize() int { return 4096 }

// rr20Handler is a server with one authoritative zone and NO upstream and NO
// iterative resolver — the shape of a pure authoritative deployment (or one
// whose upstream configuration is missing).
func rr20Handler() *integratedHandler {
	h := newTestHandler()
	z := &zone.Zone{
		Origin: "example.com.",
		SOA: &zone.SOARecord{
			Name: "example.com.", TTL: 3600, MName: "ns1.example.com.", RName: "hostmaster.example.com.",
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
		},
		Records: map[string][]zone.Record{
			rr20InZoneOwner: {{Name: rr20InZoneOwner, TTL: 300, Class: "IN", Type: "A", RData: rr20InZoneAddr}},
		},
	}
	h.zones = map[string]*zone.Zone{"example.com.": z}
	h.zoneProvider = NewMultiZoneProvider(h.zones, nil, nil, nil)
	return h
}

func rr20Run(t *testing.T, h *integratedHandler, qname string) *protocol.Message {
	t.Helper()
	w := &rr20Writer{}
	msg := newTestQuery(t, qname, protocol.TypeA)
	NewPipeline(h).ServeDNS(h, w, msg)
	if w.got == nil {
		t.Fatalf("pipeline produced no response for %s", qname)
	}
	return w.got
}

// TestRound020NoUpstreamDoesNotClaimNonexistence is the defect case.
func TestRound020NoUpstreamDoesNotClaimNonexistence(t *testing.T) {
	h := rr20Handler()

	resp := rr20Run(t, h, rr20OutsideOwner)
	rcode := resp.Header.Flags.RCODE
	if rcode != protocol.RcodeServerFailure {
		t.Fatalf("no upstream and no resolver are configured, so the server cannot know whether "+
			"%s exists; it must answer SERVFAIL (RFC 1035 §4.1.1: \"the name server was unable to "+
			"process this query due to a problem with the name server\"). Got rcode=%d (%s) AA=%v — "+
			"NXDOMAIN is a definitive nonexistence claim, it is cacheable (RFC 2308 §5), and RFC 8020 "+
			"resolvers extend it to every name below the owner, so a real name is reported as "+
			"nonexistent downstream. The same pipeline answers SERVFAIL + EDE Network Error for the "+
			"equivalent \"cannot resolve\" case when an upstream is configured but unreachable "+
			"(pipeline_stages.go:632).",
			rr20OutsideOwner, rcode, protocol.RcodeString(int(rcode)), resp.Header.Flags.AA)
	}
}

// TestRound020NoUpstreamControls pins that the pipeline still answers normally
// for the server's own zones, so the assertion above is not a broken harness.
func TestRound020NoUpstreamControls(t *testing.T) {
	h := rr20Handler()

	resp := rr20Run(t, h, rr20InZoneOwner)
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Fatalf("control: authoritative answer for %s = rcode %d (%s), want NOERROR",
			rr20InZoneOwner, resp.Header.Flags.RCODE, protocol.RcodeString(int(resp.Header.Flags.RCODE)))
	}
	found := false
	for _, rr := range resp.Answers {
		if rr != nil && rr.Type == protocol.TypeA && rr.Name != nil && rr.Name.String() == rr20InZoneOwner {
			if a, ok := rr.Data.(*protocol.RDataA); ok && a != nil {
				if net.IP(a.Address[:]).String() == rr20InZoneAddr {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("control: authoritative answer for %s did not carry A %s", rr20InZoneOwner, rr20InZoneAddr)
	}

	// The stage itself must also be the one answering the out-of-zone query, so
	// the defect is attributed to the right place.
	w := &rr20Writer{}
	q := &query{msg: newTestQuery(t, rr20OutsideOwner, protocol.TypeA), currentWriter: w}
	q.q = q.msg.Questions[0]
	q.qname = rr20OutsideOwner
	q.qtype = protocol.TypeA
	handled, err := noUpstreamStage(h)(context.Background(), q, w)
	if err != nil {
		t.Fatalf("control: noUpstreamStage error: %v", err)
	}
	if !handled || w.got == nil {
		t.Fatal("control: noUpstreamStage did not answer the out-of-zone query")
	}
}
