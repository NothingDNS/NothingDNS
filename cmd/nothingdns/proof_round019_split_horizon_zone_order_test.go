// Round-019 proof: a split-horizon view that holds overlapping zones (a parent
// plus a child) must answer from the MOST SPECIFIC (child) zone, deterministically.
//
// CONTRACT. The zone-lookup abstraction in this package documents the ordering
// it guarantees: "FindZones returns all zones that could match the given domain
// name, sorted by specificity (longest match first)" (zone_provider.go:16-18),
// and MultiZoneProvider.FindZones implements it (sortZonesByLength,
// zone_provider.go:226). authoritativeStage relies on that order: it takes the
// first zone whose handleAuthoritative reports handled (pipeline_stages.go:441-446).
// The same rule follows from RFC 1034 §4.3.2: the server answers from the zone
// it is authoritative for, and when it serves both a parent and a child the
// child (closest enclosing zone) owns names below the cut.
//
// DEFECT. splitHorizonStage does not use the provider at all: it iterates
// h.viewZones[view.Name], a map[string]*zone.Zone, filtering with a bare
// isSubdomain test and NO ordering (pipeline_stages.go:328-338). Go randomizes
// map iteration order, so with a view holding both example.com. (which carries
// the delegation NS RRset for sub.example.com.) and sub.example.com.:
//
//   - child visited first  -> the child answers authoritatively (correct)
//   - parent visited first -> handleAuthoritative's Step 0 finds the delegation
//     (authoritative.go:26-45) and answers with a REFERRAL for a name the
//     server is authoritative for, and the stage returns handled=true
//
// The same query therefore alternates between an authoritative answer and a
// referral. The test drives the production stage 200 times and requires the
// child's answer every time.
package main

import (
	"context"
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/filter"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

const (
	rr19ViewName   = "internal"
	rr19ClientIP   = "10.1.2.3"
	rr19ChildOwner = "www.sub.example.com."
	rr19ChildAddr  = "192.0.2.7"
	rr19ParentAddr = "192.0.2.1"
	rr19Iterations = 200
)

// rr19Writer captures the message the stage writes.
type rr19Writer struct {
	got *protocol.Message
}

func (w *rr19Writer) Write(msg *protocol.Message) (int, error) {
	w.got = msg
	return 0, nil
}

func (w *rr19Writer) ClientInfo() *server.ClientInfo {
	return &server.ClientInfo{
		Addr:     &net.UDPAddr{IP: net.ParseIP(rr19ClientIP), Port: 12345},
		Protocol: "udp",
	}
}

func (w *rr19Writer) MaxSize() int { return 4096 }

// rr19ViewHandler builds a handler whose single view holds a parent zone that
// delegates sub.example.com. plus the child zone itself — the overlapping-zone
// shape an operator creates when a view carries both a company zone and a
// sub-zone.
func rr19ViewHandler(t *testing.T) *integratedHandler {
	t.Helper()

	soa := func(origin string) *zone.SOARecord {
		return &zone.SOARecord{
			Name: origin, TTL: 3600, MName: "ns1." + origin, RName: "hostmaster." + origin,
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
		}
	}

	parent := &zone.Zone{
		Origin: "example.com.",
		SOA:    soa("example.com."),
		Records: map[string][]zone.Record{
			"example.com.":     {{Name: "example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.example.com."}},
			"ns1.example.com.": {{Name: "ns1.example.com.", TTL: 300, Class: "IN", Type: "A", RData: rr19ParentAddr}},
			// The zone cut: this is what makes the parent answer with a referral
			// for every name below sub.example.com.
			"sub.example.com.":     {{Name: "sub.example.com.", TTL: 3600, Class: "IN", Type: "NS", RData: "ns1.sub.example.com."}},
			"ns1.sub.example.com.": {{Name: "ns1.sub.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.2"}},
		},
	}
	child := &zone.Zone{
		Origin: "sub.example.com.",
		SOA:    soa("sub.example.com."),
		Records: map[string][]zone.Record{
			rr19ChildOwner: {{Name: rr19ChildOwner, TTL: 300, Class: "IN", Type: "A", RData: rr19ChildAddr}},
		},
	}

	sh, err := filter.NewSplitHorizon([]filter.ViewConfig{{
		Name:         rr19ViewName,
		MatchClients: []string{rr19ClientIP + "/32"},
	}})
	if err != nil {
		t.Fatalf("NewSplitHorizon: %v", err)
	}

	h := newTestHandler()
	h.splitHorizon = sh
	h.viewZones = map[string]map[string]*zone.Zone{
		rr19ViewName: {
			"example.com.":     parent,
			"sub.example.com.": child,
		},
	}
	return h
}

// rr19Query builds the pipeline query the stage receives.
func rr19Query(t *testing.T, qname string) *query {
	t.Helper()
	msg := newTestQuery(t, qname, protocol.TypeA)
	if len(msg.Questions) == 0 {
		t.Fatalf("newTestQuery(%q) produced no question", qname)
	}
	w := &rr19Writer{}
	return &query{
		msg:           msg,
		q:             msg.Questions[0],
		qname:         qname,
		qtype:         protocol.TypeA,
		currentWriter: w,
	}
}

func rr19ARecord(msg *protocol.Message, owner string) string {
	if msg == nil {
		return ""
	}
	for _, rr := range msg.Answers {
		if rr == nil || rr.Name == nil || rr.Type != protocol.TypeA {
			continue
		}
		if rr.Name.String() != owner {
			continue
		}
		if a, ok := rr.Data.(*protocol.RDataA); ok && a != nil {
			return net.IP(a.Address[:]).String()
		}
	}
	return ""
}

// TestRound019ViewOverlappingZonesAnswerFromMostSpecific is the defect case: the
// child zone in the view owns www.sub.example.com. and must answer it every time.
func TestRound019ViewOverlappingZonesAnswerFromMostSpecific(t *testing.T) {
	h := rr19ViewHandler(t)
	stage := splitHorizonStage(h)

	for i := 0; i < rr19Iterations; i++ {
		q := rr19Query(t, rr19ChildOwner)
		w := q.currentWriter.(*rr19Writer)
		handled, err := stage(context.Background(), q, w)
		if err != nil {
			t.Fatalf("iteration %d: splitHorizonStage error: %v", i, err)
		}
		if !handled {
			t.Fatalf("iteration %d: the view holds a zone for %s but the stage did not answer it",
				i, rr19ChildOwner)
		}
		got := rr19ARecord(w.got, rr19ChildOwner)
		if got != rr19ChildAddr {
			var authority []string
			aa, rcode := false, uint8(0)
			if w.got != nil {
				aa = w.got.Header.Flags.AA
				rcode = w.got.Header.Flags.RCODE
				for _, rr := range w.got.Authorities {
					if rr != nil && rr.Name != nil {
						authority = append(authority, protocol.TypeString(rr.Type)+"@"+rr.Name.String())
					}
				}
			}
			t.Fatalf("iteration %d: the view holds both example.com. and sub.example.com., and "+
				"sub.example.com. owns %s, so the child zone must answer with A %s (AA=1). Got A=%q "+
				"AA=%v rcode=%d authority=%v — the parent zone answered with a delegation referral "+
				"because splitHorizonStage iterates viewZones (a map) without the specificity ordering "+
				"that ZoneProvider.FindZones documents (zone_provider.go:16-18) and authoritativeStage "+
				"relies on (pipeline_stages.go:441-446). The answer for this query therefore depends on "+
				"Go's randomized map iteration order.",
				i, rr19ChildOwner, rr19ChildAddr, got, aa, rcode, authority)
		}
	}
}

// TestRound019ViewZoneOrderControls pins the neighbouring paths: a name that only
// the parent zone owns must still be answered by the parent, and a name that
// matches no view zone must fall through to the rest of the pipeline.
func TestRound019ViewZoneOrderControls(t *testing.T) {
	h := rr19ViewHandler(t)
	stage := splitHorizonStage(h)

	// The parent alone matches this name (it is not under the delegation), so the
	// answer must be the parent's A record — deterministic before and after any
	// ordering fix.
	for i := 0; i < 50; i++ {
		q := rr19Query(t, "ns1.example.com.")
		w := q.currentWriter.(*rr19Writer)
		handled, err := stage(context.Background(), q, w)
		if err != nil {
			t.Fatalf("control: splitHorizonStage error: %v", err)
		}
		if !handled {
			t.Fatal("control: the parent zone owns ns1.example.com. but the stage did not answer it")
		}
		if got := rr19ARecord(w.got, "ns1.example.com."); got != rr19ParentAddr {
			t.Fatalf("control: A for ns1.example.com. = %q, want %q", got, rr19ParentAddr)
		}
	}

	// Outside every view zone: the stage must not answer.
	q := rr19Query(t, "other.example.net.")
	w := q.currentWriter.(*rr19Writer)
	handled, err := stage(context.Background(), q, w)
	if err != nil {
		t.Fatalf("control: splitHorizonStage error: %v", err)
	}
	if handled {
		t.Fatal("control: the view holds no zone for other.example.net. yet the stage answered")
	}
}
