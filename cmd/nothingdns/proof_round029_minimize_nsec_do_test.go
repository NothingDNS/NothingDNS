// Regression test for round 029: minimizeResponse must keep the DNSSEC
// denial proof (NSEC/NSEC3 + RRSIG) in non-authoritative negative answers
// for DO=1 clients.
//
// reply() runs scrubForClient BEFORE minimizeResponse. scrubForClient already
// removes every DNSSEC record a client without the DO bit may not see
// (RFC 4035 §3.2.2), so by the time minimizeResponse filters the authority
// section, any NSEC/NSEC3/RRSIG still present is exactly what a DO=1 client
// is entitled to (RFC 4035 §2.2, §3.1.3): without the NSEC proof and its
// signature, a validating stub cannot verify the NXDOMAIN and treats the
// answer as Bogus (SERVFAIL). Every recursive NXDOMAIN has AA=0, so the
// non-authoritative branch stripped the proof from the most common path —
// forwarded answers, iterative resolution, the negative cache, and the
// RFC 8198 NSEC-cache synthesis alike.
package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// proofWriter records the message reply() hands to the transport — i.e. after
// the full reply() pipeline (scrubForClient + minimizeResponse) has run.
type proofWriter struct {
	got *protocol.Message
}

func (w *proofWriter) Write(msg *protocol.Message) (int, error) {
	w.got = msg
	return 0, nil
}

func (w *proofWriter) ClientInfo() *server.ClientInfo { return &server.ClientInfo{} }
func (w *proofWriter) MaxSize() int                   { return 4096 }

// recursiveNXDOMAINResponse builds the negative answer a recursive upstream
// returns for a name inside a signed zone: AA=0 (recursive servers do not set
// AA), NXDOMAIN, Authority = [SOA, NSEC, RRSIG(NSEC)].
func recursiveNXDOMAINResponse(t *testing.T) *protocol.Message {
	zone := mustParseName(t, "example.com.")
	owner := mustParseName(t, "b.example.com.")
	next := mustParseName(t, "z.example.com.")
	return &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeNameError},
		},
		Questions: []*protocol.Question{
			{Name: owner, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  zone,
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataSOA{
					MName:   mustParseName(t, "ns1.example.com."),
					RName:   mustParseName(t, "admin.example.com."),
					Serial:  2024010101,
					Refresh: 3600,
					Retry:   600,
					Expire:  604800,
					Minimum: 86400,
				},
			},
			{
				Name:  owner,
				Type:  protocol.TypeNSEC,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataNSEC{
					NextDomain: next,
					TypeBitMap: []uint16{protocol.TypeSOA, protocol.TypeNSEC, protocol.TypeRRSIG},
				},
			},
			{
				Name:  owner,
				Type:  protocol.TypeRRSIG,
				Class: protocol.ClassIN,
				TTL:   300,
				Data: &protocol.RDataRRSIG{
					TypeCovered: protocol.TypeNSEC,
					Algorithm:   13,
					Labels:      3,
					OriginalTTL: 300,
					Expiration:  4102444800,
					Inception:   1600000000,
					KeyTag:      12345,
					SignerName:  zone,
					Signature:   []byte{1, 2, 3, 4},
				},
			},
		},
	}
}

func proofQuery(t *testing.T, do bool) *protocol.Message {
	q := &protocol.Message{
		Header: protocol.Header{
			ID:    42,
			Flags: protocol.NewQueryFlags(),
		},
		Questions: []*protocol.Question{
			{Name: mustParseName(t, "b.example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
	q.SetEDNS0(4096, do)
	return q
}

func authorityTypes(t *testing.T, m *protocol.Message) []uint16 {
	t.Helper()
	types := make([]uint16, 0, len(m.Authorities))
	for _, rr := range m.Authorities {
		types = append(types, rr.Type)
	}
	return types
}

func authorityHas(types []uint16, want uint16) bool {
	for _, tpe := range types {
		if tpe == want {
			return true
		}
	}
	return false
}

// TestReply_DOClientRecursiveNegativeKeepsNSECProof is the regression: a
// DO=1 client receiving a recursive (AA=0) NXDOMAIN from a signed zone must
// still get the NSEC denial proof and its RRSIG after reply()'s response
// pipeline, or no validating stub can verify the answer.
func TestReply_DOClientRecursiveNegativeKeepsNSECProof(t *testing.T) {
	w := &proofWriter{}
	reply(w, proofQuery(t, true), recursiveNXDOMAINResponse(t))
	if w.got == nil {
		t.Fatal("reply never wrote a response")
	}
	types := authorityTypes(t, w.got)
	if !authorityHas(types, protocol.TypeNSEC) || !authorityHas(types, protocol.TypeRRSIG) {
		t.Fatalf("DO=1 recursive NXDOMAIN lost the DNSSEC denial proof: authority types after reply() = %v (want NSEC+RRSIG retained alongside SOA)", types)
	}
	if !authorityHas(types, protocol.TypeSOA) {
		t.Fatalf("SOA lost from authority section: %v", types)
	}
}

// TestReply_NoDoClientStillStripsNSECProof pins the RFC 4035 §3.2.2 side of
// the contract: a client that did not set the DO bit must not receive the
// DNSSEC records; the SOA (negative caching, RFC 2308) stays.
func TestReply_NoDoClientStillStripsNSECProof(t *testing.T) {
	w := &proofWriter{}
	reply(w, proofQuery(t, false), recursiveNXDOMAINResponse(t))
	if w.got == nil {
		t.Fatal("reply never wrote a response")
	}
	for _, rr := range w.got.Authorities {
		if rr.Type == protocol.TypeNSEC || rr.Type == protocol.TypeRRSIG {
			t.Fatalf("DO=0 client unexpectedly received DNSSEC records: %v", authorityTypes(t, w.got))
		}
	}
	types := authorityTypes(t, w.got)
	if len(types) == 0 || types[0] != protocol.TypeSOA {
		t.Fatalf("SOA lost for DO=0 client: %v", types)
	}
}

// TestReply_AuthoritativeNegativeKeepsNSECProof pins the AA branch, which
// already kept the proof before the fix, so the minimal-response policy can
// never regress it again.
func TestReply_AuthoritativeNegativeKeepsNSECProof(t *testing.T) {
	resp := recursiveNXDOMAINResponse(t)
	resp.Header.Flags.AA = true
	w := &proofWriter{}
	reply(w, proofQuery(t, true), resp)
	if w.got == nil {
		t.Fatal("reply never wrote a response")
	}
	types := authorityTypes(t, w.got)
	if !authorityHas(types, protocol.TypeNSEC) || !authorityHas(types, protocol.TypeRRSIG) {
		t.Fatalf("authoritative negative lost proof: %v", types)
	}
}

// TestReply_RecursiveNegativeStillStripsUnrelatedAuthority guards minimal
// responses for the non-DNSSEC case the policy exists for: an unrelated
// answer record smuggled into the authority section of a recursive reply is
// still dropped.
func TestReply_RecursiveNegativeStillStripsUnrelatedAuthority(t *testing.T) {
	resp := recursiveNXDOMAINResponse(t)
	resp.Authorities = append(resp.Authorities, &protocol.ResourceRecord{
		Name:  mustParseName(t, "b.example.com."),
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataA{Address: [4]byte{10, 0, 0, 1}},
	})
	w := &proofWriter{}
	reply(w, proofQuery(t, true), resp)
	if w.got == nil {
		t.Fatal("reply never wrote a response")
	}
	if authorityTypesIncludeA(w.got) {
		t.Fatalf("unrelated A record survived minimization: %v", authorityTypes(t, w.got))
	}
}

func authorityTypesIncludeA(m *protocol.Message) bool {
	for _, rr := range m.Authorities {
		if rr.Type == protocol.TypeA {
			return true
		}
	}
	return false
}
