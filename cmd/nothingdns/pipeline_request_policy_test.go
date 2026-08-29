package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// policyTestHandler returns a handler authoritative for example.com so the
// tests can tell "the request was refused up front" apart from "the request
// was processed and found nothing".
func policyTestHandler(t *testing.T) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	addZoneRecords(t, h, "example.com", []zone.Record{
		{Name: "www.example.com", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.10"},
	})
	return h
}

func serveOne(t *testing.T, h *integratedHandler, req *protocol.Message) *protocol.Message {
	t.Helper()
	w := newCaptureWriter("192.0.2.100", "udp")
	h.ServeDNS(w, req)
	return w.msg
}

// TestRequestPolicy_ResponseIsDropped covers the packet-loop guard: a message
// with QR=1 is a response, and answering it lets two servers volley packets at
// each other and lets a spoofed source use this server as a reflector.
func TestRequestPolicy_ResponseIsDropped(t *testing.T) {
	h := policyTestHandler(t)
	req := newTestQuery(t, "www.example.com.", protocol.TypeA)
	req.Header.Flags.QR = true

	if resp := serveOne(t, h, req); resp != nil {
		t.Fatalf("QR=1 message was answered (rcode=%d); it must be dropped silently",
			resp.Header.Flags.RCODE)
	}
}

// TestRequestPolicy_UnsupportedOpcodeIsNotImplemented covers RFC 3425 (IQUERY
// is retired) and RFC 6895 §2.2 (unassigned opcodes). Before this stage every
// opcode fell through to standard query processing and was answered with real
// zone data.
func TestRequestPolicy_UnsupportedOpcodeIsNotImplemented(t *testing.T) {
	for _, opcode := range []uint8{protocol.OpcodeIQuery, protocol.OpcodeStatus, 3, 7, 15} {
		h := policyTestHandler(t)
		req := newTestQuery(t, "www.example.com.", protocol.TypeA)
		req.Header.Flags.Opcode = opcode

		resp := serveOne(t, h, req)
		if resp == nil {
			t.Fatalf("opcode %d: no response", opcode)
		}
		if resp.Header.Flags.RCODE != protocol.RcodeNotImplemented {
			t.Errorf("opcode %d: rcode = %d, want NOTIMP(%d)",
				opcode, resp.Header.Flags.RCODE, protocol.RcodeNotImplemented)
		}
		if len(resp.Answers) != 0 {
			t.Errorf("opcode %d: leaked %d answer records into a NOTIMP response",
				opcode, len(resp.Answers))
		}
	}
}

// TestRequestPolicy_QuestionCountMustBeOne covers RFC 9619 §3 for QUERY.
func TestRequestPolicy_QuestionCountMustBeOne(t *testing.T) {
	h := policyTestHandler(t)
	req := newTestQuery(t, "www.example.com.", protocol.TypeA)
	req.Questions = append(req.Questions, &protocol.Question{
		Name:   req.Questions[0].Name,
		QType:  protocol.TypeAAAA,
		QClass: protocol.ClassIN,
	})

	resp := serveOne(t, h, req)
	if resp == nil {
		t.Fatal("no response to QDCOUNT=2")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeFormatError {
		t.Errorf("rcode = %d, want FORMERR(%d)", resp.Header.Flags.RCODE, protocol.RcodeFormatError)
	}
	if len(resp.Answers) != 0 {
		t.Errorf("QDCOUNT=2 was partially answered with %d records", len(resp.Answers))
	}
}

// TestRequestPolicy_NonINClassIsRefused is the regression for the cross-class
// defect: a CHAOS or Hesiod query used to be answered out of the IN zone, so
// the response carried IN-class records under a non-IN question (clients
// report the message as malformed) and — since the cache key is name+type+DO
// with no class — could be served back to an IN querier.
func TestRequestPolicy_NonINClassIsRefused(t *testing.T) {
	for _, qclass := range []uint16{protocol.ClassCH, protocol.ClassHS, protocol.ClassANY, protocol.ClassNONE, 0} {
		h := policyTestHandler(t)
		req := newTestQuery(t, "www.example.com.", protocol.TypeA)
		req.Questions[0].QClass = qclass

		resp := serveOne(t, h, req)
		if resp == nil {
			t.Fatalf("class %d: no response", qclass)
		}
		if resp.Header.Flags.RCODE != protocol.RcodeRefused {
			t.Errorf("class %d: rcode = %d, want REFUSED(%d)",
				qclass, resp.Header.Flags.RCODE, protocol.RcodeRefused)
		}
		if len(resp.Answers) != 0 {
			t.Errorf("class %d: answered with %d IN-class records", qclass, len(resp.Answers))
		}
	}
}

func TestRequestPolicy_INClassStillAnswered(t *testing.T) {
	h := policyTestHandler(t)
	resp := serveOne(t, h, newTestQuery(t, "www.example.com.", protocol.TypeA))
	if resp == nil {
		t.Fatal("no response to a normal IN query")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("normal IN query broken: rcode=%d answers=%d",
			resp.Header.Flags.RCODE, len(resp.Answers))
	}
}

func optRR(version uint8, do bool) *protocol.ResourceRecord {
	return &protocol.ResourceRecord{
		Name:  protocol.NewName(nil, true),
		Type:  protocol.TypeOPT,
		Class: 4096,
		TTL:   protocol.BuildEDNSTTL(0, version, do, 0),
		Data:  &protocol.RDataOPT{},
	}
}

// TestRequestPolicy_UnsupportedEDNSVersionGetsBadVers covers RFC 6891 §6.1.3.
// Without it, EDNS version negotiation never converges: the server answered a
// version-1 query as though it were version 0.
func TestRequestPolicy_UnsupportedEDNSVersionGetsBadVers(t *testing.T) {
	h := policyTestHandler(t)
	req := newTestQuery(t, "www.example.com.", protocol.TypeA)
	req.AddAdditional(optRR(1, false))

	resp := serveOne(t, h, req)
	if resp == nil {
		t.Fatal("no response to EDNS version 1")
	}
	// BADVERS is extended RCODE 16: the low 4 bits (0) stay in the header and
	// the high 8 bits (1) go in the OPT TTL.
	if got := resp.Header.Flags.RCODE; got != protocol.RcodeBadVers&0x0F {
		t.Errorf("header rcode = %d, want %d", got, protocol.RcodeBadVers&0x0F)
	}
	if len(resp.Answers) != 0 {
		t.Errorf("BADVERS response carried %d answer records; RFC 6891 §6.1.3 allows none",
			len(resp.Answers))
	}
	opt := resp.GetOPT()
	if opt == nil {
		t.Fatal("BADVERS response has no OPT record")
	}
	hdr := protocol.ParseEDNS0Header(opt)
	if hdr == nil {
		t.Fatal("OPT record did not parse")
	}
	if hdr.ExtendedRCODE != protocol.RcodeBadVers>>4 {
		t.Errorf("extended rcode = %d, want %d", hdr.ExtendedRCODE, protocol.RcodeBadVers>>4)
	}
	if hdr.Version != 0 {
		t.Errorf("OPT version = %d, want 0 (the highest version this server implements)", hdr.Version)
	}
}

func TestRequestPolicy_EDNSVersionZeroIsAnswered(t *testing.T) {
	h := policyTestHandler(t)
	req := newTestQuery(t, "www.example.com.", protocol.TypeA)
	req.AddAdditional(optRR(0, false))

	resp := serveOne(t, h, req)
	if resp == nil || resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("EDNS version 0 query was not answered normally: %+v", resp)
	}
}

// TestRequestPolicy_MalformedOPTIsFormErr covers the two RFC 6891 §6.1.1
// constraints on the OPT pseudo-record: at most one per message, owner name
// at the root.
func TestRequestPolicy_MalformedOPTIsFormErr(t *testing.T) {
	tests := []struct {
		name string
		opts []*protocol.ResourceRecord
	}{
		{"two OPT records", []*protocol.ResourceRecord{optRR(0, false), optRR(0, false)}},
		{"non-root OPT owner", func() []*protocol.ResourceRecord {
			rr := optRR(0, false)
			rr.Name = protocol.NewName([]string{"x"}, true)
			return []*protocol.ResourceRecord{rr}
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := policyTestHandler(t)
			req := newTestQuery(t, "www.example.com.", protocol.TypeA)
			for _, rr := range tc.opts {
				req.AddAdditional(rr)
			}

			resp := serveOne(t, h, req)
			if resp == nil {
				t.Fatal("no response")
			}
			if resp.Header.Flags.RCODE != protocol.RcodeFormatError {
				t.Errorf("rcode = %d, want FORMERR(%d)",
					resp.Header.Flags.RCODE, protocol.RcodeFormatError)
			}
		})
	}
}
