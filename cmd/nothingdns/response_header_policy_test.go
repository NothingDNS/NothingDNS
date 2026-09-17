package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/cache"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func headerEchoHandler(t *testing.T) *integratedHandler {
	t.Helper()
	h := newTestHandler()
	addZoneRecords(t, h, "example.com", []zone.Record{
		{Name: "www.example.com", Type: "A", TTL: 300, Class: "IN", RData: "192.0.2.10"},
	})
	return h
}

// TestResponseHeader_EchoesOpcodeRDCD is the regression for responses built
// from protocol.NewResponseFlags, which hardcodes Opcode=QUERY, RD=0, CD=0.
// RFC 1035 §4.1.1 requires OPCODE and RD to be copied from the request, and
// RFC 4035 §3.1.6 requires the same of CD. A response whose OPCODE does not
// match the request is discarded by conforming clients, so a NOTIFY or UPDATE
// looked like a timeout no matter what the server actually decided.
func TestResponseHeader_EchoesOpcodeRDCD(t *testing.T) {
	tests := []struct {
		name   string
		opcode uint8
		rd     bool
		cd     bool
	}{
		{"query rd+cd", protocol.OpcodeQuery, true, true},
		{"query no rd", protocol.OpcodeQuery, false, false},
		{"query cd only", protocol.OpcodeQuery, false, true},
		{"unimplemented opcode", protocol.OpcodeStatus, true, false},
		{"notify", protocol.OpcodeNotify, false, false},
		{"update", protocol.OpcodeUpdate, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := headerEchoHandler(t)
			req := newTestQuery(t, "www.example.com.", protocol.TypeA)
			req.Header.Flags.Opcode = tc.opcode
			req.Header.Flags.RD = tc.rd
			req.Header.Flags.CD = tc.cd

			resp := serveOne(t, h, req)
			if resp == nil {
				t.Fatal("no response")
			}
			if resp.Header.Flags.Opcode != tc.opcode {
				t.Errorf("opcode = %d, want %d (RFC 1035 §4.1.1: copied from the request)",
					resp.Header.Flags.Opcode, tc.opcode)
			}
			if resp.Header.Flags.RD != tc.rd {
				t.Errorf("RD = %v, want %v (RFC 1035 §4.1.1)", resp.Header.Flags.RD, tc.rd)
			}
			if resp.Header.Flags.CD != tc.cd {
				t.Errorf("CD = %v, want %v (RFC 4035 §3.1.6)", resp.Header.Flags.CD, tc.cd)
			}
			if !resp.Header.Flags.QR {
				t.Error("QR not set on a response")
			}
		})
	}
}

// TestResponseHeader_RAReflectsRecursionSupport covers RFC 1035 §4.1.1's
// definition of RA — "whether recursive query support is available in the
// name server". An authoritative-only server refuses every recursive path, so
// advertising RA=1 invites clients to keep sending it work it will refuse.
func TestResponseHeader_RAReflectsRecursionSupport(t *testing.T) {
	t.Run("recursion enabled", func(t *testing.T) {
		h := headerEchoHandler(t)
		h.config.Resolution.AuthoritativeOnly = false

		resp := serveOne(t, h, newTestQuery(t, "www.example.com.", protocol.TypeA))
		if resp == nil || !resp.Header.Flags.RA {
			t.Fatalf("RA should be set when the server recurses: %+v", resp)
		}
	})

	t.Run("authoritative only", func(t *testing.T) {
		h := headerEchoHandler(t)
		h.config.Resolution.AuthoritativeOnly = true

		// In-zone answer: still authoritative, but RA must be clear.
		resp := serveOne(t, h, newTestQuery(t, "www.example.com.", protocol.TypeA))
		if resp == nil {
			t.Fatal("no response")
		}
		if resp.Header.Flags.RA {
			t.Error("RA set on an authoritative-only server")
		}
		if len(resp.Answers) != 1 {
			t.Fatalf("in-zone answer lost: %d records", len(resp.Answers))
		}

		// Out-of-zone: refused, and still no RA.
		refused := serveOne(t, h, newTestQuery(t, "elsewhere.example.org.", protocol.TypeA))
		if refused == nil {
			t.Fatal("no response to out-of-zone query")
		}
		if refused.Header.Flags.RA {
			t.Error("RA set on the authoritative-only REFUSED response")
		}
	})
}

// The query log and dashboard record the RCODE actually sent when no stage
// set one explicitly; an explicit (possibly extended) RCODE wins.
func TestQueryResponseRcode(t *testing.T) {
	q := &query{}
	if _, ok := q.responseRcode(); ok {
		t.Error("no response written: rcode must be unknown")
	}

	hw := newHeaderPolicyWriter(nil, newCaptureWriter("192.0.2.1", "udp"), nil).(*headerPolicyResponseWriter)
	q.policyWriter = hw
	resp := &protocol.Message{Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeNameError)}}
	if _, err := hw.Write(resp); err != nil {
		t.Fatal(err)
	}
	if rcode, ok := q.responseRcode(); !ok || rcode != protocol.RcodeNameError {
		t.Errorf("rcode = %d, %v; want NXDOMAIN from the written response", rcode, ok)
	}

	q.rcode, q.rcodeSet = protocol.RcodeBadVers, true
	if rcode, _ := q.responseRcode(); rcode != protocol.RcodeBadVers {
		t.Errorf("rcode = %d; want the explicitly set BADVERS", rcode)
	}
}

// Responses carry an OPT record only for EDNS requests, with the request's
// DO bit and this server's payload size; recursive answers used to pass the
// upstream's OPT (DO=1, udp 512) straight through.
func TestHeaderPolicyWriterNormalizesOPT(t *testing.T) {
	upstreamOPT := func() *protocol.ResourceRecord {
		return &protocol.ResourceRecord{
			Name: protocol.NewName([]string{}, true), Type: protocol.TypeOPT, Class: 512,
			TTL: protocol.BuildEDNSTTL(0, 0, true, 0), Data: &protocol.RDataOPT{},
		}
	}
	request := func(edns, do bool) *protocol.Message {
		req := &protocol.Message{}
		if edns {
			req.SetEDNS0(1232, do)
		}
		return req
	}
	write := func(req *protocol.Message, resp *protocol.Message) *protocol.Message {
		cw := newCaptureWriter("192.0.2.1", "udp")
		if _, err := newHeaderPolicyWriter(nil, cw, req).Write(resp); err != nil {
			t.Fatal(err)
		}
		return cw.msg
	}

	shared := upstreamOPT()
	got := write(request(true, false), &protocol.Message{Additionals: []*protocol.ResourceRecord{shared}})
	opt := got.GetOPT()
	if opt == nil || hasDOBit(got) || opt.Class != ednsResponsePayloadSize {
		t.Fatalf("EDNS request without DO: OPT = %+v, want DO=0 udp=%d", opt, ednsResponsePayloadSize)
	}
	if shared.TTL&0x8000 == 0 || shared.Class != 512 {
		t.Fatal("the original (possibly cached) OPT record must not be modified")
	}

	got = write(request(true, true), &protocol.Message{Additionals: []*protocol.ResourceRecord{upstreamOPT()}})
	if !hasDOBit(got) {
		t.Fatal("DO must be echoed when the request set it")
	}

	got = write(request(false, false), &protocol.Message{Additionals: []*protocol.ResourceRecord{upstreamOPT()}})
	if got.GetOPT() != nil {
		t.Fatal("a non-EDNS request must not get an OPT record")
	}

	got = write(request(true, true), &protocol.Message{})
	if got.GetOPT() == nil || !hasDOBit(got) {
		t.Fatal("an EDNS request must get an OPT record even when the answer had none")
	}
}

// Local zones must win over recursively cached data. A cached upstream
// NXDOMAIN for a name inside a local zone (e.g. the root proving ".test" or
// ".lan" does not exist) used to be served before the zone lookup, hiding the
// zone from every client allowed recursion.
func TestLocalZoneWinsOverCachedNegativeAnswer(t *testing.T) {
	h := headerEchoHandler(t)
	h.cache.SetNegativeWithTTL(cache.MakeKey("www.example.com.", protocol.TypeA, false), protocol.RcodeNameError, 300)

	resp := serveOne(t, h, newTestQuery(t, "www.example.com.", protocol.TypeA))
	if resp == nil {
		t.Fatal("no response")
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess || len(resp.Answers) != 1 || !resp.Header.Flags.AA {
		t.Fatalf("rcode=%d answers=%d aa=%v, want the authoritative A record", resp.Header.Flags.RCODE, len(resp.Answers), resp.Header.Flags.AA)
	}
}
