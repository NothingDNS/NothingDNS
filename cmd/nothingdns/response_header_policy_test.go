package main

import (
	"testing"

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
