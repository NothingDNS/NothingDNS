// NothingDNS - response header conformance
//
// A DNS response is not free to invent its own header bits: RFC 1035 §4.1.1
// requires OPCODE and RD to be copied from the request being answered, and
// RFC 4035 §3.1.6 requires the same of CD. Responses in this handler are
// built in ~50 places (reply, sendError, sendErrorWithEDE, the zone/CNAME/
// referral builders, the transfer handlers, the panic-recovery path), and
// every one of them derived its header from protocol.NewResponseFlags, which
// hardcodes Opcode=QUERY, RD=false, CD=false. The result on the wire was that
// a response to any non-QUERY opcode carried OPCODE=QUERY, so conforming
// clients discarded it as a mismatch and the query looked like a timeout.
//
// Correcting ~50 construction sites would leave the next one to be added
// wrong again, so the fix is applied at the single point every response
// passes through on its way out: the pipeline's response writer.

package main

import (
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// headerPolicyResponseWriter stamps the request-derived header bits onto
// every outgoing response, then delegates to the wrapped writer.
type headerPolicyResponseWriter struct {
	inner server.ResponseWriter

	// Bits captured from the request this writer is answering.
	opcode uint8
	rd     bool
	cd     bool

	// recursionAvailable reports whether this server will actually recurse.
	// RFC 1035 §4.1.1 defines RA as "denotes whether recursive query support
	// is available in the name server"; an authoritative-only server that
	// advertises RA=1 tells clients to keep bringing it recursive work it
	// refuses by design.
	recursionAvailable bool
}

// Write applies the header policy and forwards the message.
func (hw *headerPolicyResponseWriter) Write(msg *protocol.Message) (int, error) {
	if msg != nil {
		msg.Header.Flags.Opcode = hw.opcode
		msg.Header.Flags.RD = hw.rd
		msg.Header.Flags.CD = hw.cd
		if !hw.recursionAvailable {
			msg.Header.Flags.RA = false
		}
	}
	return hw.inner.Write(msg)
}

// ClientInfo delegates to the inner writer.
func (hw *headerPolicyResponseWriter) ClientInfo() *server.ClientInfo {
	return hw.inner.ClientInfo()
}

// MaxSize delegates to the inner writer.
func (hw *headerPolicyResponseWriter) MaxSize() int {
	return hw.inner.MaxSize()
}

// newHeaderPolicyWriter wraps w so that responses to req carry the header
// bits req is entitled to have echoed back. A nil req leaves the defaults
// (OPCODE=QUERY, RD=0, CD=0) in place, which is what a response to an
// unparseable request should carry.
func newHeaderPolicyWriter(h *integratedHandler, w server.ResponseWriter, req *protocol.Message) server.ResponseWriter {
	hw := &headerPolicyResponseWriter{
		inner:              w,
		opcode:             protocol.OpcodeQuery,
		recursionAvailable: recursionAvailable(h),
	}
	if req != nil {
		hw.opcode = req.Header.Flags.Opcode
		hw.rd = req.Header.Flags.RD
		hw.cd = req.Header.Flags.CD
	}
	return hw
}

// recursionAvailable reports whether the handler has any path that will
// answer a name it is not authoritative for.
func recursionAvailable(h *integratedHandler) bool {
	if h == nil || h.config == nil {
		return true
	}
	return !h.config.Resolution.AuthoritativeOnly
}
