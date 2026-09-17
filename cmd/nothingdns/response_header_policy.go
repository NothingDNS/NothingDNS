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

	// recursionDenied is set when this client may not use recursion
	// (allow_recursion). Its responses must not advertise RA either.
	recursionDenied bool

	// EDNS state of the request. Responses carry an OPT record only when the
	// request did (RFC 6891 §7), with the request's DO bit (RFC 3225 §3) and
	// this server's UDP payload size — not the upstream's, which recursive
	// answers used to pass through verbatim.
	reqOPT bool
	reqDO  bool

	// rcode is the RCODE of the last response written, for the query log;
	// wrote reports whether a response was written at all.
	rcode uint8
	wrote bool
}

// RecursionAllowed reports whether the query this writer answers may use
// recursion: the server recurses at all, and this client is permitted to.
func (hw *headerPolicyResponseWriter) RecursionAllowed() bool {
	return hw.recursionAvailable && !hw.recursionDenied
}

// Unwrap returns the wrapped writer.
func (hw *headerPolicyResponseWriter) Unwrap() server.ResponseWriter {
	return hw.inner
}

// recursionAllowedFor reports whether a response written through w may use
// recursion. It walks writer wrappers to the header policy writer; writers
// outside the pipeline (tests, internal callers) are allowed.
func recursionAllowedFor(w server.ResponseWriter) bool {
	for w != nil {
		if hw, ok := w.(*headerPolicyResponseWriter); ok {
			return hw.RecursionAllowed()
		}
		u, ok := w.(interface{ Unwrap() server.ResponseWriter })
		if !ok {
			return true
		}
		w = u.Unwrap()
	}
	return true
}

// denyRecursion marks the header policy writer behind w so that the rest of
// the pipeline skips recursion and responses carry RA=0.
func denyRecursion(w server.ResponseWriter) {
	for w != nil {
		if hw, ok := w.(*headerPolicyResponseWriter); ok {
			hw.recursionDenied = true
			return
		}
		u, ok := w.(interface{ Unwrap() server.ResponseWriter })
		if !ok {
			return
		}
		w = u.Unwrap()
	}
}

// Write applies the header policy and forwards the message.
func (hw *headerPolicyResponseWriter) Write(msg *protocol.Message) (int, error) {
	if msg != nil {
		msg.Header.Flags.Opcode = hw.opcode
		msg.Header.Flags.RD = hw.rd
		msg.Header.Flags.CD = hw.cd
		if !hw.RecursionAllowed() {
			msg.Header.Flags.RA = false
		}
		hw.normalizeOPT(msg)
		hw.rcode, hw.wrote = msg.Header.Flags.RCODE, true
	}
	return hw.inner.Write(msg)
}

// normalizeOPT applies the request's EDNS state to msg's OPT record. The OPT
// record is replaced, never modified in place: responses may share records
// with the cache.
func (hw *headerPolicyResponseWriter) normalizeOPT(msg *protocol.Message) {
	idx := -1
	for i, rr := range msg.Additionals {
		if rr != nil && rr.Type == protocol.TypeOPT {
			idx = i
			break
		}
	}
	if idx < 0 {
		if hw.reqOPT {
			additionals := make([]*protocol.ResourceRecord, 0, len(msg.Additionals)+1)
			additionals = append(additionals, msg.Additionals...)
			msg.Additionals = append(additionals, &protocol.ResourceRecord{
				Name:  protocol.NewName([]string{}, true),
				Type:  protocol.TypeOPT,
				Class: ednsResponsePayloadSize,
				TTL:   protocol.BuildEDNSTTL(0, 0, hw.reqDO, 0),
				Data:  &protocol.RDataOPT{},
			})
		}
		return
	}
	opt := msg.Additionals[idx]
	additionals := make([]*protocol.ResourceRecord, 0, len(msg.Additionals))
	additionals = append(additionals, msg.Additionals[:idx]...)
	if hw.reqOPT {
		ttl := opt.TTL &^ 0x8000
		if hw.reqDO {
			ttl |= 0x8000
		}
		normalized := *opt
		normalized.TTL = ttl
		normalized.Class = ednsResponsePayloadSize
		additionals = append(additionals, &normalized)
	}
	additionals = append(additionals, msg.Additionals[idx+1:]...)
	msg.Additionals = additionals
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
		hw.reqOPT = req.GetOPT() != nil
		hw.reqDO = hasDOBit(req)
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
