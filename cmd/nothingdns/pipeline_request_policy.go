// NothingDNS - request admission policy
//
// Everything here answers one question: is this packet a request this server
// is willing to process at all? Before these stages existed the pipeline
// looked only at the question name and type, so a packet was processed as a
// standard query no matter what its QR bit, OPCODE, QDCOUNT, QCLASS or EDNS
// version said. Observed consequences, all reproduced against a running
// server:
//
//   - a response (QR=1) aimed at this server was answered, so two servers
//     pointed at each other ping-pong packets forever and any spoofed-source
//     response turned the server into a reflector;
//   - IQUERY/STATUS/reserved opcodes were answered with real zone data;
//   - a CHAOS- or Hesiod-class query was answered out of the IN zone, with
//     AA=1 and IN-class records, which clients report as a malformed message;
//   - EDNS version 1 was answered as if it were version 0 instead of BADVERS,
//     so EDNS version negotiation could never converge.

package main

import (
	"context"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// ednsResponsePayloadSize is the EDNS0 UDP payload size this server
// advertises on responses it originates (matching the rest of the handler).
const ednsResponsePayloadSize = 4096

// queryDirectionStage drops messages that are responses rather than requests.
//
// RFC 1035 §4.1.1: QR "specifies whether this message is a query (0), or a
// response (1)". A server has nothing to say to a response, and answering one
// is actively harmful — it sustains packet loops between two servers and lets
// a spoofed source address bounce traffic off this server. The message is
// dropped silently: any reply, including an error, would defeat the point.
//
// Runs first so a flood of such packets costs no more than a header read.
func queryDirectionStage(h *integratedHandler) Stage {
	return func(_ context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if q.msg == nil {
			return false, nil // validationStage owns the nil-message FORMERR
		}
		if q.msg.Header.Flags.QR {
			h.logger.Debugf("[%s] Dropping message with QR=1 (a response, not a request)", q.reqID)
			return true, nil
		}
		return false, nil
	}
}

// requestPolicyStage rejects requests this server does not implement or
// cannot answer meaningfully: unsupported opcodes, malformed question
// counts, classes outside IN, and unsupported EDNS.
//
// Placed after the ACL, RPZ-client and rate-limit stages so that a client
// which is not allowed to talk to this server at all is still cut off first
// and never learns anything from these replies.
func requestPolicyStage(h *integratedHandler) Stage {
	return func(_ context.Context, q *query, w server.ResponseWriter) (bool, error) {
		if q.msg == nil {
			return false, nil
		}

		// ── Opcode ──
		// OpcodeDSO never reaches the pipeline; the TCP and TLS transports
		// route it to the DSO session handler before dispatch.
		switch q.msg.Header.Flags.Opcode {
		case protocol.OpcodeQuery, protocol.OpcodeNotify, protocol.OpcodeUpdate:
			// Handled here (QUERY) or by transferStage (NOTIFY, UPDATE).
		default:
			// RFC 3425 retired IQUERY with "servers SHOULD return NOTIMP",
			// and RFC 6895 §2.2 says the same for any unassigned opcode.
			h.logger.Debugf("[%s] NOTIMP for opcode %d", q.reqID, q.msg.Header.Flags.Opcode)
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeNotImplemented)
			}
			q.rcode, q.rcodeSet = protocol.RcodeNotImplemented, true
			sendError(q.currentWriter, q.msg, protocol.RcodeNotImplemented)
			return true, nil
		}

		// ── Question count ──
		// RFC 9619 §3 makes it explicit for QUERY ("QDCOUNT MUST be 1 ...
		// otherwise FORMERR"); RFC 1996 §3.7 and RFC 2136 §3.1 require a
		// single entry for NOTIFY and UPDATE respectively. A second question
		// has no defined meaning, and answering only the first while echoing
		// QDCOUNT=2 produces a response no client can interpret.
		if len(q.msg.Questions) != 1 {
			h.logger.Debugf("[%s] FORMERR for QDCOUNT=%d", q.reqID, len(q.msg.Questions))
			if h.metrics != nil {
				h.metrics.RecordResponse(protocol.RcodeFormatError)
			}
			q.rcode, q.rcodeSet = protocol.RcodeFormatError, true
			sendError(q.currentWriter, q.msg, protocol.RcodeFormatError)
			return true, nil
		}

		// ── EDNS ──
		if handled := h.enforceEDNSPolicy(q); handled {
			return true, nil
		}

		// ── Class ──
		// Only standard queries carry a client-chosen QCLASS worth screening;
		// NOTIFY and UPDATE reach transferStage with their own class rules
		// (RFC 2136 uses ANY/NONE classes inside the prerequisite and update
		// sections, so they must not be screened here).
		if q.msg.Header.Flags.Opcode == protocol.OpcodeQuery {
			if qclass := q.msg.Questions[0].QClass; qclass != protocol.ClassIN {
				// This server serves Internet-class data only. Answering a
				// CH/HS/ANY/NONE query out of an IN zone emits IN-class
				// records under a non-IN question, which clients reject as
				// malformed, and — because the cache is keyed on name, type
				// and DO bit only — would let a non-IN answer be served to
				// an IN querier. REFUSED is the standard "not served here".
				h.logger.Debugf("[%s] REFUSED for class %d (only IN is served)", q.reqID, qclass)
				if h.metrics != nil {
					h.metrics.RecordResponse(protocol.RcodeRefused)
				}
				q.rcode, q.rcodeSet = protocol.RcodeRefused, true
				sendErrorWithEDE(q.currentWriter, q.msg, protocol.RcodeRefused,
					protocol.EDENotSupported, "only class IN is served")
				return true, nil
			}
		}

		return false, nil
	}
}

// enforceEDNSPolicy applies the RFC 6891 rules for the OPT pseudo-record in
// a request. Returns true when it has answered the request itself.
func (h *integratedHandler) enforceEDNSPolicy(q *query) bool {
	optCount := 0
	var opt *protocol.ResourceRecord
	for _, rr := range q.msg.Additionals {
		if rr != nil && rr.Type == protocol.TypeOPT {
			optCount++
			if opt == nil {
				opt = rr
			}
		}
	}
	if optCount == 0 {
		return false
	}

	// RFC 6891 §6.1.1: "If a query message with more than one OPT RR is
	// received, a FORMERR (RCODE=1) MUST be returned." The same section
	// fixes the OPT owner name at root, so a labelled owner is equally
	// malformed.
	if optCount > 1 || (opt.Name != nil && !opt.Name.IsRoot()) {
		h.logger.Debugf("[%s] FORMERR for malformed OPT (count=%d)", q.reqID, optCount)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeFormatError)
		}
		q.rcode, q.rcodeSet = protocol.RcodeFormatError, true
		sendError(q.currentWriter, q.msg, protocol.RcodeFormatError)
		return true
	}

	// RFC 6891 §6.1.3: a requestor announcing a version this server does not
	// implement gets RCODE=BADVERS and an OPT RR stating the highest version
	// the server does implement, with no other data in the response.
	if hdr := protocol.ParseEDNS0Header(opt); hdr != nil && hdr.Version != 0 {
		h.logger.Debugf("[%s] BADVERS for EDNS version %d", q.reqID, hdr.Version)
		if h.metrics != nil {
			h.metrics.RecordResponse(protocol.RcodeBadVers)
		}
		q.rcode, q.rcodeSet = protocol.RcodeBadVers, true
		sendBadVers(q.currentWriter, q.msg)
		return true
	}

	return false
}

// sendBadVers writes the RFC 6891 §6.1.3 BADVERS response: the low four bits
// of the extended RCODE 16 live in the message header (and are zero, i.e.
// NOERROR to a non-EDNS reader), the high eight bits in the OPT TTL.
func sendBadVers(w server.ResponseWriter, query *protocol.Message) {
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    query.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeBadVers & 0x0F),
		},
		Questions: query.Questions,
	}
	resp.AddAdditional(&protocol.ResourceRecord{
		Name:  protocol.NewName(nil, true), // OPT owner name is root
		Type:  protocol.TypeOPT,
		Class: ednsResponsePayloadSize,
		TTL:   protocol.BuildEDNSTTL(protocol.RcodeBadVers>>4, 0 /* highest version supported */, false, 0),
		Data:  &protocol.RDataOPT{},
	})
	if _, err := w.Write(resp); err != nil {
		logErrorf("failed to write BADVERS response: %v", err)
	}
}
