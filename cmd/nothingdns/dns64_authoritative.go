// NothingDNS - DNS64 synthesis for names in zones this server hosts
//
// RFC 6147 §5.1: for a AAAA query the DNS64 "first attempts to retrieve
// non-synthetic RRs of this type and class, either by performing a query or,
// in the case of an authoritative server, by examining its own results", and
// synthesizes from the A RRset when there are none. tryDNS64Synthesis covers
// forwarded and resolved answers only, so an IPv4-only name in a local zone
// answered NODATA to IPv6-only clients behind NAT64 (F875).

package main

import (
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// dns64CaptureWriter records the response the authoritative code would write
// instead of sending it, so it can be replaced by a synthesized answer.
type dns64CaptureWriter struct {
	inner server.ResponseWriter
	msg   *protocol.Message
}

func (c *dns64CaptureWriter) Write(m *protocol.Message) (int, error) {
	if m != nil {
		c.msg = m.Copy()
	}
	return 0, nil
}

func (c *dns64CaptureWriter) ClientInfo() *server.ClientInfo { return c.inner.ClientInfo() }
func (c *dns64CaptureWriter) MaxSize() int                   { return c.inner.MaxSize() }

// serveAuthoritative answers q from z (handleAuthoritative), applying DNS64
// to a AAAA query whose answer from the zone holds no usable AAAA.
func (h *integratedHandler) serveAuthoritative(z *zone.Zone, w server.ResponseWriter, q *query) bool {
	if h.security.DNS64Synth == nil || q.qtype != protocol.TypeAAAA || q.msg.Header.Flags.CD {
		// RFC 6147 §5.5: a CD=1 client validates itself and gets the real answer.
		return h.handleAuthoritative(z, w, q.msg, q.q, q.qname, &q.cacheHit)
	}
	cw := &dns64CaptureWriter{inner: w}
	if !h.handleAuthoritative(z, cw, q.msg, q.q, q.qname, &q.cacheHit) {
		return false
	}
	if cw.msg == nil {
		return true // nothing was written (e.g. a dropped query)
	}
	resp := cw.msg
	if synth := h.synthesizeLocalDNS64(z, w, q, resp); synth != nil {
		reply(w, q.msg, synth) // as the forwarding path sends its synthesis
		return true
	}
	if _, err := w.Write(resp); err != nil {
		logErrorf("failed to write response: %v", err)
	}
	return true
}

// synthesizeChainDNS64 is synthesizeLocalDNS64 for an in-zone CNAME chain
// (cnameStage): resp is the chain answered for AAAA; the A answer is the same
// chain resolved for A, and the synthesized answer keeps the chain (RFC 6147
// §5.3.1). handled reports that RPZ answered the A query instead, as on the
// forwarding path.
func (h *integratedHandler) synthesizeChainDNS64(w server.ResponseWriter, q *query, chain cnameChainResult, resp *protocol.Message, sign bool) (synth *protocol.Message, handled bool, err error) {
	synthesizer := h.security.DNS64Synth
	if synthesizer == nil || q.qtype != protocol.TypeAAAA || q.msg.Header.Flags.CD {
		return nil, false, nil
	}
	synthesizer.FilterExcludedAAAA(q.q, resp)
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess || !synthesizer.ShouldSynthesize(q.q, resp) {
		return nil, false, nil
	}
	aMsg := q.msg.Copy()
	aMsg.Questions = []*protocol.Question{{Name: q.q.Name.Copy(), QType: protocol.TypeA, QClass: q.q.QClass}}
	tgt := h.resolveChainTarget(w, aMsg, nil, chain.targetName, protocol.TypeA, sign)
	aResp := h.buildChainResponse(aMsg, chain, tgt, sign)
	if handled, err := h.applyRPZResponsePolicyWithError(w, q.msg, q.q, aResp, chain.targetName); handled || err != nil {
		return nil, handled, err
	}
	if aResp.Header.Flags.RCODE != protocol.RcodeSuccess || len(aResp.Answers) == 0 {
		return nil, false, nil
	}
	synth = synthesizer.SynthesizeResponse(q.q, aResp)
	if synth == nil || hasNoAAAAAnswer(synth) {
		return nil, false, nil
	}
	capSynthesizedTTL(synth, resp)
	synth.Header.ID = resp.Header.ID
	synth.Questions = q.msg.Questions
	h.logger.Debugf("DNS64: synthesized AAAA for %s through its CNAME chain", q.qname)
	return synth, false, nil
}

// hasNoAAAAAnswer reports whether m carries no AAAA answer.
func hasNoAAAAAnswer(m *protocol.Message) bool {
	for _, rr := range m.Answers {
		if rr != nil && rr.Type == protocol.TypeAAAA {
			return false
		}
	}
	return true
}

// capSynthesizedTTL limits synthesized AAAA records to the negative TTL of
// the answer they replace (RFC 6147 §5.1.7), or 600 s without an SOA.
func capSynthesizedTTL(synth, negative *protocol.Message) {
	ttlCap := uint32(600)
	if negTTL, ok := negativeCacheTTL(negative); ok {
		ttlCap = negTTL
	}
	for _, rr := range synth.Answers {
		if rr.Type == protocol.TypeAAAA && rr.TTL > ttlCap {
			rr.TTL = ttlCap
		}
	}
}

// synthesizeLocalDNS64 returns the synthesized AAAA answer for resp, the
// zone's own answer to q, or nil when resp stands: an answer with a usable
// AAAA, a non-NOERROR answer (NXDOMAIN, a refusal), or no A RRset at the name.
func (h *integratedHandler) synthesizeLocalDNS64(z *zone.Zone, w server.ResponseWriter, q *query, resp *protocol.Message) *protocol.Message {
	synthesizer := h.security.DNS64Synth
	// RFC 6147 §5.1.4: excluded AAAA records are unusable for the client.
	synthesizer.FilterExcludedAAAA(q.q, resp)
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess || !synthesizer.ShouldSynthesize(q.q, resp) {
		return nil
	}
	aMsg := q.msg.Copy()
	aMsg.Questions = []*protocol.Question{{Name: q.q.Name.Copy(), QType: protocol.TypeA, QClass: q.q.QClass}}
	acw := &dns64CaptureWriter{inner: w}
	var aCacheHit bool
	if !h.handleAuthoritative(z, acw, aMsg, aMsg.Questions[0], q.qname, &aCacheHit) || acw.msg == nil {
		return nil
	}
	aResp := acw.msg
	if aResp.Header.Flags.RCODE != protocol.RcodeSuccess || len(aResp.Answers) == 0 {
		return nil
	}
	synth := synthesizer.SynthesizeResponse(q.q, aResp)
	if synth == nil || hasNoAAAAAnswer(synth) {
		return nil
	}
	capSynthesizedTTL(synth, resp)
	synth.Header.ID = resp.Header.ID
	synth.Questions = q.msg.Questions
	h.logger.Debugf("DNS64: synthesized %d AAAA records for %s from zone %s", len(synth.Answers), q.qname, z.Origin)
	return synth
}
