// NothingDNS - special-use domain names (RFC 6761, RFC 7686)
//
// localhost., invalid., test. and onion. are never delegated, and resolvers
// and caching servers SHOULD answer them locally instead of asking upstream or
// the root (RFC 6761 §6.2-6.4, RFC 7686 §2): localhost names resolve to the
// loopback addresses, the others do not exist. Forwarding them leaked them
// (an .onion name is a privacy leak by itself) and waited on an upstream for
// an answer that is fixed (F747). The records mirror Unbound's default local
// zones. A configured zone for one of these names is served instead: the
// stage runs after the authoritative stages.

package main

import (
	"context"
	"strings"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// specialUseTTL is the TTL of the local answers (Unbound's local-zone default).
const specialUseTTL = 10800

// specialUseZones are the zones answered locally (lower case, absolute).
// localhost names exist; the others are NXDOMAIN below their apex.
var specialUseZones = []string{"localhost.", "invalid.", "test.", "onion."}

// loopbackPTRNames are the reverse names of 127.0.0.1 and ::1.
var loopbackPTRNames = map[string]bool{
	"1.0.0.127.in-addr.arpa.":                     true,
	"1." + strings.Repeat("0.", 31) + "ip6.arpa.": true,
}

// specialUseStage answers special-use names locally (F747).
func specialUseStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		resp := specialUseAnswer(q.msg, q.q, strings.ToLower(canonicalize(q.qname)))
		if resp == nil {
			return false, nil
		}
		if h.metrics != nil {
			h.metrics.RecordResponse(resp.Header.Flags.RCODE)
		}
		reply(q.currentWriter, q.msg, resp)
		return true, nil
	}
}

// specialUseAnswer builds the local answer for name, or returns nil when name
// is not special-use.
func specialUseAnswer(r *protocol.Message, q *protocol.Question, name string) *protocol.Message {
	if q == nil || q.QClass != protocol.ClassIN {
		return nil
	}
	if loopbackPTRNames[name] {
		if q.QType == protocol.TypePTR {
			return specialUseResponse(r, protocol.RcodeSuccess, specialUseRR(name, protocol.TypePTR, "localhost."), "")
		}
		return nil // other types follow the ordinary path
	}
	var apex string
	for _, z := range specialUseZones {
		if name == z || strings.HasSuffix(name, "."+z) {
			apex = z
			break
		}
	}
	if apex == "" {
		return nil
	}
	if name == apex {
		switch q.QType {
		case protocol.TypeSOA:
			return specialUseResponse(r, protocol.RcodeSuccess, specialUseRR(name, protocol.TypeSOA, ""), "")
		case protocol.TypeNS:
			return specialUseResponse(r, protocol.RcodeSuccess, specialUseRR(name, protocol.TypeNS, "localhost."), "")
		}
	}
	if apex == "localhost." {
		switch q.QType {
		case protocol.TypeA:
			return specialUseResponse(r, protocol.RcodeSuccess, specialUseRR(name, protocol.TypeA, "127.0.0.1"), "")
		case protocol.TypeAAAA:
			return specialUseResponse(r, protocol.RcodeSuccess, specialUseRR(name, protocol.TypeAAAA, "::1"), "")
		}
		return specialUseResponse(r, protocol.RcodeSuccess, nil, apex) // NODATA
	}
	if name == apex {
		return specialUseResponse(r, protocol.RcodeSuccess, nil, apex) // NODATA at the apex
	}
	return specialUseResponse(r, protocol.RcodeNameError, nil, apex)
}

// specialUseResponse is an authoritative answer carrying answer, or a negative
// one with soaZone's SOA in the authority section (RFC 2308).
func specialUseResponse(r *protocol.Message, rcode uint8, answer *protocol.ResourceRecord, soaZone string) *protocol.Message {
	resp := &protocol.Message{
		Header:    protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(rcode)},
		Questions: r.Questions,
	}
	resp.Header.Flags.AA = true
	if answer != nil {
		answer.Name = r.Questions[0].Name // the client's spelling (0x20)
		resp.AddAnswer(answer)
	}
	if soaZone != "" {
		if soa := specialUseRR(soaZone, protocol.TypeSOA, ""); soa != nil {
			resp.AddAuthority(soa)
		}
	}
	return resp
}

// specialUseRR builds one record of a special-use zone.
func specialUseRR(owner string, rtype uint16, rdata string) *protocol.ResourceRecord {
	if rtype == protocol.TypeSOA {
		rdata = "localhost. nobody.invalid. 1 3600 1200 604800 10800"
	}
	data := parseRData(typeToString(rtype), rdata)
	if data == nil {
		return nil
	}
	name, err := protocol.ParseName(owner)
	if err != nil {
		return nil
	}
	return &protocol.ResourceRecord{Name: name, Type: rtype, Class: protocol.ClassIN, TTL: specialUseTTL, Data: data}
}
