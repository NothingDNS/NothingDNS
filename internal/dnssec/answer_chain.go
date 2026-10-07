package dnssec

import (
	"context"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// answerChain describes the CNAME/DNAME chain an Answer section follows from
// the query name (F527, F528).
type answerChain struct {
	// synthesized holds the lower-case owners of unsigned CNAME RRsets that
	// are exactly the CNAME a DNAME in the same Answer section synthesizes
	// (RFC 6672 §3.1, §5.3.1): they are authenticated by that DNAME's
	// signature, not their own.
	synthesized map[string]bool
	// terminal is the chain's last name when the Answer section holds no
	// data of the query type there: the RCODE and the Authority denial then
	// belong to it (RFC 6604 §2.1) and must be proven by its zone.
	terminal string
	open     bool
}

type answerDNAME struct {
	owner, target string // canonical
	ttl           uint32
}

// walkAnswerChain follows the CNAMEs (and the CNAMEs DNAMEs synthesize) from
// queryName through the Answer section. The walk visits each name once, so it
// is bounded by the number of Answer RRsets (maxRRsetsValidated); a loop ends
// it without a terminal. Without a question there is no query type to look
// for: the chain is not walked (validateNegativeProof needs one as well).
func walkAnswerChain(msg *protocol.Message, queryName string) answerChain {
	answers := msg.Answers
	types := map[string]map[uint16]int{} // owner -> type -> record count
	cnames := map[string]*protocol.ResourceRecord{}
	signedCNAME := map[string]bool{}
	var dnames []answerDNAME
	for _, rr := range answers {
		if rr == nil || rr.Name == nil {
			continue
		}
		owner := canonicalZone(rr.Name.String())
		if types[owner] == nil {
			types[owner] = map[uint16]int{}
		}
		types[owner][rr.Type]++
		switch d := rr.Data.(type) {
		case *protocol.RDataCNAME:
			if rr.Type == protocol.TypeCNAME && d.CName != nil {
				cnames[owner] = rr
			}
		case *protocol.RDataDNAME:
			if rr.Type == protocol.TypeDNAME && d.DName != nil {
				dnames = append(dnames, answerDNAME{owner: owner, target: canonicalZone(d.DName.String()), ttl: rr.TTL})
			}
		case *protocol.RDataRRSIG:
			if d.TypeCovered == protocol.TypeCNAME {
				signedCNAME[owner] = true
			}
		}
	}

	// applicableDNAME returns the DNAME redirecting name: the shallowest one
	// owned by a proper ancestor (a DNAME occludes everything below it, so a
	// deeper one cannot be live data, RFC 6672 §2.4). A DNAME RRset must be a
	// single record.
	applicableDNAME := func(name string) (answerDNAME, bool) {
		var best answerDNAME
		found := false
		for _, d := range dnames {
			if d.owner == name || !inBailiwick(name, d.owner) {
				continue
			}
			if !found || len(d.owner) < len(best.owner) {
				best, found = d, true
			}
		}
		if !found || types[best.owner][protocol.TypeDNAME] != 1 {
			return answerDNAME{}, false
		}
		return best, true
	}
	// synthesize derives the CNAME target for name from d (RFC 6672 §2.2):
	// the owner suffix replaced by the DNAME target.
	synthesize := func(name string, d answerDNAME) (string, bool) {
		prefix := name[:len(name)-len(d.owner)]
		if d.owner == "." {
			prefix = name
		}
		target := prefix + d.target
		if d.target == "." {
			target = prefix
		}
		if len(target) > 254 { // 255 octets in wire form: YXDOMAIN, no CNAME
			return "", false
		}
		return target, true
	}

	out := answerChain{synthesized: map[string]bool{}}
	for owner, rr := range cnames {
		if signedCNAME[owner] || types[owner][protocol.TypeCNAME] != 1 {
			continue
		}
		d, ok := applicableDNAME(owner)
		if !ok {
			continue
		}
		target, ok := synthesize(owner, d)
		// The synthesized CNAME's TTL is the DNAME's (RFC 6672 §3.1; 0 from
		// RFC 2672 servers, §5.3.1): it must never outlive the DNAME.
		if ok && rr.TTL <= d.ttl && target == canonicalZone(rr.Data.(*protocol.RDataCNAME).CName.String()) {
			out.synthesized[owner] = true
		}
	}

	if len(msg.Questions) == 0 || msg.Questions[0] == nil {
		return out
	}
	qtype := msg.Questions[0].QType
	name := canonicalZone(queryName)
	seen := map[string]bool{}
	for !seen[name] {
		seen[name] = true
		has := types[name]
		switch {
		case qtype == protocol.TypeANY:
			for t := range has {
				if t != protocol.TypeRRSIG {
					return out
				}
			}
		case has[qtype] > 0:
			return out
		}
		// A DNAME above name occludes any CNAME at name (RFC 6672 §2.4):
		// only its own derivation is followed.
		if d, ok := applicableDNAME(name); ok {
			target, ok := synthesize(name, d)
			if !ok {
				return out // YXDOMAIN: the DNAME alone is the answer (RFC 6672 §2.2)
			}
			name = target
			continue
		} else if rr := cnames[name]; rr != nil {
			name = canonicalZone(rr.Data.(*protocol.RDataCNAME).CName.String())
			continue
		}
		out.terminal, out.open = name, true
		return out
	}
	return out // CNAME loop: no terminal name
}

// denialSigner returns the deepest RRSIG signer, at or above name, of an
// Authority SOA/NSEC/NSEC3 RRset: the zone claiming to deny name.
func denialSigner(msg *protocol.Message, name string) string {
	best := ""
	for _, rr := range msg.Authorities {
		if rr == nil || rr.Type != protocol.TypeRRSIG {
			continue
		}
		sig, ok := rr.Data.(*protocol.RDataRRSIG)
		if !ok || sig.SignerName == nil {
			continue
		}
		switch sig.TypeCovered {
		case protocol.TypeSOA, protocol.TypeNSEC, protocol.TypeNSEC3:
		default:
			continue
		}
		signer := canonicalZone(sig.SignerNameString())
		if inBailiwick(name, signer) && len(signer) > len(best) {
			best = signer
		}
	}
	return best
}

// validateChainTerminal validates the negative ending of a CNAME/DNAME chain:
// terminal has no data of the query type in the Answer section, so the
// Authority section must prove it (NXDOMAIN or NODATA per the RCODE) with the
// denial of terminal's own zone, validated through that zone's chain (charged
// to the response budget via chainFor). A signed zone without such a proof is
// a stripped answer or a forged negative ending: Bogus. A proven-unsigned
// zone, or an Opt-Out proof, is Insecure.
func (v *Validator) validateChainTerminal(ctx context.Context, msg *protocol.Message, terminal string, chains map[string]chainResult, noCut map[string]bool) ValidationResult {
	signer := denialSigner(msg, terminal)
	target := signer
	if target == "" {
		target = terminal
	}
	c := v.chainFor(ctx, target, chains)
	switch {
	case c.err != nil:
		return ValidationBogus
	case c.insecure:
		return ValidationInsecure
	case signer == "" || len(c.chain) == 0:
		return ValidationBogus
	}
	result, encloser := v.validateNegativeProof(msg, terminal, c.chain)
	if result == ValidationBogus {
		return ValidationBogus
	}
	if !v.noZoneCutBelowSigner(ctx, c.chain, terminal, uint8(min(len(splitLabels(encloser)), 255)), noCut) {
		return ValidationBogus
	}
	return result
}

// dnameSigner returns the in-bailiwick signer of a DNAME RRSIG in answers
// owned by a proper ancestor of queryName: the zone authenticating an answer
// whose query-name CNAME was synthesized from that DNAME (F527).
func dnameSigner(answers []*protocol.ResourceRecord, queryName string) string {
	for _, rr := range answers {
		if rr == nil || rr.Name == nil || rr.Type != protocol.TypeRRSIG {
			continue
		}
		sig, ok := rr.Data.(*protocol.RDataRRSIG)
		if !ok || sig.SignerName == nil || sig.TypeCovered != protocol.TypeDNAME {
			continue
		}
		owner := rr.Name.String()
		signer := sig.SignerNameString()
		if !sameDNSName(owner, queryName) && inBailiwick(queryName, owner) && inBailiwick(owner, signer) {
			return canonicalZone(signer)
		}
	}
	return ""
}

// isSynthesizedCNAME reports whether rrSet is an unsigned CNAME derived from
// a DNAME of the same Answer section (see walkAnswerChain).
func (c answerChain) isSynthesizedCNAME(rrSet []*protocol.ResourceRecord) bool {
	return len(rrSet) == 1 && rrSet[0].Type == protocol.TypeCNAME && c.synthesized[canonicalZone(rrSet[0].Name.String())]
}
