// NothingDNS - RPZ precedence across pipeline stages
//
// draft-vixie-dnsop-dns-rpz-00 §5: of all the rules matched for a query only
// one affects the response, "even if the selected rule has a PASSTHRU
// action" (§5.1), chosen by policy zone order (§5.2) and, within a zone, by
// trigger type: client IP, QNAME, response IP, NSDNAME, NSIP (§5.4). The
// pipeline checks the triggers in that order, one stage at a time, and a
// PASSTHRU match only let the query continue: a QNAME exemption was still
// blocked by a response-IP rule of the same or a later zone (F885).

package main

import (
	"github.com/nothingdns/nothingdns/internal/rpz"
	"github.com/nothingdns/nothingdns/internal/server"
)

// rpzQueryState is the RPZ state of one query: the PASSTHRU rule selected
// for it, and whether that rule, being a client-IP rule, let through an
// answer other clients must not get from the cache (a cache hit is not
// checked against response rules again).
type rpzQueryState struct {
	passthru    *rpz.Rule
	uncacheable bool
}

// rpzPassthruWriter carries the RPZ state for a response checked outside the
// pipeline (a prefetch refresh).
type rpzPassthruWriter struct {
	server.ResponseWriter
	state rpzQueryState
}

func (w *rpzPassthruWriter) Unwrap() server.ResponseWriter { return w.ResponseWriter }

// rpzStateOf returns the RPZ state of the query answered through w, or nil
// when w carries none.
func rpzStateOf(w server.ResponseWriter) *rpzQueryState {
	for w != nil {
		switch t := w.(type) {
		case *headerPolicyResponseWriter:
			return &t.rpz
		case *rpzPassthruWriter:
			return &t.state
		}
		u, ok := w.(interface{ Unwrap() server.ResponseWriter })
		if !ok {
			return nil
		}
		w = u.Unwrap()
	}
	return nil
}

// rpzOverruledByPassthru reports whether rule must be ignored because a
// PASSTHRU rule already selected for this query outranks it — every rule not
// from a strictly earlier policy zone, since earlier stages check
// higher-ranked trigger types — and records rule when it is a PASSTHRU that
// takes effect.
func rpzOverruledByPassthru(w server.ResponseWriter, rule *rpz.Rule) bool {
	st := rpzStateOf(w)
	if st == nil {
		return false
	}
	if p := st.passthru; p != nil && !rule.Precedes(p) {
		if p.Trigger == rpz.TriggerClientIP {
			st.uncacheable = true
		}
		return true
	}
	if rule.Action == rpz.ActionPassThrough {
		st.passthru = rule
	}
	return false
}

// rpzQNAMEOutranks reports whether a QNAME rule of a strictly earlier policy
// zone matches qname, which outranks the client-IP rule (§5.2 before §5.4);
// rpzQnameStage then applies it.
func rpzQNAMEOutranks(eng *rpz.Engine, qname string, clientRule *rpz.Rule) bool {
	r := eng.QNAMEPolicy(qname)
	return r != nil && r.Precedes(clientRule)
}
