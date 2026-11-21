package main

import (
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestDenial_NSECTTLIsNegativeTTL (F863): served NSEC records carry the
// lesser of the SOA MINIMUM and the SOA TTL (RFC 9077 §3), not the zone's
// $TTL — otherwise resolvers doing aggressive NSEC caching (RFC 8198) keep
// denying names for $TTL. denialZoneFile: $TTL 3600, MINIMUM 300.
func TestDenial_NSECTTLIsNegativeTTL(t *testing.T) {
	h := denialTestHandler(t)
	for _, q := range []struct {
		name  string
		qtype uint16
	}{
		{"nothere.denial.test.", protocol.TypeA}, // NXDOMAIN
		{"www.denial.test.", protocol.TypeMX},    // NODATA
	} {
		resp := askDNSSEC(t, h, q.name, q.qtype)
		nsecs, rrsigs, _ := authoritySection(resp)
		if len(nsecs) == 0 {
			t.Fatalf("%s: no NSEC", q.name)
		}
		for _, rr := range nsecs {
			if rr.TTL != 300 {
				t.Errorf("%s: NSEC %s TTL %d, want 300", q.name, rr.Name.String(), rr.TTL)
			}
		}
		for _, rr := range rrsigs {
			if sig, ok := rr.Data.(*protocol.RDataRRSIG); ok && sig.TypeCovered == protocol.TypeNSEC && sig.OriginalTTL != 300 {
				t.Errorf("%s: RRSIG(NSEC) original TTL %d, want 300", q.name, sig.OriginalTTL)
			}
		}
	}
}
