package main

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/upstream"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// F656: the upstream answer for an out-of-zone CNAME target was neither
// validated nor kept out of the target's own cache entry, so a forged answer
// for a signed name reached clients through the CNAME and then, from the
// cache, direct queries that validation SERVFAILs.
func TestCNAMETargetFromUpstreamIsValidated(t *testing.T) {
	fx := buildSecureFixture(t)
	fx.resp.Answers[0].Data = &protocol.RDataA{Address: [4]byte{198, 51, 100, 99}} // RRSIG no longer covers it
	h := newTestHandler()
	uc, err := upstream.NewClient(upstream.Config{Servers: []string{signedAUpstream(t, fx)}, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	h.upstream = uc
	h.config.DNSSEC.Enabled = true
	h.validator = dnssec.NewValidator(dnssec.ValidatorConfig{Enabled: true}, fx.anchors, fx.resolver)
	addZoneRecords(t, h, "local.test.", []zone.Record{
		{Name: "www.local.test.", TTL: 300, Class: "IN", Type: "CNAME", RData: "example.com."},
	})

	w := newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "www.local.test.", protocol.TypeA))
	if w.msg == nil {
		t.Fatal("no response for the CNAME owner")
	}
	for _, rr := range w.msg.Answers {
		if rr.Type == protocol.TypeA {
			t.Fatalf("forged target A served through the CNAME: %v", rr)
		}
	}

	w = newCaptureWriter("10.0.0.1", "udp")
	h.ServeDNS(w, newTestQuery(t, "example.com.", protocol.TypeA))
	if w.msg == nil || w.msg.Header.Flags.RCODE != protocol.RcodeServerFailure {
		t.Fatalf("direct query after the CNAME: got %+v, want SERVFAIL (bogus, not cached)", w.msg)
	}
}
