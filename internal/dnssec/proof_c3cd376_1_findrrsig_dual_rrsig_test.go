package dnssec

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestValidateResponse_TriesAllRRSIGs_Rollover pins RFC 4035 §5.3.3 behaviour:
// an RRset is Secure when ANY of its RRSIGs validates under the chain keys.
// During a key/algorithm rollover an authority legitimately serves an RRset
// with two RRSIGs — one from a ZSK that is no longer in the DNSKEY RRset
// (stale signature from a cache or dual-signing window) and one from the live
// ZSK. findRRSIG returned only the FIRST matching RRSIG, so a stale-key
// signature in front of a live one turned the whole response Bogus (SERVFAIL
// for a correctly-signed zone).
//
// Controls: a message with only the live RRSIG must be Secure both before and
// after (the chain fixture works — same path as
// TestValidateResponse_SubdomainSignedByParentZone), and a message with only
// the stale RRSIG must be Bogus both before and after (the stale key must not
// validate).
func TestValidateResponse_TriesAllRRSIGs_Rollover(t *testing.T) {
	v, keys := buildTwoLevelFixture(t)

	// Stale ZSK: fresh key for the same zone, NOT in the fixture's served
	// DNSKEY RRset and not covered by any DS — its signatures can never
	// validate under the chain keys.
	staleKeys := newTestZoneKeys(t, "example.com.")

	a := aRecord(t, "www.example.com.")
	rrsigLive := keys["example.com."].sign(t, "example.com.", []*protocol.ResourceRecord{a})
	rrsigStale := staleKeys.sign(t, "example.com.", []*protocol.ResourceRecord{a})

	buildMsg := func(rrs ...*protocol.ResourceRecord) *protocol.Message {
		msg := &protocol.Message{
			Header:  protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Answers: rrs,
		}
		return msg
	}

	t.Run("control_live_only_is_secure", func(t *testing.T) {
		got, err := v.ValidateResponse(context.Background(), buildMsg(a, rrsigLive), "www.example.com.")
		if err != nil {
			t.Fatalf("ValidateResponse: %v", err)
		}
		if got != ValidationSecure {
			t.Fatalf("control (live RRSIG only) = %v, want Secure — chain fixture is broken", got)
		}
	})

	t.Run("control_stale_only_is_bogus", func(t *testing.T) {
		got, err := v.ValidateResponse(context.Background(), buildMsg(a, rrsigStale), "www.example.com.")
		if err != nil {
			t.Fatalf("ValidateResponse: %v", err)
		}
		if got != ValidationBogus {
			t.Fatalf("control (stale RRSIG only) = %v, want Bogus — the stale key must not validate", got)
		}
	})

	t.Run("stale_first_live_second_is_secure", func(t *testing.T) {
		got, err := v.ValidateResponse(context.Background(), buildMsg(a, rrsigStale, rrsigLive), "www.example.com.")
		if err != nil {
			t.Fatalf("ValidateResponse: %v", err)
		}
		if got != ValidationSecure {
			t.Fatalf("dual-RRSIG rollover answer = %v, want Secure: RFC 4035 §5.3.3 requires trying every RRSIG; the first (stale-key) RRSIG must not mask the live one", got)
		}
	})
}
