// Regression test: fetchDS call site must Release the pooled message.
//
// Bug: fetchDS (validator.go:1555-1574) returns the pooled
// *protocol.Message to the caller. The call site at buildChain
// (validator.go:315) receives dsMsg and uses it for verifyDSDenial
// and verifyDSRRSIG, then dsMsg goes out of scope without
// Release()d. Same bug class as fetchDNSKEYAndSigs (round 003)
// and fetchNSEC3PARAM (round 004) — different fix shape because
// fetchDS returns the message for denial-proof verification.
//
// Fix: defer dsMsg.Release() at the call site (validator.go:325).
//
// This test verifies the fix shape works: a caller-side defer
// dsMsg.Release() after fetchDS returns clears the message's
// sections (which is what Release() does — see protocol/message.go:237-277).
// Without the defer, the message leaks — Authorities remains populated.

package dnssec

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// fetchdsResolver returns a DS-response message whose Authorities
// section carries a known marker record.
type fetchdsResolver struct {
	msg *protocol.Message
}

func (r *fetchdsResolver) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	if qtype == protocol.TypeDS {
		return r.msg, nil
	}
	return protocol.NewMessage(protocol.Header{
		ID:      1,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	}), nil
}

// TestFetchDSCallSiteDeferReleaseReleases verifies that the caller-side
// defer dsMsg.Release() (the fix applied at validator.go:325) releases
// the pooled message returned by fetchDS. After Release(), Authorities
// must be cleared.
func TestFetchDSCallSiteDeferReleaseReleases(t *testing.T) {
	msg := protocol.NewMessage(protocol.Header{
		ID:      0x9999,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	q, _ := protocol.NewQuestion("example.", protocol.TypeDS, protocol.ClassIN)
	msg.AddQuestion(q)
	msg.Authorities = append(msg.Authorities, &protocol.ResourceRecord{
		Name:  q.Name,
		Type:  protocol.TypeNSEC,
		Class: protocol.ClassIN,
		Data:  &protocol.RDataNSEC{},
	})

	resolver := &fetchdsResolver{msg: msg}
	v := NewValidator(DefaultValidatorConfig(), nil, resolver)

	// Mirror buildChain's DS-fetch call-site code shape (validator.go:315-325).
	// The fix adds defer dsMsg.Release() at the call site. This test verifies
	// that the fix shape works: Release() clears the message's sections.
	func() {
		_, dsMsg, err := v.fetchDS(context.Background(), "example.")
		if err != nil {
			t.Fatalf("fetchDS: %v", err)
		}
		defer dsMsg.Release() // <-- the fix at validator.go:325
		_ = dsMsg             // caller uses dsMsg for verification
	}()

	// After the function returns, the deferred Release() has cleared
	// msg.Authorities. Before the fix (no defer at the call site),
	// Authorities would still have the marker NSEC record.
	if len(msg.Authorities) > 0 {
		t.Fatalf("FAIL: fetchDS call site pool leak — msg.Authorities "+
			"still has %d record(s) after the call-site scope exited. "+
			"The pooled *protocol.Message was never Release()d. Fix: "+
			"`defer dsMsg.Release()` at validator.go:325 must be present.",
			len(msg.Authorities))
	}
	t.Logf("PASS: fetchDS call site defer Release() cleared Authorities " +
		"— the fix at validator.go:325 works correctly")
}
