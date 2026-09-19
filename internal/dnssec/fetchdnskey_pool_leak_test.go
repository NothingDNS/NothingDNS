// Regression test: fetchDNSKEY must Release the pooled message.
//
// Bug: fetchDNSKEY (validator.go:1545) calls v.resolver.Query which
// returns a pooled *protocol.Message. The function extracts DNSKEY
// records from msg.Answers and returns ONLY the records — but
// does NOT defer msg.Release(). Since protocol.UnpackMessage uses
// sync.Pool (message.go:212,442), every call leaks one pooled
// struct.
//
// Same bug class as fetchDNSKEYAndSigs (round 003) and
// fetchNSEC3PARAM (round 004) — different fix shape because
// fetchDNSKEY returns only derived records (not the message
// itself), so the fix lives at function entry: defer msg.Release().
//
// Note: fetchDNSKEY is currently dead code (no callers), but the
// leak is a defect waiting to become live if someone calls it.

package dnssec

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// dnskeyResolver returns a message with a known marker in Answers.
// After the consumer is done with it, we can inspect whether
// Release() was called by checking if Answers was cleared (which
// is what Release() does — see protocol/message.go:237-277).
type dnskeyResolver struct {
	msg *protocol.Message
}

func (r *dnskeyResolver) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	return r.msg, nil
}

// TestFetchDNSKEYReleasesPooledMessage verifies that fetchDNSKEY
// releases the pooled message. Before the fix: msg.Answers still
// populated after fetchDNSKEY returns — the leak. After the fix:
// msg.Answers cleared by Release().
func TestFetchDNSKEYReleasesPooledMessage(t *testing.T) {
	msg := protocol.NewMessage(protocol.Header{
		ID:      0xCCCC,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	q, _ := protocol.NewQuestion("example.com.", protocol.TypeDNSKEY, protocol.ClassIN)
	msg.AddQuestion(q)
	// Marker DNSKEY answer so we can detect non-release.
	msg.Answers = append(msg.Answers, &protocol.ResourceRecord{
		Name:  q.Name,
		Type:  protocol.TypeDNSKEY,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataDNSKEY{},
	})

	resolver := &dnskeyResolver{msg: msg}
	v := NewValidator(DefaultValidatorConfig(), nil, resolver)

	_, err := v.fetchDNSKEY(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEY: %v", err)
	}

	// After Release(), all section slices are cleared. If
	// fetchDNSKEY failed to Release, the Answers slice still has
	// the marker DNSKEY record we added.
	if len(msg.Answers) > 0 {
		t.Fatalf("FAIL: fetchDNSKEY pool leak — msg.Answers still has "+
			"%d record(s) after fetchDNSKEY returned. The pooled "+
			"*protocol.Message was never Release()d. Same bug class "+
			"as fetchDNSKEYAndSigs and fetchNSEC3PARAM (see commit "+
			"dac7975 and related rounds). Fix: add `defer msg.Release()` "+
			"at validator.go:1553 (immediately after the err check).",
			len(msg.Answers))
	}
	t.Logf("PASS: fetchDNSKEY released the pooled message " +
		"(msg.Answers cleared by Release)")
}
