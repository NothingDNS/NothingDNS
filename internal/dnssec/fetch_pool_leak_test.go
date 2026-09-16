// Proof of pool leak in fetchDNSKEYAndSigs.
//
// Bug: fetchDNSKEYAndSigs (validator.go:497-516) takes a pooled
// *protocol.Message from v.resolver.Query, iterates msg.Answers to
// extract DNSKEY and RRSIG records, and returns ONLY the extracted
// records. The message itself is never Release()d. Since
// v.resolver.Query returns a pooled message (see messagePool in
// internal/protocol/message.go), failing to Release leaks the message
// from the pool.
//
// Impact: under sustained DNSSEC validation load (every chain build
// fetches DNSKEY/DS/NSEC3PARAM), the pool drains. New allocations
// fall back to the pool's New function, which is more expensive than
// recycling. Long-running validators eventually run out of pool slots
// and degrade. The same class of bug was fixed in many other DNSSEC
// code paths (see commit dac7975 and related rounds).
//
// Proof approach: install a Resolver that returns a *Message with
// non-empty sections. After fetchDNSKEYAndSigs returns, inspect the
// same message object — if Release() was called, its sections are
// cleared (see protocol.Message.Release() implementation at
// internal/protocol/message.go:237-277). Before the fix: sections
// still populated. After the fix: sections cleared.

package dnssec

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// instrumentedResolver returns a single message whose sections are
// populated. After the consumer is done with it, we can inspect
// whether Release() was called by checking if sections were cleared.
type instrumentedResolver struct {
	msg *protocol.Message
}

func (r *instrumentedResolver) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	// Add a dummy DNSKEY answer so fetchDNSKEYAndSigs has something
	// to extract. The dummy record is minimal — just enough to
	// populate msg.Answers so we can detect non-release.
	msg := r.msg
	parsedName, err := protocol.ParseName(name)
	if err != nil {
		return nil, err
	}
	msg.Answers = append(msg.Answers, &protocol.ResourceRecord{
		Name:  parsedName,
		Type:  protocol.TypeDNSKEY,
		Class: protocol.ClassIN,
		TTL:   300,
		Data:  &protocol.RDataDNSKEY{},
	})
	return msg, nil
}

// TestFetchDNSKEYAndSigsReleasesPooledMessage is the deterministic
// reproduction. It must FAIL before the fix (fetchDNSKEYAndSigs never
// calls msg.Release()) and PASS after.
func TestFetchDNSKEYAndSigsReleasesPooledMessage(t *testing.T) {
	// Build a message via the pool, then hand it to the resolver.
	// After fetchDNSKEYAndSigs returns, check whether the message's
	// sections were cleared (which is what Release() does — see
	// protocol/message.go:237-277).
	msg := protocol.NewMessage(protocol.Header{
		ID:      0x1234,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	q, _ := protocol.NewQuestion("example.com.", protocol.TypeDNSKEY, protocol.ClassIN)
	msg.AddQuestion(q)

	resolver := &instrumentedResolver{msg: msg}
	v := NewValidator(DefaultValidatorConfig(), nil, resolver)

	_, _, err := v.fetchDNSKEYAndSigs(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("fetchDNSKEYAndSigs: %v", err)
	}

	// After Release(), all section slices are nil'd to length 0.
	// If fetchDNSKEYAndSigs failed to Release, the Answers slice
	// still has the dummy DNSKEY record we added.
	if len(msg.Answers) > 0 {
		t.Fatalf("FAIL: fetchDNSKEYAndSigs pool leak — msg.Answers still has "+
			"%d record(s) after fetchDNSKEYAndSigs returned. The pooled "+
			"*protocol.Message was never Release()d. Under sustained DNSSEC "+
			"validation load this drains the messagePool (internal/protocol/"+
			"message.go:212) and forces expensive NewMessage allocations on "+
			"every subsequent fetch.", len(msg.Answers))
	}
	t.Logf("PASS: fetchDNSKEYAndSigs released the pooled message " +
		"(msg.Answers cleared by Release)")
}
