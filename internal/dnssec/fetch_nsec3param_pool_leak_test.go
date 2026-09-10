// Proof of pool leak in fetchNSEC3PARAM.
//
// Bug: fetchNSEC3PARAM (validator.go:1741-1759) takes a pooled
// *protocol.Message from v.resolver.Query, iterates msg.Answers to
// extract NSEC3PARAM records, and returns ONLY the extracted records
// (or nil if no NSEC3PARAM found). The message itself is never
// Release()d. Since v.resolver.Query returns a pooled message (see
// messagePool in internal/protocol/message.go), failing to Release
// leaks the message from the pool.
//
// This is the same bug class as fetchDNSKEYAndSigs (fixed in the
// previous round, commit dac7975 and related). Both are DNSSEC
// chain-build fetch helpers that take a pooled message and return
// only derived records, forgetting to Release the message.
//
// Impact: under sustained DNSSEC validation load (every chain build
// fetches DNSKEY/DS/NSEC3PARAM), the pool drains. New allocations
// fall back to the pool's New function, which is more expensive than
// recycling.
//
// Proof approach: install a Resolver that returns a *Message with
// non-empty sections. After fetchNSEC3PARAM returns, inspect the
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

// nsec3paramResolver returns a single message whose sections are
// populated. After the consumer is done with it, we can inspect
// whether Release() was called by checking if sections were cleared.
type nsec3paramResolver struct {
	msg *protocol.Message
}

func (r *nsec3paramResolver) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	msg := r.msg
	parsedName, err := protocol.ParseName(name)
	if err != nil {
		return nil, err
	}
	msg.Answers = append(msg.Answers, &protocol.ResourceRecord{
		Name:  parsedName,
		Type:  protocol.TypeNSEC3PARAM,
		Class: protocol.ClassIN,
		TTL:   0,
		Data:  &protocol.RDataNSEC3PARAM{},
	})
	return msg, nil
}

// TestFetchNSEC3PARAMReleasesPooledMessage is the deterministic
// reproduction. It must FAIL before the fix (fetchNSEC3PARAM never
// calls msg.Release()) and PASS after.
func TestFetchNSEC3PARAMReleasesPooledMessage(t *testing.T) {
	msg := protocol.NewMessage(protocol.Header{
		ID:      0x5678,
		Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
		QDCount: 1,
	})
	q, _ := protocol.NewQuestion("example.com.", protocol.TypeNSEC3PARAM, protocol.ClassIN)
	msg.AddQuestion(q)

	resolver := &nsec3paramResolver{msg: msg}
	v := NewValidator(DefaultValidatorConfig(), nil, resolver)

	_, err := v.fetchNSEC3PARAM(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("fetchNSEC3PARAM: %v", err)
	}

	// After Release(), all section slices are nil'd to length 0.
	// If fetchNSEC3PARAM failed to Release, the Answers slice
	// still has the dummy NSEC3PARAM record we added.
	if len(msg.Answers) > 0 {
		t.Fatalf("FAIL: fetchNSEC3PARAM pool leak — msg.Answers still has "+
			"%d record(s) after fetchNSEC3PARAM returned. The pooled "+
			"*protocol.Message was never Release()d. Under sustained DNSSEC "+
			"validation load this drains the messagePool (internal/protocol/"+
			"message.go:212) and forces expensive NewMessage allocations on "+
			"every subsequent fetch.", len(msg.Answers))
	}
	t.Logf("PASS: fetchNSEC3PARAM released the pooled message " +
		"(msg.Answers cleared by Release)")
}
