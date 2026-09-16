package resolver

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// txidTestTransport captures the TXID from the query and can be configured to
// echo it back or return a different (spoofed) ID.
type txidTestTransport struct {
	returnMismatched bool // if true, return a TXID that differs from the query's
}

func (t *txidTestTransport) QueryContext(_ context.Context, msg *protocol.Message, _ string) (*protocol.Message, error) {
	resp := &protocol.Message{
		Header:    protocol.Header{Flags: protocol.Flags{QR: true}},
		Questions: msg.Questions,
	}
	if t.returnMismatched {
		// Return a guaranteed TXID mismatch.
		resp.Header.ID = msg.Header.ID + 9999
	} else {
		// Echo back the query's TXID like a well-behaved DNS server.
		resp.Header.ID = msg.Header.ID
	}
	return resp, nil
}

// TestSendQuery_RejectsTXIDMismatch verifies that sendQuery rejects responses
// whose Header.ID does not match the query's, preventing DNS response spoofing
// attacks on the iterative resolver path used by DNSSEC chain-of-trust fetches.
func TestSendQuery_RejectsTXIDMismatch(t *testing.T) {
	transport := &txidTestTransport{returnMismatched: true}
	r := NewResolver(Config{}, nil, transport)

	_, err := r.sendQuery(context.Background(), "example.com.", protocol.TypeA, "127.0.0.1:53")
	if err == nil {
		t.Fatal("sendQuery: expected TXID mismatch error, got nil")
	}
}

// TestSendQuery_AcceptsMatchingTXID is the positive control: when the upstream
// echoes the correct TXID, sendQuery must accept the response.
func TestSendQuery_AcceptsMatchingTXID(t *testing.T) {
	transport := &txidTestTransport{returnMismatched: false}
	r := NewResolver(Config{}, nil, transport)

	resp, err := r.sendQuery(context.Background(), "example.com.", protocol.TypeA, "127.0.0.1:53")
	if err != nil {
		t.Fatalf("sendQuery: unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("sendQuery: expected non-nil response")
	}
	resp.Release()
}
