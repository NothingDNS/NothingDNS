// Proof of TXID-bypass in resolver.sendQuery() — the path feeding the
// DNSSEC validator's chain-of-trust fetches.
//
// Bug: sendQuery() generates a random transaction ID via nextSecureID()
// but does NOT verify that the response's Header.ID matches the query's.
// It returns resp unconditionally. An on-path attacker (or a buggy/
// misbehaving nameserver that echoes the wrong transaction ID) can
// therefore inject a response whose ID differs from the one we sent,
// and the resolver — and the DNSSEC validator feeding off it — will
// accept the mismatched answer as the response to THIS query.
//
// Impact: the DNSSEC validator's fetchDS / fetchDNSKEYAndSigs /
// fetchNSEC3PARAM path goes through r.Resolve() → r.resolve() →
// r.queryDelegation() → r.sendQuery(). A forged DNSKEY/DS/NSEC3PARAM
// with a mismatched ID would be accepted and authenticated by the
// chain-of-trust logic, compromising DNSSEC validation for the entire
// subtree.
//
// This is the same bug class that was fixed in earlier rounds for
// upstream.Client.queryUDP/queryTCP (commit dac7975) and the
// LoadBalancer (memory 01M1PHJT9DRKY835ZPZEV7R6N0), but the
// iterative resolver's sendQuery was missed.
//
// Proof approach: directly invoke sendQuery() with a fake Transport
// that always returns a response whose ID is a known constant (0xDEAD),
// regardless of the query's actual ID. Before the fix, sendQuery returns
// the mismatched response with no error. After the fix, sendQuery returns
// an explicit "TXID mismatch" error and releases the pooled response.

package resolver

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// mismatchedIDTransport is a Transport stub that returns a response
// whose transaction ID is always the configured value (0xDEAD),
// regardless of the query's actual ID. It echoes the question so
// question-mismatch guards (added in earlier rounds) cannot reject the
// response on those grounds — the ONLY way the resolver can reject it
// is by checking the transaction ID.
type mismatchedIDTransport struct {
	calls atomic.Int32
}

func (m *mismatchedIDTransport) QueryContext(_ context.Context, q *protocol.Message, _ string) (*protocol.Message, error) {
	m.calls.Add(1)
	if len(q.Questions) == 0 {
		return &protocol.Message{
			Header: protocol.Header{ID: 0xDEAD, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		}, nil
	}
	return &protocol.Message{
		Header: protocol.Header{
			ID:      0xDEAD, // deliberately mismatched
			Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
			QDCount: 1,
			ANCount: 1,
		},
		Questions: q.Questions,
		Answers: []*protocol.ResourceRecord{
			{
				Name:  q.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 99}},
			},
		},
	}, nil
}

// TestSendQuery_RejectsTXIDMismatch is the deterministic reproduction.
// It must FAIL before the fix (sendQuery accepts a response whose
// transaction ID differs from the one we sent) and PASS after.
func TestSendQuery_RejectsTXIDMismatch(t *testing.T) {
	tr := &mismatchedIDTransport{}
	r := NewResolver(Config{
		Timeout:      2 * time.Second,
		EDNS0BufSize: 4096,
		DNSSECOK:     false,
	}, nil, tr)

	// Directly invoke sendQuery with the fake transport. The query's
	// TXID is a random nextSecureID() value; the response's TXID is
	// always 0xDEAD from the fake transport.
	msg, err := r.sendQuery(context.Background(), "example.com.", protocol.TypeA, "127.0.0.1:53")
	if err == nil {
		// Pre-fix behavior: sendQuery returned the mismatched response
		// with no error. This is the security defect.
		t.Fatalf("FAIL: sendQuery accepted response with mismatched TXID "+
			"(resp.ID=%#x, expected random ID; transport always sends 0xDEAD). "+
			"The DNSSEC chain-of-trust fetches that route through "+
			"sendQuery would also accept this — a forged DNSKEY/DS "+
			"response could authenticate the chain.", msg.Header.ID)
	}
	if msg != nil {
		t.Fatalf("FAIL: sendQuery returned non-nil msg alongside error: %v", err)
	}
	if !strings.Contains(err.Error(), "TXID mismatch") {
		t.Fatalf("FAIL: expected TXID mismatch error, got: %v", err)
	}
	// Verify sendQuery was actually exercised.
	if tr.calls.Load() == 0 {
		t.Fatalf("FAIL: transport was never called — test didn't exercise sendQuery")
	}
	// Post-fix expectation: a TXID-mismatch error, and the transport
	// was called at least once.
	t.Logf("PASS: sendQuery rejected TXID-mismatched response after %d call(s): %v",
		tr.calls.Load(), err)
}

// TestSendQuery_AcceptsMatchingTXID is a positive control: with the
// fake transport returning responses whose ID echoes the query's,
// sendQuery must succeed. This guards against an over-eager fix that
// rejects ALL responses.
func TestSendQuery_AcceptsMatchingTXID(t *testing.T) {
	tr := &echoingTransport{}
	r := NewResolver(Config{
		Timeout:      2 * time.Second,
		EDNS0BufSize: 4096,
		DNSSECOK:     false,
	}, nil, tr)

	msg, err := r.sendQuery(context.Background(), "example.com.", protocol.TypeA, "127.0.0.1:53")
	if err != nil {
		t.Fatalf("FAIL: sendQuery rejected matching-TXID response: %v", err)
	}
	if msg == nil {
		t.Fatalf("FAIL: sendQuery returned nil msg without error")
	}
	if msg.Header.ID == 0xDEAD {
		t.Fatalf("FAIL: sendQuery returned the mismatched ID (0xDEAD) — test not exercising the fix correctly")
	}
	t.Logf("PASS: sendQuery accepted matching-TXID response (ID=%#x)", msg.Header.ID)
}

// echoingTransport returns responses whose ID ECHOES the query's ID.
// This is the well-behaved-nameserver baseline.
type echoingTransport struct{}

func (e *echoingTransport) QueryContext(_ context.Context, q *protocol.Message, _ string) (*protocol.Message, error) {
	if len(q.Questions) == 0 {
		return &protocol.Message{
			Header: protocol.Header{ID: q.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
		}, nil
	}
	return &protocol.Message{
		Header: protocol.Header{
			ID:      q.Header.ID, // echo: ID matches the query
			Flags:   protocol.NewResponseFlags(protocol.RcodeSuccess),
			QDCount: 1,
			ANCount: 1,
		},
		Questions: q.Questions,
		Answers: []*protocol.ResourceRecord{
			{
				Name:  q.Questions[0].Name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 99}},
			},
		},
	}, nil
}
