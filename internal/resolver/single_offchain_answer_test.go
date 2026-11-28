package resolver

import (
	"context"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func resolveSingleAnswerOwnerF903(t *testing.T, owner string) *protocol.Message {
	t.Helper()
	transport := newMockTransport()
	transport.setAllRootHandlers(func(query *protocol.Message) *protocol.Message {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: query.Header.ID, Flags: protocol.Flags{QR: true, AA: true}},
			Questions: query.Questions,
		}
		resp.AddAnswer(makeARR(owner, "192.0.2.53"))
		return resp
	})
	cfg := DefaultConfig()
	cfg.AllowPrivateUpstream = true
	cfg.QnameMinimization = false
	r := NewResolver(cfg, nil, transport)
	resp, err := r.Resolve(context.Background(), "www.example.test.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return resp
}

// RFC 5452 section 6 requires accepting data only for the domain queried.
// A single off-chain RR is no safer than the same RR beside a valid answer.
func TestResolveRejectsSingleOffChainAnswer_F903(t *testing.T) {
	control := resolveSingleAnswerOwnerF903(t, "www.example.test.")
	if len(control.Answers) != 1 || control.Answers[0].Name.String() != "www.example.test." {
		t.Fatalf("CONTROL FAILED: direct answer = %v", owners(control))
	}
	t.Log("CONTROL OK: a single answer owned by the queried name was preserved")

	got := resolveSingleAnswerOwnerF903(t, "poison.attacker.test.")
	if len(got.Answers) != 0 {
		t.Log("EXPECTED: the answer section is empty because its only owner is off-chain")
		t.Logf("ACTUAL: answer owners = %v", owners(got))
		t.Fatal("PROBLEM CONFIRMED: single off-chain Answer record bypassed pruning")
	}
	t.Log("PROBLEM NOT REPRODUCED: single off-chain Answer record was rejected")
}

func TestPruneSingleAnswerBoundaries_F903(t *testing.T) {
	t.Run("matching A stays", func(t *testing.T) {
		msg := &protocol.Message{Answers: []*protocol.ResourceRecord{aRR(t, "www.example.test.", 1)}}
		pruneAnswerToChain(msg, "www.example.test.", protocol.TypeA)
		if len(msg.Answers) != 1 {
			t.Fatalf("FIX NOT VERIFIED: matching A was removed")
		}
	})
	t.Run("matching CNAME stays", func(t *testing.T) {
		msg := &protocol.Message{Answers: []*protocol.ResourceRecord{cnameRR(t, "www.example.test.", "target.example.test.")}}
		pruneAnswerToChain(msg, "www.example.test.", protocol.TypeA)
		if len(msg.Answers) != 1 {
			t.Fatalf("FIX NOT VERIFIED: matching CNAME was removed")
		}
	})
	t.Run("empty and nil are safe", func(t *testing.T) {
		pruneAnswerToChain(nil, "www.example.test.", protocol.TypeA)
		msg := &protocol.Message{}
		pruneAnswerToChain(msg, "www.example.test.", protocol.TypeA)
		if len(msg.Answers) != 0 {
			t.Fatalf("FIX NOT VERIFIED: empty answer changed")
		}
	})
	t.Log("FIX VERIFIED: single-answer chain boundaries are preserved while off-chain data is pruned")
}
