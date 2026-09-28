package resolver

// Round-17 proof: the CNAME-chase error path in internal/resolver/resolver.go
// returns a message it has already released back into protocol.messagePool.
//
// The code reads:
//
//	cnameAnswers := resp.Answers
//	target, err := r.resolve(ctx, cname, qtype, cnameDepth+1)
//	if err != nil {
//	    resp.Header.Flags.RA = true
//	    ret := resp
//	    resp = nil
//	    ret.Release()   // <- returns resp to messagePool AND zeroes it
//	    return ret, nil // <- hands that same object to the caller
//	}
//
// protocol.Message.Release() (internal/protocol/message.go:257) releases every
// Question/Answer/Authority/Additional, sets Header = Header{}, truncates every
// section to [:0], and then calls messagePool.Put(m). So at the moment `ret` is
// returned it is (a) emptied of content and (b) owned by the shared pool, which
// may hand the very same object to any other in-flight resolution.
//
// The comment says "Return the CNAME at least" — the intent is unambiguous,
// and the DNAME path directly above does it correctly (it Releases resp and
// then builds a fresh result via protocol.AcquireMessage()).
//
// REACHING THE PATH. The only way the recursive resolve() returns a non-nil
// error is its depth guard, `cnameDepth > MaxCNAMEDepth` (resolver.go:312) —
// every other failure (including an exhausted transport) degrades to
// servfail(name, qtype), nil. And MaxCNAMEDepth==0 is silently rewritten to 16
// by NewResolver (resolver.go:192), so the guard needs a real value. This test
// therefore uses MaxCNAMEDepth=1 and a TWO-level chain a->b->c: resolve(c, 2)
// trips the guard, resolve(b, 1) takes the error path, and the released message
// is returned as `target` to resolve(a, 0), which then hands it straight back
// as its own result.
//
// THE PROOF. resolve() is called directly (the exported Resolve() copies its
// result, which hides pool ownership). If the returned message is the one the
// resolver just Released, then the very next AcquireMessage() — which any
// concurrent request performs constantly — returns the SAME pointer, proving the
// caller holds a live reference into the shared pool.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// chainTransport answers with a CNAME to next for every name except the final
// target, which it answers with an A record.
type chainTransport struct {
	next  string // CNAME target for the first hop
	final string // final name, answered with an A record
	hops  []string
}

func (t *chainTransport) QueryContext(ctx context.Context, msg *protocol.Message, addr string) (*protocol.Message, error) {
	qname := ""
	if len(msg.Questions) > 0 && msg.Questions[0] != nil && msg.Questions[0].Name != nil {
		qname = msg.Questions[0].Name.String()
	}
	t.hops = append(t.hops, qname)

	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    msg.Header.ID,
			Flags: protocol.Flags{QR: true, AA: true, RCODE: protocol.RcodeSuccess},
		},
	}

	if qname == t.final {
		owner, err := protocol.ParseName(qname)
		if err != nil {
			return nil, err
		}
		resp.AddAnswer(&protocol.ResourceRecord{
			Name: owner, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 60,
			Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 7}},
		})
		return resp, nil
	}

	owner, err := protocol.ParseName(qname)
	if err != nil {
		return nil, err
	}
	cnameTarget, err := protocol.ParseName(t.next)
	if err != nil {
		return nil, err
	}
	resp.AddAnswer(&protocol.ResourceRecord{
		Name: owner, Type: protocol.TypeCNAME, Class: protocol.ClassIN, TTL: 300,
		Data: &protocol.RDataCNAME{CName: cnameTarget},
	})
	return resp, nil
}

func newChainResolver(t *testing.T, tr Transport, maxCNAMEDepth int) *Resolver {
	t.Helper()
	return NewResolver(Config{
		MaxDepth:      5,
		MaxCNAMEDepth: maxCNAMEDepth, // must be non-zero: 0 is rewritten to 16
		Timeout:       2 * time.Second,
		Hints:         []RootHint{{Name: "fake.root.", IPv4: []string{"127.0.0.1"}}},
	}, nil, tr)
}

// TestCNAMEChaseError_ReturnedMessageIsNotPoolOwned is the CLAIM.
func TestCNAMEChaseError_ReturnedMessageIsNotPoolOwned(t *testing.T) {
	tr := &chainTransport{next: "b.example.com.", final: "c.example.com."}
	r := newChainResolver(t, tr, 1)

	ret, err := r.resolve(context.Background(), "a.example.com.", protocol.TypeA, 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ret == nil {
		t.Fatalf("harness setup: resolve returned nil message")
	}

	// Drain the pool. Anything the resolver Released is handed back here.
	// AcquireMessage() runs reset(), so compare identity BEFORE inspecting.
	pooled := protocol.AcquireMessage()
	if pooled == ret {
		t.Fatalf("FAIL: resolve() returned a message it had already Release()d into "+
			"protocol.messagePool (ptr %p). The CNAME-chase error path does "+
			"ret.Release(); return ret, nil. The caller now holds a reference "+
			"into the shared pool: a concurrent AcquireMessage() can hand it the "+
			"same object and overwrite it mid-use, and Release() will later "+
			"double-Put it. hops=%v", ret, tr.hops)
	}
	pooled.Release()

	t.Logf("PASS: returned message is not pool-owned")
}

// TestCNAMEChaseError_ChainNotTruncated is the CLAIM's user-visible half: the
// released-and-returned message is emptied, so the CNAME chain the comment
// promises to "return at least" is silently truncated.
func TestCNAMEChaseError_ChainNotTruncated(t *testing.T) {
	tr := &chainTransport{next: "b.example.com.", final: "c.example.com."}
	r := newChainResolver(t, tr, 1)

	ret, err := r.resolve(context.Background(), "a.example.com.", protocol.TypeA, 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	names := make([]string, 0, len(ret.Answers))
	for _, rr := range ret.Answers {
		if rr != nil && rr.Name != nil {
			names = append(names, rr.Name.String())
		}
	}
	// The full chain is a -> b -> c. Losing the second hop means the resolver
	// returned an answer for a name the client never asked about.
	if len(names) < 2 {
		t.Fatalf("FAIL: CNAME chain truncated: got answers for %v, expected at "+
			"least a.example.com. and b.example.com. The error path returned the "+
			"CNAME-bearing response after Release() had already emptied it, and the "+
			"parent merged against that empty message. hops=%v", names, tr.hops)
	}
	t.Logf("PASS: chain preserved: %v", names)
}

// TestCNAMEChaseSuccess_Unaffected is the CONTROL: a single-hop chain within
// the depth budget must resolve fully. A harness that merely breaks everything
// could not pass this.
func TestCNAMEChaseSuccess_Unaffected(t *testing.T) {
	tr := &chainTransport{next: "b.example.com.", final: "b.example.com."}
	r := newChainResolver(t, tr, 16)

	msg, err := r.Resolve(context.Background(), "a.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	var sawCNAME, sawA bool
	for _, rr := range msg.Answers {
		if rr == nil {
			continue
		}
		switch rr.Type {
		case protocol.TypeCNAME:
			sawCNAME = true
		case protocol.TypeA:
			sawA = true
		}
	}
	if !sawCNAME || !sawA {
		t.Fatalf("FAIL: single-hop chase must merge CNAME and target A "+
			"(cname=%v a=%v, answers=%d, hops=%v)", sawCNAME, sawA, len(msg.Answers), tr.hops)
	}
	t.Logf("PASS: single-hop chase merged CNAME + A across %d answers", len(msg.Answers))
}

// TestCNAMEChaseSuccess_NotPoolOwned is a second CONTROL: a successful chase
// must also return a message the caller exclusively owns.
func TestCNAMEChaseSuccess_NotPoolOwned(t *testing.T) {
	tr := &chainTransport{next: "b.example.com.", final: "b.example.com."}
	r := newChainResolver(t, tr, 16)

	ret, err := r.resolve(context.Background(), "a.example.com.", protocol.TypeA, 0)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	pooled := protocol.AcquireMessage()
	if pooled == ret {
		t.Fatalf("FAIL: successful chase also returned a pool-owned message")
	}
	pooled.Release()
	t.Logf("PASS: successful chase returns a caller-owned message")
}

var _ = fmt.Sprintf // keep fmt imported if the harness is trimmed
