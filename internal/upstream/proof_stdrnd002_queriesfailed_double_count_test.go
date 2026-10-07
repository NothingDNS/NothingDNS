// Regression: (*LoadBalancer).queriesFailed was double-counted.
//
// CONTRACT. The sibling type (*Client) in client.go counts its queriesFailed
// exactly once per failed public Query() call — only in Query, never in a
// callee. Stats() returns (queries, failed) and the API surfaces them as
// "queries"/"failed" (internal/api/api_upstreams.go:33, response.go:236-237),
// so `failed` means "number of failed queries". A single failed query must
// therefore contribute exactly 1, and `failed` must never exceed `queries`.
//
// DEFECT. queryWithFailover incremented lb.queriesFailed on each of its four
// error returns (the circuit-breaker-open path, the no-failover-available path,
// the failover-target-breaker-open path, and the primary+failover-both-failed
// path), and then Query incremented it AGAIN (loadbalancer.go:354) as that same
// error propagated back out. Every failure reaching the public API was counted
// twice, which made the operator-facing upstream stats report failed > queries.
//
// FIX. queryWithFailover no longer touches the counter; Query owns it.
package upstream

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// deadUpstreamAddr returns a loopback address whose UDP and TCP ports are held
// by the test for its whole lifetime and fail every exchange immediately: UDP
// queries get a 1-byte (unparseable) datagram back and TCP connections are
// accepted and closed before any reply. Holding the port matters: a
// reserve-then-close address can be bound by another test binary running in
// parallel (go test ./...), which then answers the "dead" upstream and makes
// the failure-accounting tests flake (F443).
func deadUpstreamAddr(t *testing.T) string {
	t.Helper()
	var (
		l   net.Listener
		pc  net.PacketConn
		err error
	)
	for attempt := 0; attempt < 20; attempt++ {
		l, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("could not reserve a tcp port: %v", err)
		}
		pc, err = net.ListenPacket("udp", l.Addr().String())
		if err == nil {
			break
		}
		_ = l.Close()
	}
	if err != nil {
		t.Fatalf("could not reserve matching tcp+udp ports: %v", err)
	}
	t.Cleanup(func() {
		_ = l.Close()
		_ = pc.Close()
	})
	go func() {
		buf := make([]byte, 4096)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo([]byte{0}, from)
		}
	}()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return l.Addr().String()
}

func lbTestMessage(t *testing.T) *protocol.Message {
	t.Helper()
	name, err := protocol.ParseName("example.com.")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	return &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			Flags:   protocol.Flags{QR: false, Opcode: protocol.OpcodeQuery, RD: true},
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}
}

// TestLoadBalancerFailedCountedOncePerQuery pins the contract for a single
// failed query. This is the exact trigger: the dead-upstream path returns from
// queryWithFailover and then propagates out through Query.
func TestLoadBalancerFailedCountedOncePerQuery(t *testing.T) {
	lb, err := NewLoadBalancer(LoadBalancerConfig{
		Servers:  []string{deadUpstreamAddr(t)},
		Strategy: "round_robin",
		Timeout:  150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewLoadBalancer: %v", err)
	}
	defer lb.Close()

	if _, err := lb.Query(lbTestMessage(t)); err == nil {
		t.Fatal("expected the dead-upstream query to fail, but it succeeded")
	}

	queries, failed, _ := lb.Stats()
	if queries != 1 {
		t.Fatalf("expected exactly 1 query, got %d", queries)
	}
	if failed != 1 {
		t.Errorf("queriesFailed = %d after 1 failed query; want 1 (the failure was counted more than once)", failed)
	}
}

// TestLoadBalancerFailedNeverExceedsQueries covers the secondary branch the
// fix also touched: the circuit-breaker-open path inside queryWithFailover.
// After 5 failures the breaker opens, so the 6th query is rejected by
// shouldAllow() — a different error return than the one the first test drives.
// Both must still count as exactly one failure each.
func TestLoadBalancerFailedNeverExceedsQueries(t *testing.T) {
	const attempts = 6 // 5 trip the breaker (failureLimit), the 6th hits shouldAllow()==false

	lb, err := NewLoadBalancer(LoadBalancerConfig{
		Servers:  []string{deadUpstreamAddr(t)},
		Strategy: "round_robin",
		Timeout:  100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewLoadBalancer: %v", err)
	}
	defer lb.Close()

	for i := 0; i < attempts; i++ {
		if _, err := lb.Query(lbTestMessage(t)); err == nil {
			t.Fatalf("query %d unexpectedly succeeded against a dead upstream", i+1)
		}
	}

	queries, failed, _ := lb.Stats()
	if queries != attempts {
		t.Fatalf("expected %d queries, got %d", attempts, queries)
	}
	if failed != attempts {
		t.Errorf("queriesFailed = %d after %d failed queries; want %d", failed, attempts, attempts)
	}
	if failed > queries {
		t.Errorf("queriesFailed (%d) exceeds queriesTotal (%d); the failure counter is double-counting", failed, queries)
	}
}

// TestLoadBalancerSuccessfulQueryCountsNoFailure is the unaffected-path
// control: it must hold both before and after the fix, so a harness that simply
// always incremented could not masquerade as the defect.
func TestLoadBalancerSuccessfulQueryCountsNoFailure(t *testing.T) {
	addr, stop := startCountingUDPResolver(t)
	defer stop()

	lb, err := NewLoadBalancer(LoadBalancerConfig{
		Servers:  []string{addr},
		Strategy: "round_robin",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewLoadBalancer: %v", err)
	}
	defer lb.Close()

	if _, err := lb.Query(lbTestMessage(t)); err != nil {
		t.Fatalf("expected the live upstream to answer, got %v", err)
	}

	queries, failed, _ := lb.Stats()
	if queries != 1 {
		t.Fatalf("expected exactly 1 query, got %d", queries)
	}
	if failed != 0 {
		t.Errorf("queriesFailed = %d after 1 successful query; want 0", failed)
	}
}

// startCountingUDPResolver runs a minimal UDP DNS responder that answers every
// query, so the success path is exercised for real rather than mocked.
func startCountingUDPResolver(t *testing.T) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	var once sync.Once
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			query, err := protocol.UnpackMessage(buf[:n])
			if err != nil || len(query.Questions) == 0 {
				if query != nil {
					query.Release()
				}
				continue
			}
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      query.Header.ID,
					Flags:   protocol.Flags{QR: true, Opcode: protocol.OpcodeQuery, RD: true, RA: true},
					QDCount: 1, ANCount: 1,
				},
				Questions: query.Questions,
				Answers: []*protocol.ResourceRecord{{
					Name:  query.Questions[0].Name.Copy(),
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   60,
					Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
				}},
			}
			out := make([]byte, resp.WireLength())
			if wn, err := resp.Pack(out); err == nil {
				_, _ = pc.WriteTo(out[:wn], from)
			}
			// resp is a literal (not pool-acquired) whose Questions slice
			// aliases query's pooled backing array: Releasing it would hand
			// that array to messagePool while query still owns it, and the
			// client's concurrent UnpackMessage could reacquire it (F442 DATA
			// RACE). Only the pool-acquired query is Released.
			query.Release()
		}
	}()

	return pc.LocalAddr().String(), func() {
		once.Do(func() { close(done) })
		_ = pc.Close()
	}
}
