package upstream

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// When anycast_groups and upstream.servers are both configured, the anycast
// backends are tried first and the standalone servers are the fallback: used
// when no anycast backend is healthy, and as the failover target when the
// anycast backend that was tried fails. They used to be built and never
// selected.
func TestStandaloneServersBackAnycastGroups(t *testing.T) {
	good, cleanup := failoverMockServer(t)
	defer cleanup()
	host, portStr, _ := net.SplitHostPort(good)
	port, _ := strconv.Atoi(portStr)

	build := func(t *testing.T, anycastAddrIsLive bool) (*LoadBalancer, *AnycastBackend, *Server) {
		t.Helper()
		backend := &AnycastBackend{PhysicalIP: "127.0.0.1", Port: 1, Region: "r1"} // nothing listens
		if anycastAddrIsLive {
			backend = &AnycastBackend{PhysicalIP: host, Port: port, Region: "r1"}
		}
		group := NewAnycastGroup("10.0.0.1", time.Minute, time.Second)
		if err := group.AddBackend(backend); err != nil {
			t.Fatal(err)
		}
		standalone := &Server{Address: good, healthy: true, Timeout: 2 * time.Second, latency: time.Millisecond}
		lb := newFailoverTestLB([]*Server{standalone}, RoundRobin)
		lb.timeout = 300 * time.Millisecond
		lb.anycastGroups[group.AnycastIP] = group
		return lb, backend, standalone
	}

	t.Run("a healthy anycast backend is preferred", func(t *testing.T) {
		lb, backend, _ := build(t, true)
		target, err := lb.selectTarget()
		if err != nil || target.Type != "anycast" || target.Backend != backend {
			t.Fatalf("target = %+v err=%v, want the anycast backend", target, err)
		}
	})

	t.Run("no healthy anycast backend selects a standalone server", func(t *testing.T) {
		lb, backend, standalone := build(t, false)
		for i := 0; i < 3; i++ {
			backend.markFailure()
		}
		target, err := lb.selectTarget()
		if err != nil {
			t.Fatal(err)
		}
		if target.Type != "standalone" || target.Server != standalone {
			t.Fatalf("FAIL: with every anycast backend unhealthy selected %+v, want the standalone server", target)
		}
	})

	t.Run("a failed anycast backend fails over to a standalone server", func(t *testing.T) {
		lb, _, _ := build(t, false)
		resp, err := lb.Query(newTestQuery2(0xE200))
		if err != nil {
			t.Fatalf("FAIL: query failed although a standalone server is configured: %v", err)
		}
		if resp.Header.ID != 0xE200 {
			t.Fatalf("response ID = %#x, want 0xE200", resp.Header.ID)
		}
	})

	t.Run("without standalone servers the old behavior holds", func(t *testing.T) {
		lb, backend, _ := build(t, false)
		lb.servers = nil
		for i := 0; i < 3; i++ {
			backend.markFailure()
		}
		target, err := lb.selectTarget()
		if err != nil || target.Type != "anycast" {
			t.Fatalf("target = %+v err=%v, want the (unhealthy) anycast fallback", target, err)
		}
	})
}
