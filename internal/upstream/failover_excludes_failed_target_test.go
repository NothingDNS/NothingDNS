package upstream

import (
	"net"
	"sync"
	"testing"
	"time"
)

func newFailoverTestLB(servers []*Server, strategy Strategy) *LoadBalancer {
	lb := &LoadBalancer{
		servers:       servers,
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      strategy,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}
	return lb
}

func failoverMockServer(t *testing.T) (string, func()) {
	t.Helper()
	return startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		id := uint16(data[0])<<8 | uint16(data[1])
		conn.WriteToUDP(packMessage2(t, buildTestDNSResponse2(id)), remote)
	})
}

// When the fastest server fails, failover must go to another server. The
// failed server stays "healthy" until its third consecutive failure, so a
// re-selection that does not exclude it picks it again ("no failover
// available") and the query fails although a working server exists.
func TestQueryWithFailoverSkipsFailedFastestServer(t *testing.T) {
	good, cleanup := failoverMockServer(t)
	defer cleanup()

	bad := &Server{Address: "127.0.0.1:1", healthy: true, Timeout: 100 * time.Millisecond, latency: time.Millisecond}
	ok := &Server{Address: good, healthy: true, Timeout: 2 * time.Second, latency: 50 * time.Millisecond}
	lb := newFailoverTestLB([]*Server{bad, ok}, Fastest)

	resp, err := lb.queryWithFailover(&Target{Type: "standalone", Address: bad.Address, Server: bad}, newTestQuery2(0xE100))
	if err != nil {
		t.Fatalf("FAIL: no failover to the working server: %v", err)
	}
	if resp.Header.ID != 0xE100 {
		t.Fatalf("response ID = %#x, want 0xE100", resp.Header.ID)
	}
}

// Control: with a single server there is nothing to fail over to.
func TestQueryWithFailoverSingleServerStillFails(t *testing.T) {
	bad := &Server{Address: "127.0.0.1:1", healthy: true, Timeout: 100 * time.Millisecond, latency: time.Millisecond}
	lb := newFailoverTestLB([]*Server{bad}, Fastest)
	if _, err := lb.queryWithFailover(&Target{Type: "standalone", Address: bad.Address, Server: bad}, newTestQuery2(0xE101)); err == nil {
		t.Fatal("expected an error with no alternative server")
	}
}

// A preferred-region anycast backend that fails must fail over to a backend
// elsewhere in the group.
func TestQueryWithFailoverSkipsFailedPreferredAnycastBackend(t *testing.T) {
	good, cleanup := failoverMockServer(t)
	defer cleanup()
	host, portStr, _ := net.SplitHostPort(good)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	group := NewAnycastGroup("10.0.0.1", time.Minute, time.Second)
	preferred := &AnycastBackend{PhysicalIP: "127.0.0.1", Port: 1, Region: "r1"}
	other := &AnycastBackend{PhysicalIP: host, Port: port, Region: "r2"}
	for _, b := range []*AnycastBackend{preferred, other} {
		if err := group.AddBackend(b); err != nil {
			t.Fatal(err)
		}
	}
	lb := newFailoverTestLB(nil, RoundRobin)
	lb.timeout = 200 * time.Millisecond
	lb.topology = Topology{Region: "r1"}
	lb.anycastGroups[group.AnycastIP] = group

	target, err := lb.selectTarget()
	if err != nil || target.Backend != preferred {
		t.Fatalf("setup: expected the preferred backend, got %+v err=%v", target, err)
	}
	if _, err := lb.queryWithFailover(target, newTestQuery2(0xE102)); err != nil {
		t.Fatalf("FAIL: no failover to the other region's backend: %v", err)
	}
}
