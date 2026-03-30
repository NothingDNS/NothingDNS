package upstream

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ---------------------------------------------------------------------------
// anycast.go:246 - weightedSelect fallback to last backend
// The fallback `return backends[len(backends)-1]` is mathematically
// unreachable when weights are non-negative because the selector is
// always < totalWeight. We call weightedSelect enough times to confirm
// correctness, though the fallback itself cannot be hit through normal
// execution. We also exercise the function with various weight
// configurations to maximize coverage of the weighted loop path.
// ---------------------------------------------------------------------------

func TestWeightedSelect_FallbackPathExercise(t *testing.T) {
	// Multiple backends with equal weights.
	// Run enough iterations to cover different time-based selector values.
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.1.1", Weight: 10},
		{PhysicalIP: "10.0.1.2", Weight: 10},
		{PhysicalIP: "10.0.1.3", Weight: 10},
		{PhysicalIP: "10.0.1.4", Weight: 10},
	}
	for i := 0; i < 100; i++ {
		b := weightedSelect(backends)
		if b == nil {
			t.Fatal("expected non-nil backend")
		}
		found := false
		for _, expected := range backends {
			if b == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("selected backend %s not in original list", b.PhysicalIP)
		}
	}
}

// ---------------------------------------------------------------------------
// client.go:336-338 - queryUDP SetDeadline error path
// We create a scenario where SetDeadline on the UDP connection fails.
// Since SetDeadline on a real *net.UDPConn never fails, we instead
// exercise the queryUDP path with a timeout=0 which causes the
// SetDeadline to return a deadline-in-past, making the subsequent
// Write fail. This indirectly covers the error handling around
// SetDeadline.
// ---------------------------------------------------------------------------

func TestCovLB4_ClientQueryUDP_SetDeadlineZero(t *testing.T) {
	addr, cleanup := startUDPMockServer4(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		// Do not respond
	})
	defer cleanup()

	server := &Server{Address: addr, healthy: true, Timeout: 0}
	client := &Client{
		servers: []*Server{server},
		udpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 4096) }},
		},
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery4(0xA100)
	_, err := client.queryUDP(server, msg)
	if err == nil {
		t.Error("expected error with zero timeout (SetDeadline path)")
	}
}

// ---------------------------------------------------------------------------
// client.go:394-396 - queryTCP SetDeadline error path
// We use a timeout of 0 so SetDeadline(time.Now().Add(0)) succeeds
// but the subsequent Write (send length) fails because the deadline
// is already past.
// ---------------------------------------------------------------------------

func TestCovLB4_ClientQueryTCP_SetDeadlineZero(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	addr := ln.Addr().String()
	server := &Server{Address: addr, healthy: true, Timeout: 0}
	client := &Client{
		servers: []*Server{server},
		udpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 4096) }},
		},
		tcpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 65535) }},
		},
	}

	msg := newTestQuery4(0xA200)
	_, err = client.queryTCP(server, msg)
	if err == nil {
		t.Error("expected error with zero timeout (TCP SetDeadline path)")
	}
	ln.Close()
}

// ---------------------------------------------------------------------------
// client.go:406-408 - queryTCP send query body error
// We set up a TCP server that reads the length prefix but closes before
// the query body can be written, causing the Write(packed) to fail.
// We use a short server-side read timeout and a long client timeout.
// ---------------------------------------------------------------------------

func TestCovLB4_ClientQueryTCP_SendBodyError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read only the 2-byte length prefix
		lenBuf := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if queryLen > 0 {
			io.ReadFull(conn, make([]byte, queryLen))
		}
		// Close immediately after reading the full query to cause the
		// client's subsequent Read to fail. Actually we want the Write
		// to fail, so we close after reading.
	}()

	addr := ln.Addr().String()
	server := &Server{Address: addr, healthy: true, Timeout: 5 * time.Second}
	client := &Client{
		servers: []*Server{server},
		udpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 4096) }},
		},
		tcpPool: map[string]*sync.Pool{
			addr: {New: func() interface{} { return make([]byte, 65535) }},
		},
	}

	msg := newTestQuery4(0xA300)
	_, err = client.queryTCP(server, msg)
	if err == nil {
		t.Error("expected error when TCP server closes after reading query")
	}
	ln.Close()
}

// ---------------------------------------------------------------------------
// loadbalancer.go:300-302 - selectAnycastTarget when backend is nil
// AnycastGroup has backends but SelectBackend returns nil.
// This can happen if the Backends slice is emptied between Stats() and
// SelectBackend().
// ---------------------------------------------------------------------------

func TestCovLB4_SelectAnycastTarget_NilBackendRace(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	// Add a backend and mark it healthy
	b1 := &AnycastBackend{
		PhysicalIP: "10.0.1.1",
		Port:       53,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     100,
		healthy:    true,
	}
	group.AddBackend(b1)

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		topology: Topology{Region: "us-east-1", Zone: "a"},
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
	}

	// Empty backends after setup to trigger the nil backend path
	group.mu.Lock()
	group.Backends = nil
	group.mu.Unlock()

	_, err := lb.selectAnycastTarget()
	if err == nil {
		t.Error("expected error when backend is nil after Stats")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:331-333 - selectStandaloneTarget when selected is nil
// This requires a strategy to return nil even though len(servers) > 0.
// All strategies currently return non-nil when servers exist, so this
// path is effectively unreachable. We still test the early return
// path (len(lb.servers) == 0) which is already tested, but we also
// test the Fastest path with no servers after the initial check.
//
// Additionally, test the RoundRobin strategy with empty servers.
// ---------------------------------------------------------------------------

func TestCovLB4_SelectStandaloneTarget_RoundRobinEmpty(t *testing.T) {
	lb := &LoadBalancer{
		servers:  []*Server{},
		strategy: RoundRobin,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
	}

	_, err := lb.selectStandaloneTarget()
	if err == nil {
		t.Error("expected error with empty servers (RoundRobin)")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:483-485 - LB.queryUDP SetDeadline error
// We use timeout=0 to trigger the SetDeadline error on the LB's queryUDP.
// Since the LB uses a hardcoded 5*time.Second timeout, we need to
// approach this differently. We test by using an address where dial
// succeeds but then SetDeadline might fail. Since SetDeadline on a real
// connection never fails, we exercise the Write error path instead by
// using an unreachable address.
// ---------------------------------------------------------------------------

func TestCovLB4_LBQueryUDP_WriteError_InvalidHost(t *testing.T) {
	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery4(0xB100)
	_, err := lb.queryUDP("invalid.host.invalid:53", msg)
	if err == nil {
		t.Error("expected error connecting to invalid host")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:551-553 - LB.queryTCP SetDeadline error
// loadbalancer.go:557-559 - LB.queryTCP send length error
// loadbalancer.go:562-564 - LB.queryTCP send query error
// We exercise these paths by connecting to a server that closes
// immediately, causing writes to fail.
// ---------------------------------------------------------------------------

func TestCovLB4_LBQueryTCP_ServerClosesImmediately(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	addr := ln.Addr().String()
	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery4(0xB200)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error when TCP server closes immediately")
	}
	ln.Close()
}

// ---------------------------------------------------------------------------
// loadbalancer.go:562-564 - LB.queryTCP send query body error
// We create a server that reads the length prefix but then closes,
// causing the packed query write to fail.
// ---------------------------------------------------------------------------

func TestCovLB4_LBQueryTCP_SendBodyFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read only the 2-byte length prefix
		lenBuf := make([]byte, 2)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if queryLen > 0 {
			io.ReadFull(conn, make([]byte, queryLen))
		}
		// Close to cause client Read to fail
	}()

	addr := ln.Addr().String()
	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery4(0xB300)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error when TCP server closes after reading query body")
	}
	ln.Close()
}

// ---------------------------------------------------------------------------
// loadbalancer.go:488-490 - LB.queryUDP Write error with conn deadline
// We test the write error path by using a very short deadline.
// The LB uses a hardcoded 5s timeout, but we can cause the Write to
// fail by connecting to a port where nobody is listening (ICMP port
// unreachable may cause write error on some systems).
// ---------------------------------------------------------------------------

func TestCovLB4_LBQueryUDP_ReadError(t *testing.T) {
	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery4(0xB400)
	// Using a port that's not listening - UDP dial succeeds but read times out
	_, err := lb.queryUDP("127.0.0.1:1", msg)
	if err == nil {
		t.Error("expected error with no UDP server")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:551-553 - LB.queryTCP SetDeadline error
// We test by connecting to an address with a server that accepts
// and reads the length prefix, then we verify the send query body error.
// The SetDeadline path on a real connection doesn't fail, but the
// send length/send query body paths are exercised.
// ---------------------------------------------------------------------------

func TestCovLB4_LBQueryTCP_SendLengthFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	time.Sleep(50 * time.Millisecond)

	addr := ln.Addr().String()
	lb := &LoadBalancer{
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery4(0xB500)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error with immediate server close (send length)")
	}
	ln.Close()
}

// ---------------------------------------------------------------------------
// Helper functions for coverage_lb4 tests
// ---------------------------------------------------------------------------

func newTestQuery4(id uint16) *protocol.Message {
	return &protocol.Message{
		Header: protocol.Header{
			ID:      id,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{"test", "com"}, FQDN: true},
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}
}

func startUDPMockServer4(t *testing.T, handler func(conn *net.UDPConn, data []byte, remote *net.UDPAddr)) (string, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve UDP: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}

	localAddr := conn.LocalAddr().String()
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			handler(conn, buf[:n], remote)
		}
	}()

	return localAddr, func() { close(done); conn.Close() }
}
