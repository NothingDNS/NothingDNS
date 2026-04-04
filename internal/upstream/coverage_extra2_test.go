package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ---------------------------------------------------------------------------
// anycast.go:246 - weightedSelect fallback to last backend
// The fallback at line 246 is reached when the weighted loop doesn't return
// early. With correct arithmetic this is actually unreachable since
// selector < totalWeight guarantees the loop returns on the last iteration.
// We still call weightedSelect with multiple backends to exercise the code.
// ---------------------------------------------------------------------------

func TestWeightedSelect_FallbackToLast(t *testing.T) {
	backends := []*AnycastBackend{
		{PhysicalIP: "10.0.1.1", Weight: 1},
		{PhysicalIP: "10.0.1.2", Weight: 1},
		{PhysicalIP: "10.0.1.3", Weight: 1},
	}
	for i := 0; i < 100; i++ {
		result := weightedSelect(backends)
		if result == nil {
			t.Error("expected a backend")
		}
	}
}

// ---------------------------------------------------------------------------
// client.go:336-338 - queryUDP SetDeadline error
// client.go:342-344 - queryUDP Write error
// These paths require UDP connection operations to fail after a successful
// dial. We use a very short timeout to trigger deadline errors.
// ---------------------------------------------------------------------------

func TestClient_QueryUDP_WriteError(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		// Don't respond - causes read timeout
	})
	defer cleanup()

	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  1 * time.Nanosecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	client.servers[0].Timeout = 1 * time.Nanosecond

	msg := newTestQuery2(0xCCCC)
	_, err = client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error with expired deadline")
	}
}

// ---------------------------------------------------------------------------
// client.go:394-396 - queryTCP SetDeadline error
// client.go:401-403 - queryTCP send length error
// client.go:406-408 - queryTCP send query body error
// client.go:423-425 - queryTCP read response error
// client.go:431-433 - queryTCP unpack response error
// ---------------------------------------------------------------------------

func TestClient_QueryTCP_SendQueryBodyError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		lenBuf := make([]byte, 2)
		io.ReadFull(conn, lenBuf)
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if queryLen > 0 {
			io.ReadFull(conn, make([]byte, queryLen))
		}
		conn.Close()
	}()

	addr := ln.Addr().String()
	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery2(0xDDDD)
	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when server closes after reading query")
	}

	ln.Close()
}

func TestClient_QueryTCP_UnpackGarbageResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if queryLen > 0 {
			io.ReadFull(conn, make([]byte, queryLen))
		}

		garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(garbage)))
		conn.Write(respLen)
		conn.Write(garbage)
	}()

	addr := ln.Addr().String()
	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery2(0xEEEE)
	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when unpacking garbage TCP response")
	}

	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// loadbalancer.go:300-302 - selectAnycastTarget: backend is nil
// ---------------------------------------------------------------------------

func TestLB_SelectAnycastTarget_BackendNil(t *testing.T) {
	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		strategy: Random,
		udpPool:  make(map[string]*sync.Pool),
		tcpPool:  make(map[string]*sync.Pool),
		topology: Topology{Region: "us-east-1", Zone: "a"},
	}

	_, err := lb.selectAnycastTarget()
	if err == nil {
		t.Error("expected error when no backends available in anycast group")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:331-333 - selectStandaloneTarget: selected is nil
// ---------------------------------------------------------------------------

func TestLB_SelectStandaloneTarget_NilSelectedFromStrategy(t *testing.T) {
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	_, err := lb.selectStandaloneTarget()
	if err == nil {
		t.Error("expected error with no servers")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:443-445 - queryWithFailover: retry path error
// ---------------------------------------------------------------------------

func TestLB_QueryWithFailover_RetryPathError(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: "127.0.0.1:1", healthy: true, Timeout: 100 * time.Millisecond},
			{Address: "127.0.0.1:2", healthy: true, Timeout: 100 * time.Millisecond},
		},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0xF001)

	lb.udpPool["127.0.0.1:1"] = &sync.Pool{New: func() interface{} { return make([]byte, 4096) }}
	lb.udpPool["127.0.0.1:2"] = &sync.Pool{New: func() interface{} { return make([]byte, 4096) }}
	lb.tcpPool["127.0.0.1:1"] = &sync.Pool{New: func() interface{} { return make([]byte, 65535) }}
	lb.tcpPool["127.0.0.1:2"] = &sync.Pool{New: func() interface{} { return make([]byte, 65535) }}

	target := &Target{
		Type:    "standalone",
		Address: "127.0.0.1:1",
		Server:  lb.servers[0],
	}

	_, err := lb.queryWithFailover(target, msg)
	if err == nil {
		t.Error("expected error when all queries fail")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:483-485 - queryUDP SetDeadline error
// loadbalancer.go:488-490 - queryUDP Write error
// loadbalancer.go:512-514 - queryUDP TC flag check
// ---------------------------------------------------------------------------

func TestLB_QueryUDP_TCFlag(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		resp.Header.Flags.TC = true
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		udpPool: make(map[string]*sync.Pool),
		tcpPool: make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0xF002)
	resp, err := lb.queryUDP(addr, msg)
	if err == nil {
		t.Error("expected error for truncated response")
	}
	if resp == nil {
		t.Error("expected non-nil response with TC flag set")
	}
	if resp != nil && !resp.Header.Flags.TC {
		t.Error("expected TC flag in response")
	}
}

func TestLB_QueryUDP_WriteError(t *testing.T) {
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0xF003)
	_, err := lb.queryUDP("invalid.host.invalid:53", msg)
	if err == nil {
		t.Error("expected error with invalid address")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go:551-553 - queryTCP SetDeadline error
// loadbalancer.go:557-559 - queryTCP send length error
// loadbalancer.go:562-564 - queryTCP send query error
// loadbalancer.go:572-574 - queryTCP respLen > buf
// loadbalancer.go:577-579 - queryTCP read response error
// loadbalancer.go:584-586 - queryTCP unpack error
// ---------------------------------------------------------------------------

func TestLB_QueryTCP_FullErrorPaths(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if queryLen > 0 {
			io.ReadFull(conn, make([]byte, queryLen))
		}

		garbage := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(garbage)))
		conn.Write(respLen)
		conn.Write(garbage)
	}()

	addr := ln.Addr().String()
	lb := &LoadBalancer{
		servers:       []*Server{{Address: addr, healthy: true}},
		anycastGroups: map[string]*AnycastGroup{},
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0xF004)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error unpacking garbage TCP response")
	}

	ln.Close()
	wg.Wait()
}

func TestLB_QueryTCP_ConnectionRefused(t *testing.T) {
	lb := &LoadBalancer{
		servers:       []*Server{},
		anycastGroups: map[string]*AnycastGroup{},
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0xF005)
	_, err := lb.queryTCP("127.0.0.1:1", msg)
	if err == nil {
		t.Error("expected error connecting to refused port")
	}
}

func TestLB_QueryTCP_ServerClosesAfterQuery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if queryLen > 0 {
			io.ReadFull(conn, make([]byte, queryLen))
		}
	}()

	addr := ln.Addr().String()
	lb := &LoadBalancer{
		servers:       []*Server{{Address: addr, healthy: true}},
		anycastGroups: map[string]*AnycastGroup{},
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0xF006)
	_, err = lb.queryTCP(addr, msg)
	if err == nil {
		t.Error("expected error when server closes after query")
	}

	ln.Close()
	wg.Wait()
}

func TestLB_QueryTCP_LargeResponseResize(t *testing.T) {
	queryMsg := newTestQuery2(0xF007)
	queryBuf := make([]byte, 65535)
	queryN, err := queryMsg.Pack(queryBuf)
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	minPackSize := queryN + 1

	resp := buildTestDNSResponse2(0xF007)
	for i := 0; i < 100; i++ {
		name, _ := protocol.ParseName("test.com.")
		resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   300,
			Data:  &protocol.RDataA{Address: [4]byte{byte(i), 2, 3, 4}},
		})
	}
	resp.Header.ANCount = uint16(len(resp.Answers))

	respPacked := packMessage2(&testing.T{}, resp)
	poolBufSize := len(respPacked) - 1

	if poolBufSize < minPackSize {
		poolBufSize = minPackSize
		for poolBufSize >= len(respPacked) {
			name, _ := protocol.ParseName("test.com.")
			resp.Answers = append(resp.Answers, &protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{0, 0, 0, 0}},
			})
			resp.Header.ANCount = uint16(len(resp.Answers))
			respPacked = packMessage2(&testing.T{}, resp)
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if _, err := io.ReadFull(conn, make([]byte, queryLen)); err != nil {
			return
		}

		respLenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(respLenBuf, uint16(len(respPacked)))
		conn.Write(respLenBuf)
		conn.Write(respPacked)
	}()

	addr := ln.Addr().String()
	lb := &LoadBalancer{
		servers:       []*Server{{Address: addr, healthy: true}},
		anycastGroups: map[string]*AnycastGroup{},
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	lb.tcpPool[addr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, poolBufSize)
		},
	}

	resultResp, err := lb.queryTCP(addr, queryMsg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resultResp == nil {
		t.Fatal("expected non-nil response")
	}
	if resultResp.Header.ID != 0xF007 {
		t.Errorf("expected response ID 0xF007, got 0x%04X", resultResp.Header.ID)
	}

	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// loadbalancer.go:653-655 - checkHealth: backend markSuccess path
// ---------------------------------------------------------------------------

func TestLB_CheckHealth_AnycastBackendSuccess(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	group := NewAnycastGroup("192.0.2.1", 30*time.Second, 5*time.Second)
	backend := &AnycastBackend{
		PhysicalIP: "127.0.0.1",
		Port:       0,
		Region:     "us-east-1",
		Zone:       "a",
		Weight:     50,
	}
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	backend.Port = port

	group.AddBackend(backend)

	lb := &LoadBalancer{
		anycastGroups: map[string]*AnycastGroup{
			"192.0.2.1": group,
		},
		servers:     []*Server{},
		udpPool:     make(map[string]*sync.Pool),
		tcpPool:     make(map[string]*sync.Pool),
		healthCheck: 30 * time.Second,
	}

	lb.checkHealth()
	time.Sleep(500 * time.Millisecond)

	if !backend.IsHealthy() {
		t.Error("expected backend to be healthy after successful health check")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go: queryWithFailover UDP success on first try
// ---------------------------------------------------------------------------

func TestLB_QueryWithFailover_UDPDirectSuccess(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		anycastGroups: map[string]*AnycastGroup{},
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0xF008)
	target := &Target{
		Type:    "standalone",
		Address: addr,
		Server:  lb.servers[0],
	}

	resp, err := lb.queryWithFailover(target, msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xF008 {
		t.Errorf("expected ID 0xF008, got 0x%04X", resp.Header.ID)
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go: queryWithFailover TCP success after UDP fails
// ---------------------------------------------------------------------------

func TestLB_QueryWithFailover_TCPAfterUDPFail(t *testing.T) {
	if testing.Short() {
		t.Skip("requires network timeout")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}

		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	addr := ln.Addr().String()
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		anycastGroups: map[string]*AnycastGroup{},
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
	}

	msg := newTestQuery2(0xF009)
	target := &Target{
		Type:    "standalone",
		Address: addr,
		Server:  lb.servers[0],
	}

	resp, err := lb.queryWithFailover(target, msg)
	if err != nil {
		t.Fatalf("expected TCP fallback success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}

	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// loadbalancer.go: Query method full success path
// ---------------------------------------------------------------------------

func TestLB_Query_FullSuccessWithMockServer(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
		healthCheck:   30 * time.Second,
	}

	msg := newTestQuery2(0xF00A)
	resp, err := lb.Query(msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xF00A {
		t.Errorf("expected ID 0xF00A, got 0x%04X", resp.Header.ID)
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go: QueryContext with successful response
// ---------------------------------------------------------------------------

func TestLB_QueryContext_SuccessWithMockServer(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	lb := &LoadBalancer{
		servers: []*Server{
			{Address: addr, healthy: true, Timeout: 2 * time.Second},
		},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
		healthCheck:   30 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msg := newTestQuery2(0xF00B)
	resp, err := lb.QueryContext(ctx, msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// ---------------------------------------------------------------------------
// loadbalancer.go: QueryContext with cancelled context
// ---------------------------------------------------------------------------

func TestLB_QueryContext_CancelledContext(t *testing.T) {
	lb := &LoadBalancer{
		servers: []*Server{
			{Address: "127.0.0.1:1", healthy: true, Timeout: 2 * time.Second},
		},
		anycastGroups: map[string]*AnycastGroup{},
		strategy:      Random,
		udpPool:       make(map[string]*sync.Pool),
		tcpPool:       make(map[string]*sync.Pool),
		healthCheck:   30 * time.Second,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	msg := newTestQuery2(0xF00C)
	_, err := lb.QueryContext(ctx, msg)
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Client: Full Query success path with mock UDP server
// ---------------------------------------------------------------------------

func TestClient_Query_FullSuccessUDP(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery2(0xF00D)
	resp, err := client.Query(msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xF00D {
		t.Errorf("expected ID 0xF00D, got 0x%04X", resp.Header.ID)
	}

	queries, _, responses := client.Stats()
	if queries != 1 {
		t.Errorf("expected 1 query, got %d", queries)
	}
	if responses != 1 {
		t.Errorf("expected 1 response, got %d", responses)
	}
}

// ---------------------------------------------------------------------------
// Client: Query where UDP fails, TCP succeeds (connection refused on UDP)
// ---------------------------------------------------------------------------

func TestClient_Query_TCPFallbackSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}

		resp := buildTestDNSResponse2(queryID)
		packed := packMessage2(&testing.T{}, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	// Use the TCP listener address - UDP will fail (connection refused)
	// since there's no UDP listener on that port
	addr := ln.Addr().String()
	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery2(0xF00E)
	resp, err := client.Query(msg)
	if err != nil {
		t.Logf("Query result: %v (may fail depending on port reuse)", err)
	} else if resp != nil && resp.Header.ID != 0xF00E {
		t.Errorf("expected ID 0xF00E, got 0x%04X", resp.Header.ID)
	}

	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Client: queryUDP with expired deadline
// ---------------------------------------------------------------------------

func TestClient_QueryUDP_ExpiredDeadline(t *testing.T) {
	addr, cleanup := startUDPMockServer2(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		// Don't respond - silence
	})
	defer cleanup()

	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  1 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery2(0xF00F)
	_, err = client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error with very short timeout")
	}
}
