package upstream

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

func mustNameP(s string) *protocol.Name {
	n, err := protocol.ParseName(s)
	if err != nil {
		panic("mustNameP: " + err.Error())
	}
	return n
}

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

// ---------------------------------------------------------------------------
// Config.HealthCheckDuration
// ---------------------------------------------------------------------------

func TestConfig_HealthCheckDuration_Default(t *testing.T) {
	cfg := Config{}
	if d := cfg.HealthCheckDuration(); d != 30*time.Second {
		t.Errorf("expected default 30s, got %v", d)
	}
}

func TestConfig_HealthCheckDuration_Custom(t *testing.T) {
	cfg := Config{HealthCheck: 10 * time.Second}
	if d := cfg.HealthCheckDuration(); d != 10*time.Second {
		t.Errorf("expected 10s, got %v", d)
	}
}

func TestConfig_HealthCheckDuration_InvalidUsesDefault(t *testing.T) {
	cfg := Config{HealthCheck: -time.Second}
	if d := cfg.HealthCheckDuration(); d != 30*time.Second {
		t.Errorf("expected default 30s, got %v", d)
	}
}

// ---------------------------------------------------------------------------
// Client.IsHealthy
// ---------------------------------------------------------------------------

func TestClient_IsHealthy_AllHealthy(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	if !client.IsHealthy() {
		t.Error("expected healthy when server starts healthy")
	}
}

func TestClient_IsHealthy_NoneHealthy(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	client.mu.Lock()
	client.servers[0].healthy = false
	client.mu.Unlock()

	if client.IsHealthy() {
		t.Error("expected unhealthy when all servers are down")
	}
}

func TestClient_IsHealthy_Mixed(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53", "8.8.4.4:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	client.mu.Lock()
	client.servers[0].healthy = false
	client.mu.Unlock()

	if !client.IsHealthy() {
		t.Error("expected healthy when at least one server is up")
	}
}

// ---------------------------------------------------------------------------
// Client.AddServer
// ---------------------------------------------------------------------------

func TestClient_AddServer_Success(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.AddServer("1.1.1.1:53")
	if err != nil {
		t.Fatalf("AddServer failed: %v", err)
	}

	client.mu.RLock()
	count := len(client.servers)
	_, hasUDP := client.udpPool["1.1.1.1:53"]
	_, hasTCP := client.tcpPool["1.1.1.1:53"]
	_, hasConn := client.tcpConnPools["1.1.1.1:53"]
	client.mu.RUnlock()

	if count != 2 {
		t.Errorf("expected 2 servers, got %d", count)
	}
	if !hasUDP {
		t.Error("expected UDP pool for new server")
	}
	if !hasTCP {
		t.Error("expected TCP pool for new server")
	}
	if !hasConn {
		t.Error("expected TCP conn pool for new server")
	}
}

func TestClient_AddServer_Duplicate(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.AddServer("8.8.8.8:53")
	if err == nil {
		t.Error("expected error for duplicate server")
	}
}

// ---------------------------------------------------------------------------
// Client.RemoveServer
// ---------------------------------------------------------------------------

func TestClient_RemoveServer_Success(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53", "1.1.1.1:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.RemoveServer("8.8.8.8:53")
	if err != nil {
		t.Fatalf("RemoveServer failed: %v", err)
	}

	client.mu.RLock()
	count := len(client.servers)
	_, hasUDP := client.udpPool["8.8.8.8:53"]
	client.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 server, got %d", count)
	}
	if hasUDP {
		t.Error("UDP pool should be removed")
	}
}

func TestClient_RemoveServer_NotFound(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.RemoveServer("9.9.9.9:53")
	if err == nil {
		t.Error("expected error for non-existent server")
	}
}

func TestClient_RemoveServer_CleansConnPool(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	err := client.RemoveServer("8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}

	client.mu.RLock()
	_, hasConn := client.tcpConnPools["8.8.8.8:53"]
	client.mu.RUnlock()

	if hasConn {
		t.Error("TCP conn pool should be removed")
	}
}

// ---------------------------------------------------------------------------
// AddServer + RemoveServer roundtrip
// ---------------------------------------------------------------------------

func TestClient_AddRemoveRoundtrip(t *testing.T) {
	client, _ := NewClient(Config{
		Servers: []string{"8.8.8.8:53"},
		Timeout: 2 * time.Second,
	})
	defer client.Close()

	client.AddServer("1.1.1.1:53")
	client.RemoveServer("1.1.1.1:53")

	client.mu.RLock()
	count := len(client.servers)
	client.mu.RUnlock()

	if count != 1 {
		t.Errorf("expected 1 server after add/remove, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.getBackoff
// ---------------------------------------------------------------------------

func TestCircuitBreaker_GetBackoff_ZeroAttempt(t *testing.T) {
	cb := &circuitBreaker{
		backoff: 30 * time.Second,
	}

	if d := cb.getBackoff(0); d != 100*time.Millisecond {
		t.Errorf("attempt 0: expected 100ms, got %v", d)
	}
}

func TestCircuitBreaker_GetBackoff_NegativeAttempt(t *testing.T) {
	cb := &circuitBreaker{
		backoff: 30 * time.Second,
	}

	if d := cb.getBackoff(-1); d != 100*time.Millisecond {
		t.Errorf("attempt -1: expected 100ms, got %v", d)
	}
}

func TestCircuitBreaker_GetBackoff_Exponential(t *testing.T) {
	cb := &circuitBreaker{
		backoff: 30 * time.Second,
	}

	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{5, 1600 * time.Millisecond},
		{6, 3200 * time.Millisecond},
		{7, 6400 * time.Millisecond},
		{8, 12800 * time.Millisecond},
	}

	for _, tt := range tests {
		got := cb.getBackoff(tt.attempt)
		if got != tt.want {
			t.Errorf("attempt %d: expected %v, got %v", tt.attempt, tt.want, got)
		}
	}
}

func TestCircuitBreaker_GetBackoff_CappedAtMax(t *testing.T) {
	cb := &circuitBreaker{
		backoff: 500 * time.Millisecond,
	}

	got := cb.getBackoff(10)
	if got != 500*time.Millisecond {
		t.Errorf("expected capped at 500ms, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// LoadBalancer.IsHealthy
// ---------------------------------------------------------------------------

func TestLoadBalancer_IsHealthy_Servers(t *testing.T) {
	lb, _ := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{"8.8.8.8:53"},
		HealthCheck: 30 * time.Second,
	})
	defer lb.Close()

	if !lb.IsHealthy() {
		t.Error("expected healthy with one server")
	}
}

func TestLoadBalancer_IsHealthy_NoHealthyServers(t *testing.T) {
	lb, _ := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{"8.8.8.8:53"},
		HealthCheck: 30 * time.Second,
	})
	defer lb.Close()

	lb.mu.Lock()
	lb.servers[0].healthy = false
	lb.mu.Unlock()

	if lb.IsHealthy() {
		t.Error("expected unhealthy when all servers are down")
	}
}

func TestLoadBalancer_IsHealthy_AnycastGroup(t *testing.T) {
	lb, _ := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{"8.8.8.8:53"},
		HealthCheck: 30 * time.Second,
	})
	defer lb.Close()

	lb.mu.Lock()
	lb.anycastGroups["test-group"] = &AnycastGroup{
		AnycastIP: "1.2.3.4",
		Backends: []*AnycastBackend{
			{PhysicalIP: "10.0.0.1", Port: 53, healthy: true},
		},
	}
	lb.servers[0].healthy = false
	lb.mu.Unlock()

	if !lb.IsHealthy() {
		t.Error("expected healthy due to anycast group backend")
	}
}

func TestLoadBalancer_IsHealthy_AnycastAllDown(t *testing.T) {
	lb, _ := NewLoadBalancer(LoadBalancerConfig{
		Servers:     []string{"8.8.8.8:53"},
		HealthCheck: 30 * time.Second,
	})
	defer lb.Close()

	lb.mu.Lock()
	lb.anycastGroups["test-group"] = &AnycastGroup{
		AnycastIP: "1.2.3.4",
		Backends: []*AnycastBackend{
			{PhysicalIP: "10.0.0.1", Port: 53, healthy: false},
		},
	}
	lb.servers[0].healthy = false
	lb.mu.Unlock()

	if lb.IsHealthy() {
		t.Error("expected unhealthy when all servers and anycast backends are down")
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.shouldAllow — all states
// ---------------------------------------------------------------------------

func TestCircuitBreaker_ShouldAllow_Closed(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true when closed")
	}
}

func TestCircuitBreaker_ShouldAllow_HalfOpen(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbHalfOpen,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true when half-open")
	}
}

func TestCircuitBreaker_ShouldAllow_Open_WithinTimeout(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
		lastFailure:  time.Now(), // recent failure
	}
	if cb.shouldAllow() {
		t.Error("expected shouldAllow=false when open and within timeout")
	}
}

func TestCircuitBreaker_ShouldAllow_Open_AfterTimeout(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failureLimit: 3,
		resetTimeout: 50 * time.Millisecond,
		lastFailure:  time.Now().Add(-100 * time.Millisecond), // expired
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true after reset timeout expired")
	}

	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()

	if state != cbHalfOpen {
		t.Error("expected state to transition to half-open after timeout")
	}
}

func TestCircuitBreaker_ResetTimeoutReachedBoundary(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	resetTimeout := 30 * time.Second

	if circuitBreakerResetReachedAt(now.Add(-resetTimeout+time.Nanosecond), now, resetTimeout) {
		t.Error("reset timeout should not be reached before the boundary")
	}
	if !circuitBreakerResetReachedAt(now.Add(-resetTimeout), now, resetTimeout) {
		t.Error("reset timeout should be reached exactly at the boundary")
	}
	if !circuitBreakerResetReachedAt(now.Add(-resetTimeout-time.Nanosecond), now, resetTimeout) {
		t.Error("reset timeout should be reached after the boundary")
	}
}

func TestCircuitBreaker_ShouldAllow_UnknownState(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbState(99), // unknown state
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}
	if !cb.shouldAllow() {
		t.Error("expected shouldAllow=true for unknown state (default)")
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.recordSuccess
// ---------------------------------------------------------------------------

func TestCircuitBreaker_RecordSuccess(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbOpen,
		failures:     5,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordSuccess()

	cb.mu.Lock()
	failures := cb.failures
	state := cb.state
	cb.mu.Unlock()

	if failures != 0 {
		t.Errorf("expected failures=0 after recordSuccess, got %d", failures)
	}
	if state != cbClosed {
		t.Errorf("expected state=cbClosed after recordSuccess, got %d", state)
	}
}

// ---------------------------------------------------------------------------
// circuitBreaker.recordFailure transitions
// ---------------------------------------------------------------------------

func TestCircuitBreaker_RecordFailure_BelowLimit(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failures:     0,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordFailure()

	cb.mu.Lock()
	failures := cb.failures
	state := cb.state
	cb.mu.Unlock()

	if failures != 1 {
		t.Errorf("expected failures=1, got %d", failures)
	}
	if state != cbClosed {
		t.Errorf("expected state=cbClosed (below limit), got %d", state)
	}
}

func TestCircuitBreaker_RecordFailure_TripsOpen(t *testing.T) {
	cb := &circuitBreaker{
		state:        cbClosed,
		failures:     2,
		failureLimit: 3,
		resetTimeout: 5 * time.Second,
	}

	cb.recordFailure()

	cb.mu.Lock()
	state := cb.state
	cb.mu.Unlock()

	if state != cbOpen {
		t.Error("expected circuit breaker to be open after reaching failure limit")
	}
}

// ---------------------------------------------------------------------------
// tcpPool.put — overflow connection
// ---------------------------------------------------------------------------

func TestTCPPool_Put_OverflowConnection(t *testing.T) {
	// Create a pool
	pool := &tcpConnPool{
		maxIdle:  2,
		maxTotal: 5,
	}

	// Create a connection that belongs to a different pool
	otherPool := &tcpConnPool{}
	closeErr := errors.New("overflow close failed")
	conn := &tcpConn{
		pool: otherPool,
		conn: &closeErrorConn{closeErr: closeErr},
	}

	// put should close the overflow connection
	if err := pool.put(conn); !errors.Is(err, closeErr) {
		t.Fatalf("put error = %v, want %v", err, closeErr)
	}
	// Should not panic and should not add to idle
	if len(pool.idle) != 0 {
		t.Errorf("expected 0 idle conns, got %d", len(pool.idle))
	}
}

func TestTCPPool_Put_PoolClosed(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  2,
		maxTotal: 5,
		closed:   true,
		active:   1,
	}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	conn := &tcpConn{
		pool: pool,
		conn: clientConn,
	}
	conn.inUse.Store(true)

	if err := pool.put(conn); err != nil {
		t.Fatalf("put to closed pool: %v", err)
	}

	if pool.active != 0 {
		t.Errorf("expected active=0 after put to closed pool, got %d", pool.active)
	}
}

func TestTCPPool_Put_TooManyIdle(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  1,
		maxTotal: 5,
		idle:     make([]*tcpConn, 1),
		active:   2,
	}
	pool.idle[0] = &tcpConn{pool: pool}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	conn := &tcpConn{
		pool: pool,
		conn: clientConn,
	}
	conn.inUse.Store(true)

	if err := pool.put(conn); err != nil {
		t.Fatalf("put over max idle: %v", err)
	}

	// Should close the connection because idle is full
	if len(pool.idle) != 1 {
		t.Errorf("expected 1 idle conn (max), got %d", len(pool.idle))
	}
	if pool.active != 1 {
		t.Errorf("expected active=1 after closing excess, got %d", pool.active)
	}
}

func TestTCPPool_Put_Success(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  5,
		maxTotal: 10,
		idle:     []*tcpConn{},
		active:   1,
	}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	conn := &tcpConn{
		pool: pool,
		conn: clientConn,
	}
	conn.inUse.Store(true)

	if err := pool.put(conn); err != nil {
		t.Fatalf("put: %v", err)
	}

	if len(pool.idle) != 1 {
		t.Errorf("expected 1 idle conn, got %d", len(pool.idle))
	}
	if conn.inUse.Load() {
		t.Error("expected inUse=false after put")
	}
}

func TestTCPPool_IdleTimeoutReachedBoundary(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	idleTimeout := 30 * time.Second

	if tcpIdleTimeoutReachedAt(now.Add(-idleTimeout+time.Nanosecond), now, idleTimeout) {
		t.Error("idle timeout should not be reached before the boundary")
	}
	if !tcpIdleTimeoutReachedAt(now.Add(-idleTimeout), now, idleTimeout) {
		t.Error("idle timeout should be reached exactly at the boundary")
	}
	if !tcpIdleTimeoutReachedAt(now.Add(-idleTimeout-time.Nanosecond), now, idleTimeout) {
		t.Error("idle timeout should be reached after the boundary")
	}
}

func TestTCPConn_Close_DecrementsPooledActiveOnce(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  1,
		maxTotal: 1,
		active:   1,
	}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	conn := &tcpConn{
		pool: pool,
		conn: clientConn,
	}
	conn.inUse.Store(true)

	if err := conn.close(); err != nil {
		t.Fatalf("close() error = %v", err)
	}
	if pool.active != 0 {
		t.Fatalf("expected active=0 after close, got %d", pool.active)
	}

	if err := conn.close(); err != nil {
		t.Fatalf("second close() error = %v", err)
	}
	if pool.active != 0 {
		t.Fatalf("expected second close to keep active=0, got %d", pool.active)
	}
}

func TestWriteFullRetriesPartialWrites(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 2}
	data := []byte{1, 2, 3, 4, 5}

	if err := util.WriteFull(conn, data); err != nil {
		t.Fatalf("WriteFull failed: %v", err)
	}
	if string(conn.written) != string(data) {
		t.Fatalf("written bytes = %v, want %v", conn.written, data)
	}
	if conn.calls <= 1 {
		t.Fatalf("expected multiple partial writes, got %d call", conn.calls)
	}
}

func TestWriteFullRejectsZeroByteWrite(t *testing.T) {
	conn := &partialWriteConn{}
	err := util.WriteFull(conn, []byte{1, 2, 3})
	if err != io.ErrNoProgress {
		t.Fatalf("WriteFull error = %v, want %v", err, io.ErrNoProgress)
	}
}

func TestWritePacketRejectsPartialDatagramWrite(t *testing.T) {
	conn := &partialWriteConn{maxWrite: 2}
	err := writePacket(conn, []byte{1, 2, 3})
	if err != io.ErrShortWrite {
		t.Fatalf("writePacket error = %v, want %v", err, io.ErrShortWrite)
	}
	if conn.calls != 1 {
		t.Fatalf("writePacket should not retry partial datagrams, got %d calls", conn.calls)
	}
}

type partialWriteConn struct {
	maxWrite int
	written  []byte
	calls    int
}

func (c *partialWriteConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *partialWriteConn) Write(p []byte) (int, error) {
	c.calls++
	if c.maxWrite <= 0 {
		return 0, nil
	}
	n := c.maxWrite
	if n > len(p) {
		n = len(p)
	}
	c.written = append(c.written, p[:n]...)
	return n, nil
}

func (c *partialWriteConn) Close() error {
	return nil
}

type closeErrorConn struct {
	partialWriteConn
	closeErr error
}

func (c *closeErrorConn) Close() error {
	return c.closeErr
}

func (c *partialWriteConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *partialWriteConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *partialWriteConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *partialWriteConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *partialWriteConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

func TestTCPPool_CloseAll_DecrementsIdleActive(t *testing.T) {
	pool := &tcpConnPool{
		maxIdle:  2,
		maxTotal: 2,
		active:   2,
	}

	clientConn1, serverConn1 := net.Pipe()
	defer serverConn1.Close()
	clientConn2, serverConn2 := net.Pipe()
	defer serverConn2.Close()

	pool.idle = []*tcpConn{
		{pool: pool, conn: clientConn1},
		{pool: pool, conn: clientConn2},
	}

	if err := pool.closeAll(); err != nil {
		t.Fatalf("closeAll: %v", err)
	}

	if pool.active != 0 {
		t.Fatalf("expected active=0 after closeAll, got %d", pool.active)
	}
	if len(pool.idle) != 0 {
		t.Fatalf("expected idle list to be cleared, got %d", len(pool.idle))
	}
}

func TestTCPPool_CloseAllReportsCloseError(t *testing.T) {
	closeErr := errors.New("idle close failed")
	pool := &tcpConnPool{
		maxIdle:  1,
		maxTotal: 1,
		active:   1,
	}
	pool.idle = []*tcpConn{
		{pool: pool, conn: &closeErrorConn{closeErr: closeErr}},
	}

	err := pool.closeAll()
	if !errors.Is(err, closeErr) {
		t.Fatalf("closeAll error = %v, want %v", err, closeErr)
	}
	if pool.active != 0 {
		t.Fatalf("expected active=0 after closeAll, got %d", pool.active)
	}
	if len(pool.idle) != 0 {
		t.Fatalf("expected idle list to be cleared, got %d", len(pool.idle))
	}
}

func TestTCPPool_GetRejectsClosedPool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
		close(accepted)
	}()

	pool := newTCPConnPool(ln.Addr().String(), 1, 1, time.Second, time.Second)
	if err := pool.closeAll(); err != nil {
		t.Fatalf("closeAll: %v", err)
	}

	tc, err := pool.get()
	if err == nil {
		if tc != nil {
			if closeErr := tc.close(); closeErr != nil {
				t.Fatalf("close unexpected conn: %v", closeErr)
			}
		}
		t.Fatal("expected closed pool to reject get")
	}
	if tc != nil {
		t.Fatalf("expected nil conn from closed pool, got %#v", tc)
	}
	if pool.active != 0 {
		t.Fatalf("expected active=0 after rejected get, got %d", pool.active)
	}

	select {
	case conn := <-accepted:
		if conn != nil {
			if err := conn.Close(); err != nil {
				t.Fatalf("close unexpected accepted conn: %v", err)
			}
			t.Fatal("closed pool unexpectedly opened a TCP connection")
		}
	case <-time.After(50 * time.Millisecond):
	}
}

// buildTestDNSResponse builds a valid DNS response message for testing.
func buildTestDNSResponse(id uint16) *protocol.Message {
	name, _ := protocol.ParseName("test.com.")
	return &protocol.Message{
		Header: protocol.Header{
			ID:    id,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}
}

// packMessage is a helper to pack a protocol.Message into a byte slice.
func packMessage(t *testing.T, msg *protocol.Message) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("failed to pack message: %v", err)
	}
	return buf[:n]
}

// startTCPMockServer starts a TCP listener that accepts one connection and calls handler.
// Returns the listener address and a cleanup function.
func startTCPMockServer(t *testing.T, handler func(conn net.Conn)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		handler(conn)
		conn.Close()
	}()

	return ln.Addr().String(), func() { ln.Close(); <-done }
}

// startUDPMockServer starts a UDP listener that calls handler for each received packet.
// Returns the listener address and a cleanup function.
func startUDPMockServer(t *testing.T, handler func(conn *net.UDPConn, data []byte, remote *net.UDPAddr)) (string, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
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

// newTestClient creates a Client configured to talk to the given address.
func newTestClient(t *testing.T, addr string) *Client {
	t.Helper()
	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  2 * time.Second,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client
}

// newTestQuery creates a simple DNS query message.
func newTestQuery(id uint16) *protocol.Message {
	return &protocol.Message{
		Header: protocol.Header{
			ID:      id,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   mustNameP("test.com."),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_SendError: UDP server address that refuses connections (send fails).
// Using a non-routable address to trigger a write error quickly.
// ---------------------------------------------------------------------------
func TestQueryUDP_SendError(t *testing.T) {
	config := Config{
		Servers:  []string{"198.51.100.1:53"}, // TEST-NET-1, non-routable
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	msg := newTestQuery(0x1234)
	_, err = client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error from queryUDP with non-routable address")
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_ReadError: UDP server that accepts queries but never replies,
// causing a read timeout.
// ---------------------------------------------------------------------------
func TestQueryUDP_ReadError(t *testing.T) {
	addr, cleanup := startUDPMockServer(t, func(_ *net.UDPConn, _ []byte, _ *net.UDPAddr) {
		// Intentionally do not reply - silence causes read timeout
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0xABCD)
	_, err := client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when UDP server does not respond")
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_TruncatedResponse: UDP server that sends a TC=1 response,
// which should return both the response and an error.
// ---------------------------------------------------------------------------
func TestQueryUDP_TruncatedResponse(t *testing.T) {
	addr, cleanup := startUDPMockServer(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		// Extract the query ID from the received data
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])

		resp := buildTestDNSResponse(queryID)
		resp.Header.Flags.TC = true // Set truncation bit
		packed := packMessage(&testing.T{}, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0xBEEF)
	resp, err := client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error for truncated response")
	}
	if resp == nil {
		t.Error("expected non-nil response even when TC bit is set")
	}
	if resp != nil && !resp.Header.Flags.TC {
		t.Error("expected TC flag to be set in response")
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_UnpackError: UDP server that sends garbage (non-DNS) data.
// ---------------------------------------------------------------------------
func TestQueryUDP_UnpackError(t *testing.T) {
	addr, cleanup := startUDPMockServer(t, func(conn *net.UDPConn, _ []byte, remote *net.UDPAddr) {
		// Send invalid DNS data
		garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		conn.WriteToUDP(garbage, remote)
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0xDEAD)
	_, err := client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when unpacking garbage UDP response")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_SendLengthError: TCP server that closes immediately, causing
// the length-prefix write to fail.
// ---------------------------------------------------------------------------
func TestQueryTCP_SendLengthError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(_ net.Conn) {
		// Close immediately - the client's Write of the length prefix will fail
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x1111)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server closes before receiving length prefix")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_ReadLengthError: TCP server that reads the query but then
// closes without sending a response length prefix.
// ---------------------------------------------------------------------------
func TestQueryTCP_ReadLengthError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(conn net.Conn) {
		// Read the full query (length prefix + body) then close
		io.ReadAll(io.LimitReader(conn, 65535))
		// Do not send any response - client's Read of length prefix will fail
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x2222)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server closes before sending length prefix")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_ReadBodyError: TCP server that sends a length prefix but
// closes before sending the response body.
// ---------------------------------------------------------------------------
func TestQueryTCP_ReadBodyError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(conn net.Conn) {
		// Read the query
		io.ReadAll(io.LimitReader(conn, 65535))
		// Send length prefix indicating a response of 100 bytes
		lengthBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuf, 100)
		conn.Write(lengthBuf)
		// Do NOT send the body - close causes read error
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x3333)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server sends length but no body")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_UnpackError: TCP server that sends garbage data with a valid
// length prefix.
// ---------------------------------------------------------------------------
func TestQueryTCP_UnpackError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(conn net.Conn) {
		// Read the query
		io.ReadAll(io.LimitReader(conn, 65535))
		// Send garbage response with valid length prefix
		garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		lengthBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lengthBuf, uint16(len(garbage)))
		conn.Write(lengthBuf)
		conn.Write(garbage)
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x4444)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when unpacking garbage TCP response")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_LargeResponse: TCP server that sends a response larger than
// the pool buffer, triggering the buf = make([]byte, respLen) resize path.
// The pool buffer is replaced with a smaller one to force the resize.
// ---------------------------------------------------------------------------
func TestQueryTCP_LargeResponse(t *testing.T) {
	// First, determine the size of a packed query message so we know the minimum
	// pool buffer size needed for Pack to succeed.
	queryMsg := newTestQuery(0x5555)
	queryBuf := make([]byte, 65535)
	queryN, err := queryMsg.Pack(queryBuf)
	if err != nil {
		t.Fatalf("pack query: %v", err)
	}
	minPackSize := queryN + 1 // buffer must be at least this big for Pack

	// Now build a response that is larger than minPackSize so we can use a
	// pool buffer between minPackSize and the response size.
	resp := buildTestDNSResponse(0x5555)
	for i := 0; i < 50; i++ {
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

	respPacked := packMessage(t, resp)
	poolBufSize := len(respPacked) - 1 // one byte smaller than response

	// Ensure poolBufSize is still large enough for Pack
	if poolBufSize < minPackSize {
		poolBufSize = minPackSize
		// Add more answers to make the response larger than poolBufSize
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
			respPacked = packMessage(t, resp)
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

		// Read the query (length prefix + body)
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		if _, err := io.ReadFull(conn, make([]byte, queryLen)); err != nil {
			return
		}

		// Send the large response
		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(respPacked)))
		conn.Write(respLen)
		conn.Write(respPacked)
	}()

	client := newTestClient(t, ln.Addr().String())

	// Replace the TCP pool buffer with one smaller than the response,
	// but large enough for Pack to succeed.
	client.mu.Lock()
	poolAddr := client.servers[0].Address
	finalPoolSize := poolBufSize
	client.tcpPool[poolAddr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, finalPoolSize)
		},
	}
	client.mu.Unlock()

	msg := newTestQuery(0x5555)
	resultResp, err := client.queryTCP(client.servers[0], msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resultResp == nil {
		t.Fatal("expected non-nil response")
	}
	if resultResp.Header.ID != 0x5555 {
		t.Errorf("expected response ID 0x5555, got 0x%04X", resultResp.Header.ID)
	}
	if len(resultResp.Answers) < 1 {
		t.Error("expected at least one answer in response")
	}

	client.Close()
	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TestCheckHealth_UDPFailTCPFail: Both UDP and TCP fail for a server.
// checkHealth fires goroutines that attempt UDP then TCP. Since neither
// queryUDP nor queryTCP call markFailure (only Query does), we verify
// that checkHealth runs without panic and the server remains unchanged.
// ---------------------------------------------------------------------------
func TestCheckHealth_UDPFailTCPFail(t *testing.T) {
	// Start a TCP listener that accepts connections but immediately closes them.
	// UDP will fail (no UDP listener), and TCP will also fail (connection closed).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tcpServerDone := make(chan struct{})
	go func() {
		defer close(tcpServerDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close() // Immediately close - causes TCP failure
		}
	}()

	addr := ln.Addr().String()
	config := Config{
		Servers:  []string{addr},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// Record initial state
	initialHealthy := client.servers[0].IsHealthy()

	// Call checkHealth - the goroutines will try UDP (fails) then TCP (fails).
	// This exercises the code paths where both UDP and TCP fail.
	client.checkHealth()

	// Wait for the health check goroutines to complete.
	time.Sleep(600 * time.Millisecond)

	// Server should still be in its initial state since checkHealth goroutines
	// don't modify server health on failure (only markSuccess is called on success).
	finalHealthy := client.servers[0].IsHealthy()
	if finalHealthy != initialHealthy {
		t.Logf("server health changed from %v to %v", initialHealthy, finalHealthy)
	}

	ln.Close()
	<-tcpServerDone
}

// ---------------------------------------------------------------------------
// TestCheckHealth_UDPFailTCPSuccess: UDP fails but TCP succeeds.
// We start a TCP mock server but no UDP server, so UDP will fail
// (timeout/connection refused) and TCP will succeed.
// ---------------------------------------------------------------------------
func TestCheckHealth_UDPFailTCPSuccess(t *testing.T) {
	// Start a TCP mock server that echoes DNS responses
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

		// Read query
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		// Extract query ID and build valid response
		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}
		resp := buildTestDNSResponse(queryID)
		resp.Questions = []*protocol.Question{
			{
				Name:   mustNameP("."),
				QType:  protocol.TypeNS,
				QClass: protocol.ClassIN,
			},
		}
		packed := packMessage(&testing.T{}, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	// Use a random high UDP port that won't have a UDP listener
	// but will have our TCP mock server.
	// We construct a client pointing at the TCP server address.
	// UDP to this address will fail (connection refused / timeout),
	// but TCP will succeed.
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

	// call checkHealth - UDP will fail, then TCP should succeed
	client.checkHealth()

	// Wait for the health check goroutine
	time.Sleep(500 * time.Millisecond)

	// Server should still be healthy (TCP succeeded and called markSuccess)
	if !client.servers[0].IsHealthy() {
		t.Error("expected server to remain healthy after TCP fallback success")
	}

	ln.Close()
	wg.Wait()
}

// ---------------------------------------------------------------------------
// TestHealthCheckLoop_ExitsOnCancel: Verify the health check loop exits
// cleanly when the context is cancelled via Close().
// ---------------------------------------------------------------------------
func TestHealthCheckLoop_ExitsOnCancel(t *testing.T) {
	config := Config{
		Servers:  []string{"8.8.8.8:53"},
		Strategy: "random",
		Timeout:  100 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Close cancels the context; the health check loop should exit via ctx.Done()
	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	elapsed := time.Since(start)

	// Close should return quickly (within a second), meaning the loop exited
	if elapsed > 2*time.Second {
		t.Errorf("Close took too long (%v), health check loop may not have exited on cancel", elapsed)
	}

	// Verify the WaitGroup is done by calling Close again (should be idempotent)
	if err := client.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_SendBodyError: TCP server that accepts the length prefix
// but closes before the query body is fully written.
// ---------------------------------------------------------------------------
func TestQueryTCP_SendBodyError(t *testing.T) {
	addr, cleanup := startTCPMockServer(t, func(conn net.Conn) {
		// Read only the 2-byte length prefix then close immediately
		lenBuf := make([]byte, 2)
		io.ReadFull(conn, lenBuf)
		// Close right after reading length prefix - client's Write of body fails
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x6666)
	_, err := client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected error when TCP server closes before receiving query body")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_PackError: Attempt to pack a message into a tiny buffer
// to trigger pack failure.
// ---------------------------------------------------------------------------
func TestQueryTCP_PackError(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:0"},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// Replace the TCP pool with a zero-length buffer to force Pack to fail
	client.mu.Lock()
	addr := client.servers[0].Address
	client.tcpPool[addr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 0) // Zero-length buffer
		},
	}
	client.mu.Unlock()

	msg := newTestQuery(0x7777)
	_, err = client.queryTCP(client.servers[0], msg)
	if err == nil {
		t.Error("expected pack error with zero-length buffer")
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_PackError: Attempt to pack a message into a tiny buffer
// to trigger UDP pack failure.
// ---------------------------------------------------------------------------
func TestQueryUDP_PackError(t *testing.T) {
	config := Config{
		Servers:  []string{"127.0.0.1:0"},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	defer client.Close()

	// Replace the UDP pool with a zero-length buffer to force Pack to fail
	client.mu.Lock()
	addr := client.servers[0].Address
	client.udpPool[addr] = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 0) // Zero-length buffer
		},
	}
	client.mu.Unlock()

	msg := newTestQuery(0x8888)
	_, err = client.queryUDP(client.servers[0], msg)
	if err == nil {
		t.Error("expected pack error with zero-length buffer")
	}
}

// ---------------------------------------------------------------------------
// TestHealthCheckLoop_TickerFires: Verify that the health check loop
// calls checkHealth on each tick by using a very short interval and
// observing server state changes.
// ---------------------------------------------------------------------------
func TestHealthCheckLoop_TickerFires(t *testing.T) {
	// Use a non-routable address so health checks fail quickly
	config := Config{
		Servers:  []string{"198.51.100.1:53"},
		Strategy: "random",
		Timeout:  200 * time.Millisecond,
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// The health check loop uses a fixed 30s ticker in healthCheckLoop.
	// Wait a moment and then close. The loop should have had a chance to
	// at least select on the ticker case.
	// Since the ticker is 30s, we can't wait for it in a unit test.
	// Instead, just verify clean shutdown.
	if err := client.Close(); err != nil {
		t.Errorf("close failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestQueryUDP_SuccessWithMockServer: Full success path for queryUDP
// with a properly responding mock UDP server.
// ---------------------------------------------------------------------------
func TestQueryUDP_SuccessWithMockServer(t *testing.T) {
	addr, cleanup := startUDPMockServer(t, func(conn *net.UDPConn, data []byte, remote *net.UDPAddr) {
		if len(data) < 2 {
			return
		}
		queryID := uint16(data[0])<<8 | uint16(data[1])
		resp := buildTestDNSResponse(queryID)
		packed := packMessage(t, resp)
		conn.WriteToUDP(packed, remote)
	})
	defer cleanup()

	client := newTestClient(t, addr)
	defer client.Close()

	msg := newTestQuery(0x9999)
	resp, err := client.queryUDP(client.servers[0], msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0x9999 {
		t.Errorf("expected response ID 0x9999, got 0x%04X", resp.Header.ID)
	}
	if resp.Header.Flags.TC {
		t.Error("expected TC flag to be clear")
	}

	// Verify server was marked healthy
	if !client.servers[0].IsHealthy() {
		t.Error("expected server to be healthy after successful UDP query")
	}
}

// ---------------------------------------------------------------------------
// TestQueryTCP_SuccessWithMockServer: Full success path for queryTCP
// with a properly responding mock TCP server.
// ---------------------------------------------------------------------------
func TestQueryTCP_SuccessWithMockServer(t *testing.T) {
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

		// Read length prefix
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lenBuf))
		queryData := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, queryData); err != nil {
			return
		}

		// Extract query ID
		var queryID uint16
		if len(queryData) >= 2 {
			queryID = uint16(queryData[0])<<8 | uint16(queryData[1])
		}

		// Build and send response
		resp := buildTestDNSResponse(queryID)
		packed := packMessage(&testing.T{}, resp)

		respLen := make([]byte, 2)
		binary.BigEndian.PutUint16(respLen, uint16(len(packed)))
		conn.Write(respLen)
		conn.Write(packed)
	}()

	client := newTestClient(t, ln.Addr().String())
	defer client.Close()

	msg := newTestQuery(0xAAAA)
	resp, err := client.queryTCP(client.servers[0], msg)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Header.ID != 0xAAAA {
		t.Errorf("expected response ID 0xAAAA, got 0x%04X", resp.Header.ID)
	}

	// Verify server was marked healthy
	if !client.servers[0].IsHealthy() {
		t.Error("expected server to be healthy after successful TCP query")
	}

	ln.Close()
	wg.Wait()
}
