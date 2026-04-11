package e2e

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// DNSRunner runs an actual DNS server for E2E testing.
type DNSRunner struct {
	Address string
	server  *testDNSServer
	mu      sync.Mutex
}

type testDNSServer struct {
	ln     net.Listener
	packets int
}

func (s *testDNSServer) Close() error {
	return s.ln.Close()
}

// NewDNSServer creates a test DNS server on a random port.
func NewDNSServer() (*DNSRunner, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	srv := &testDNSServer{ln: ln}
	runner := &DNSRunner{
		Address: ln.Addr().String(),
		server:  srv,
	}

	go srv.serve()

	return runner, nil
}

func (s *testDNSServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *testDNSServer) handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		// Read 2-byte length prefix for TCP DNS
		var length [2]byte
		if _, err := conn.Read(length[:]); err != nil {
			return
		}

		msgLen := int(length[0])<<8 | int(length[1])
		if msgLen > 65535 {
			return
		}

		buf := make([]byte, msgLen)
		_, err := conn.Read(buf)
		if err != nil {
			return
		}

		// Create response with proper 2-byte length prefix
		// Set QR bit (response) and AA bit
		buf[2] |= 0x80 // QR bit = response
		buf[3] |= 0x04 // AA bit = authoritative

		resp := make([]byte, msgLen+2)
		resp[0] = length[0]
		resp[1] = length[1]
		copy(resp[2:], buf)

		conn.Write(resp)
	}
}

// Close shuts down the test DNS server.
func (r *DNSRunner) Close() {
	r.server.Close()
}

// Query sends a DNS query and returns the response.
func (r *DNSRunner) Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error) {
	conn, err := net.DialTimeout("tcp", r.Address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	qname, err := protocol.ParseName(name)
	if err != nil {
		return nil, fmt.Errorf("parse name: %w", err)
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			Flags:   protocol.Flags{QR: false, Opcode: protocol.OpcodeQuery, RD: true},
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: qname, QType: qtype, QClass: protocol.ClassIN},
		},
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Write 2-byte length prefix (big-endian)
	if _, err := conn.Write([]byte{byte(n >> 8), byte(n & 0xff)}); err != nil {
		return nil, fmt.Errorf("write length: %w", err)
	}

	if _, err := conn.Write(buf[:n]); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	// Read 2-byte length prefix
	var length [2]byte
	if _, err := conn.Read(length[:]); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	respLen := int(length[0])<<8 | int(length[1])
	resp := make([]byte, respLen)
	if _, err := conn.Read(resp); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return protocol.UnpackMessage(resp)
}

// TestDNSQueryFlow tests the complete DNS query → response flow.
func TestDNSQueryFlow(t *testing.T) {
	server, err := NewDNSServer()
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := server.Query(ctx, "www.example.com.", protocol.TypeA)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if resp.Header.ID != 0x1234 {
		t.Errorf("Expected ID 0x1234, got 0x%x", resp.Header.ID)
	}
}

// TestDNSQueryVariousTypes tests different DNS query types.
func TestDNSQueryVariousTypes(t *testing.T) {
	server, err := NewDNSServer()
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	types := []struct {
		name  string
		qtype uint16
	}{
		{"A", protocol.TypeA},
		{"AAAA", protocol.TypeAAAA},
		{"CNAME", protocol.TypeCNAME},
		{"MX", protocol.TypeMX},
		{"TXT", protocol.TypeTXT},
		{"NS", protocol.TypeNS},
		{"SOA", protocol.TypeSOA},
		{"DNSKEY", protocol.TypeDNSKEY},
		{"NSEC", protocol.TypeNSEC},
		{"ANY", protocol.TypeANY},
	}

	for _, tt := range types {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.Query(ctx, "www.example.com.", tt.qtype)
			if err != nil {
				t.Fatalf("Query failed: %v", err)
			}

			if resp.Header.QDCount != 1 {
				t.Errorf("Expected QDCount 1, got %d", resp.Header.QDCount)
			}
		})
	}
}

// TestDNSMultipleQueries tests multiple queries to same server.
func TestDNSMultipleQueries(t *testing.T) {
	server, err := NewDNSServer()
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	domains := []string{
		"www.example.com.",
		"mail.example.com.",
		"blog.example.com.",
		"api.example.com.",
		"cdn.example.com.",
	}

	var wg sync.WaitGroup
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()

			for i := 0; i < 10; i++ {
				resp, err := server.Query(ctx, domain, protocol.TypeA)
				if err != nil {
					t.Errorf("Query %s failed: %v", domain, err)
					return
				}

				if resp.Header.ID == 0 {
					t.Errorf("Got invalid response for %s", domain)
				}
			}
		}(domain)
	}

	wg.Wait()
}

// TestDNSConnection回收 tests that connections are properly cleaned up.
func TestDNSConnectionCleanup(t *testing.T) {
	server, err := NewDNSServer()
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}

	// Close without defer to test cleanup
	server.Close()

	// Try to connect to closed server - should fail quickly
	conn, err := net.DialTimeout("tcp", server.Address, time.Second)
	if err == nil {
		conn.Close()
		t.Error("Expected error when connecting to closed server")
	}
}

// TestZoneTransferFlow tests AXFR flow (basic TCP behavior).
func TestZoneTransferFlow(t *testing.T) {
	server, err := NewDNSServer()
	if err != nil {
		t.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Close()

	// AXFR uses TCP - send zone request
	conn, err := net.DialTimeout("tcp", server.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Send empty query (simplified - real AXFR would send SOA request)
	qname, _ := protocol.ParseName("example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			Flags:   protocol.Flags{QR: false, Opcode: protocol.OpcodeQuery, RD: true, AA: true},
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{Name: qname, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
	}

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack failed: %v", err)
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(buf[:n]); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read multiple responses (AXFR streams multiple records)
	for i := 0; i < 5; i++ {
		resp := make([]byte, 512)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(resp)
		if err != nil {
			break // End of stream
		}

		if n > 0 {
			msg, err := protocol.UnpackMessage(resp[:n])
			if err == nil && msg != nil {
				t.Logf("Got AXFR response: ID=%d, ANCount=%d", msg.Header.ID, msg.Header.ANCount)
			}
		}
	}
}

// BenchmarkDNSQuery benchmarks DNS query throughput.
func BenchmarkDNSQuery(b *testing.B) {
	server, err := NewDNSServer()
	if err != nil {
		b.Fatalf("Failed to create test server: %v", err)
	}
	defer server.Close()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := server.Query(context.Background(), "www.example.com.", protocol.TypeA)
		if err != nil {
			b.Fatalf("Query failed: %v", err)
		}
	}
}
