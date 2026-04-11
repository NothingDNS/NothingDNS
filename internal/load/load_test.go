package load

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestRunPreset(t *testing.T) {
	// This test just validates the preset runs without panic
	// Actual load testing requires a running DNS server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := RunPreset(ctx, "127.0.0.1:5354", "light")

	// With no server running, we expect 100% errors/timeouts
	if result == nil {
		t.Fatal("result was nil")
	}

	t.Logf("Light preset result: Success=%d, Errors=%d, Timeouts=%d",
		result.Success, result.Errors, result.Timeouts)
}

func TestConfigValidation(t *testing.T) {
	cfg := Config{
		Server:   "127.0.0.1:53",
		Queries:  100,
		Workers:  4,
		Timeout:  2 * time.Second,
		Type:     1, // TypeA
		Name:     "www.example.com.",
		Protocol: "tcp",
	}

	runner := NewRunner(cfg)
	if runner == nil {
		t.Fatal("NewRunner returned nil")
	}
}

// TestIntegrationLoadWithServer tests load against an actual DNS server.
func TestIntegrationLoadWithServer(t *testing.T) {
	// Create a TCP server that sends proper DNS responses
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				for {
					conn.SetDeadline(time.Now().Add(3 * time.Second))
					// Read 2-byte length prefix
					var lenBuf [2]byte
					_, err := conn.Read(lenBuf[:])
					if err != nil {
						return
					}
					msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
					if msgLen > 4096 || msgLen < 12 {
						return
					}
					buf := make([]byte, msgLen)
					_, err = conn.Read(buf)
					if err != nil {
						return
					}
					// Set QR bit to make it a response
					buf[2] |= 0x80
					// Send back with length prefix
					conn.Write(lenBuf[:])
					conn.Write(buf)
				}
			}(conn)
		}
	}()

	cfg := Config{
		Server:   serverAddr,
		Queries:  50,
		Workers:  2,
		Timeout:  5 * time.Second, // Longer timeout for integration test
		Type:     1,
		Name:     "www.example.com.",
		Protocol: "tcp",
	}

	runner := NewRunner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	result := runner.Run(ctx)
	cancel()

	if result == nil {
		t.Fatal("result was nil")
	}

	total := result.Success + result.Errors + result.Timeouts
	if total == 0 {
		t.Fatal("no queries were attempted")
	}

	// Log results for debugging
	t.Logf("Integration test: Success=%d, Errors=%d, Timeouts=%d, Total=%d",
		result.Success, result.Errors, result.Timeouts, total)
}

// BenchmarkLoadIntegration benchmarks DNS query throughput with a live server.
func BenchmarkLoadIntegration(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	serverAddr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				for {
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					if n < 2 {
						return
					}
					msgLen := int(buf[0])<<8 | int(buf[1])
					if n < msgLen+2 {
						return
					}
					dnsMsg := buf[2 : 2+msgLen]
					dnsMsg[2] |= 0x80
					conn.Write(buf[:2+msgLen])
				}
			}(conn)
		}
	}()

	cfg := Config{
		Server:   serverAddr,
		Queries:  b.N / 4,
		Workers:  4,
		Timeout:  2 * time.Second,
		Type:     1,
		Name:     "www.example.com.",
		Protocol: "tcp",
	}

	runner := NewRunner(cfg)
	ctx := context.Background()

	b.ResetTimer()
	result := runner.Run(ctx)
	b.ReportMetric(float64(result.Success), "queries")
	b.ReportMetric(result.QPS, "queries_per_second")
}
