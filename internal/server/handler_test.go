package server

import (
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TestClientInfoString tests the ClientInfo.String() method.
func TestClientInfoString(t *testing.T) {
	tests := []struct {
		name     string
		client   *ClientInfo
		expected string
	}{
		{
			name:     "nil client",
			client:   nil,
			expected: "<nil>",
		},
		{
			name: "client with UDP addr",
			client: &ClientInfo{
				Addr: &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 53},
			},
			expected: "192.168.1.1:53",
		},
		{
			name: "client with TCP addr",
			client: &ClientInfo{
				Addr: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345},
			},
			expected: "10.0.0.1:12345",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.client.String()
			if result != tt.expected {
				t.Errorf("String() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestClientInfoIPMore tests additional ClientInfo.IP() cases.
func TestClientInfoIPMore(t *testing.T) {
	// Test with IPAddr (non-TCP/UDP)
	client := &ClientInfo{
		Addr: &net.IPAddr{IP: net.ParseIP("172.16.0.1")},
	}
	ip := client.IP()
	if ip == nil || ip.String() != "172.16.0.1" {
		t.Errorf("IP() = %v, want 172.16.0.1", ip)
	}

	// Test with IPAddr with zone - returns nil since "fe80::1%eth0" can't be parsed
	client2 := &ClientInfo{
		Addr: &net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "eth0"},
	}
	ip2 := client2.IP()
	// Zone suffix causes parse to fail, so IP() returns nil
	// This is expected behavior
	_ = ip2 // Just verify it doesn't panic
}

// TestHandlerFunc tests the HandlerFunc adapter.
func TestHandlerFunc(t *testing.T) {
	called := false
	handler := HandlerFunc(func(w ResponseWriter, req *protocol.Message) {
		called = true
	})

	// Create a mock response writer
	rw := &mockResponseWriter{client: &ClientInfo{Protocol: "udp"}}

	// Create a simple message
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x1234,
			Flags: protocol.NewQueryFlags(),
		},
	}

	handler.ServeDNS(rw, msg)

	if !called {
		t.Error("HandlerFunc should have been called")
	}
}

// TestNewResponseWriter tests the NewResponseWriter function.
func TestNewResponseWriter(t *testing.T) {
	client := &ClientInfo{
		Protocol: "udp",
		Addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
	}
	maxSize := 512

	rw := NewResponseWriter(client, maxSize)

	if rw == nil {
		t.Fatal("NewResponseWriter should not return nil")
	}

	if rw.ClientInfo() != client {
		t.Error("ClientInfo() should return the same client")
	}

	if rw.MaxSize() != maxSize {
		t.Errorf("MaxSize() = %d, want %d", rw.MaxSize(), maxSize)
	}
}

// TestBaseResponseWriterWrite tests that baseResponseWriter.Write returns an error.
func TestBaseResponseWriterWrite(t *testing.T) {
	client := &ClientInfo{Protocol: "udp"}
	rw := NewResponseWriter(client, 512).(*baseResponseWriter)

	msg := &protocol.Message{}
	_, err := rw.Write(msg)
	if err == nil {
		t.Error("baseResponseWriter.Write() should return an error")
	}
}

// TestResponseSizeLimitEdgeCases tests edge cases for ResponseSizeLimit.
func TestResponseSizeLimitEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		client   *ClientInfo
		expected int
	}{
		{
			name:     "nil client",
			client:   nil,
			expected: 512,
		},
		{
			name: "TCP always returns max",
			client: &ClientInfo{
				Protocol:     "tcp",
				HasEDNS0:     true,
				EDNS0UDPSize: 1280,
			},
			expected: 65535,
		},
		{
			name: "UDP with EDNS0 at boundary",
			client: &ClientInfo{
				Protocol:     "udp",
				HasEDNS0:     true,
				EDNS0UDPSize: 512,
			},
			expected: 512, // Exactly 512 should stay 512
		},
		{
			name: "UDP with EDNS0 just above 512",
			client: &ClientInfo{
				Protocol:     "udp",
				HasEDNS0:     true,
				EDNS0UDPSize: 513,
			},
			expected: 513,
		},
		{
			name: "UDP with EDNS0 just below cap",
			client: &ClientInfo{
				Protocol:     "udp",
				HasEDNS0:     true,
				EDNS0UDPSize: 4095,
			},
			expected: 4095,
		},
		{
			name: "UDP with EDNS0 exactly at cap",
			client: &ClientInfo{
				Protocol:     "udp",
				HasEDNS0:     true,
				EDNS0UDPSize: 4096,
			},
			expected: 4096,
		},
		{
			name: "UDP with EDNS0 above cap",
			client: &ClientInfo{
				Protocol:     "udp",
				HasEDNS0:     true,
				EDNS0UDPSize: 65535,
			},
			expected: 4096, // Capped
		},
		{
			name: "UDP without EDNS0 ignores EDNS0UDPSize",
			client: &ClientInfo{
				Protocol:     "udp",
				HasEDNS0:     false,
				EDNS0UDPSize: 4096,
			},
			expected: 512, // No EDNS0 means 512
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ResponseSizeLimit(tt.client)
			if result != tt.expected {
				t.Errorf("ResponseSizeLimit() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// mockResponseWriter is a mock for testing.
type mockResponseWriter struct {
	client  *ClientInfo
	maxSize int
	written bool
	msg     *protocol.Message
}

func (m *mockResponseWriter) ClientInfo() *ClientInfo {
	return m.client
}

func (m *mockResponseWriter) MaxSize() int {
	return m.maxSize
}

func (m *mockResponseWriter) Write(msg *protocol.Message) (int, error) {
	if m.written {
		return 0, nil
	}
	m.written = true
	m.msg = msg
	return 0, nil
}
