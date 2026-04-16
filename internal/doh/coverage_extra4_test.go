package doh

import (
	"net"
	"net/http"
	"testing"

	"github.com/nothingdns/nothingdns/internal/server"
)

// ---------------------------------------------------------------------------
// jsonResponseWriter.ClientInfo — hostname fallback to 0.0.0.0
// ---------------------------------------------------------------------------

func TestJSONResponseWriter_ClientInfo_HostnameFallback(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "hostname-not-ip:1234",
	}
	rw := &jsonResponseWriter{httpReq: req}

	info := rw.ClientInfo()
	if info == nil {
		t.Fatal("expected non-nil ClientInfo")
	}
	if info.Protocol != "https" {
		t.Errorf("Protocol = %q, want https", info.Protocol)
	}
	if info.Addr == nil {
		t.Fatal("expected non-nil Addr")
	}
	// Should fall back to 0.0.0.0 since "hostname-not-ip" is not a valid IP
	tcpAddr, ok := info.Addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", info.Addr)
	}
	if !tcpAddr.IP.Equal(net.IPv4(0, 0, 0, 0)) {
		t.Errorf("IP = %v, want 0.0.0.0", tcpAddr.IP)
	}
	if tcpAddr.Port != 1234 {
		t.Errorf("Port = %d, want 1234", tcpAddr.Port)
	}
}

// ---------------------------------------------------------------------------
// jsonResponseWriter.ClientInfo — no port
// ---------------------------------------------------------------------------

func TestJSONResponseWriter_ClientInfo_NoPort(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "1.2.3.4", // no port
	}
	rw := &jsonResponseWriter{httpReq: req}

	info := rw.ClientInfo()
	if info == nil {
		t.Fatal("expected non-nil ClientInfo")
	}
	if info.Protocol != "https" {
		t.Errorf("Protocol = %q, want https", info.Protocol)
	}
	// SplitHostPort fails, so Addr should be nil
	if info.Addr != nil {
		t.Errorf("expected nil Addr when RemoteAddr has no port, got %v", info.Addr)
	}
}

// ---------------------------------------------------------------------------
// dohResponseWriter.ClientInfo — IPv6 address
// ---------------------------------------------------------------------------

func TestDohResponseWriter_ClientInfo_IPv6(t *testing.T) {
	req := &http.Request{
		RemoteAddr: "[::1]:4321",
	}
	rw := &dohResponseWriter{
		r: req,
	}

	info := rw.ClientInfo()
	if info == nil {
		t.Fatal("expected non-nil ClientInfo")
	}
	if info.Addr == nil {
		t.Fatal("expected non-nil Addr")
	}
	tcpAddr, ok := info.Addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", info.Addr)
	}
	if !tcpAddr.IP.Equal(net.ParseIP("::1")) {
		t.Errorf("IP = %v, want ::1", tcpAddr.IP)
	}
	if tcpAddr.Port != 4321 {
		t.Errorf("Port = %d, want 4321", tcpAddr.Port)
	}
}

// ---------------------------------------------------------------------------
// wsResponseWriter — verify interface compliance
// ---------------------------------------------------------------------------

func TestWSResponseWriter_Interface(t *testing.T) {
	// Compile-time check that wsResponseWriter implements server.ResponseWriter
	var _ server.ResponseWriter = (*wsResponseWriter)(nil)
}
