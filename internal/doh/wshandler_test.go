package doh

import (
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

func TestNewWSHandler(t *testing.T) {
	h := NewWSHandler(nil, nil)
	if h == nil {
		t.Fatal("NewWSHandler returned nil")
	}
	if h.dnsHandler == nil {
		t.Error("dnsHandler should be wrapped in ServeDNSWithRecovery, not nil")
	}

	h2 := NewWSHandler(nil, []string{"https://example.com"})
	if len(h2.allowedOrigins) != 1 {
		t.Errorf("expected 1 allowed origin, got %d", len(h2.allowedOrigins))
	}
}

func TestWSHandler_ServeHTTP_InvalidUpgrade(t *testing.T) {
	// Regular HTTP GET (not a WebSocket upgrade) should fail handshake
	h := NewWSHandler(&mockDNSHandler{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	// Handshake failure returns 400 or similar non-200
	if rr.Code == http.StatusOK {
		t.Error("Expected non-200 for non-WebSocket request")
	}
}

func TestWSResponseWriter_ClientInfo_ValidAddr(t *testing.T) {
	rw := &wsResponseWriter{
		httpReq: &http.Request{RemoteAddr: "10.0.0.1:54321"},
	}
	info := rw.ClientInfo()
	if info.Protocol != "wss" {
		t.Errorf("Expected protocol 'wss', got %s", info.Protocol)
	}
	tcpAddr, ok := info.Addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("Expected *net.TCPAddr, got %T", info.Addr)
	}
	if !tcpAddr.IP.Equal([]byte{10, 0, 0, 1}) {
		t.Errorf("Expected IP 10.0.0.1, got %v", tcpAddr.IP)
	}
	if tcpAddr.Port != 54321 {
		t.Errorf("Expected port 54321, got %d", tcpAddr.Port)
	}
}

func TestWSResponseWriter_ClientInfo_InvalidAddr(t *testing.T) {
	rw := &wsResponseWriter{
		httpReq: &http.Request{RemoteAddr: "invalid"},
	}
	info := rw.ClientInfo()
	if info.Protocol != "wss" {
		t.Errorf("Expected protocol 'wss', got %s", info.Protocol)
	}
	if info.Addr != nil {
		t.Errorf("Expected nil Addr for invalid RemoteAddr, got %v", info.Addr)
	}
}

func TestWSResponseWriter_ClientInfo_NoPort(t *testing.T) {
	rw := &wsResponseWriter{
		httpReq: &http.Request{RemoteAddr: "10.0.0.1"},
	}
	info := rw.ClientInfo()
	if info.Protocol != "wss" {
		t.Errorf("Expected protocol 'wss', got %s", info.Protocol)
	}
}

func TestWSResponseWriter_ClientInfo_InvalidIP(t *testing.T) {
	rw := &wsResponseWriter{
		httpReq: &http.Request{RemoteAddr: "not-an-ip:1234"},
	}
	info := rw.ClientInfo()
	if info.Protocol != "wss" {
		t.Errorf("Expected protocol 'wss', got %s", info.Protocol)
	}
	// Should get 0.0.0.0 fallback
	tcpAddr, ok := info.Addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("Expected *net.TCPAddr, got %T", info.Addr)
	}
	if !tcpAddr.IP.Equal([]byte{0, 0, 0, 0}) {
		t.Errorf("Expected 0.0.0.0 fallback, got %v", tcpAddr.IP)
	}
}

func TestDohResponseWriter_ClientInfo_ValidAddr(t *testing.T) {
	_, query := createTestQuery()
	rw := newDoHResponseWriter(httptest.NewRecorder(), &http.Request{RemoteAddr: "192.168.1.100:8080"}, query, false)
	info := rw.ClientInfo()
	if info.Protocol != "https" {
		t.Errorf("Expected protocol 'https', got %s", info.Protocol)
	}
	tcpAddr, ok := info.Addr.(*net.TCPAddr)
	if !ok {
		t.Fatalf("Expected *net.TCPAddr, got %T", info.Addr)
	}
	if tcpAddr.Port != 8080 {
		t.Errorf("Expected port 8080, got %d", tcpAddr.Port)
	}
}

func TestDohResponseWriter_ClientInfo_InvalidAddr(t *testing.T) {
	_, query := createTestQuery()
	rw := newDoHResponseWriter(httptest.NewRecorder(), &http.Request{RemoteAddr: "garbage"}, query, false)
	info := rw.ClientInfo()
	if info.Protocol != "https" {
		t.Errorf("Expected protocol 'https', got %s", info.Protocol)
	}
	if info.Addr != nil {
		t.Errorf("Expected nil Addr, got %v", info.Addr)
	}
}

func TestServeHTTP_MethodNotAllowed(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodPut, "/dns-query", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for PUT, got %d", rr.Code)
	}
	if rr.Header().Get("Allow") != "GET, POST" {
		t.Errorf("Expected Allow header 'GET, POST', got %s", rr.Header().Get("Allow"))
	}
}

func TestServeHTTP_GET_MissingDNS(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing dns param, got %d", rr.Code)
	}
}

func TestServeHTTP_GET_InvalidBase64(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns=!invalid-base64!", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid base64, got %d", rr.Code)
	}
}

func TestServeHTTP_GET_OversizedDNS(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Create a base64 string that exceeds MaxBase64DNSSize
	oversized := strings.Repeat("A", MaxBase64DNSSize+1)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+oversized, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for oversized dns param, got %d", rr.Code)
	}
}

func TestServeHTTP_POST_WrongContentType(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	queryData, _ := createTestQuery()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader(string(queryData)))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for wrong content type, got %d", rr.Code)
	}
}

func TestServeHTTP_SecurityHeaders(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Any request should set security headers
	queryData, _ := createTestQuery()
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader(string(queryData)))
	req.Header.Set("Content-Type", ContentTypeDNSMessage)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Check security headers are present
	expectedHeaders := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"X-XSS-Protection":       "1; mode=block",
	}
	for hdr, expected := range expectedHeaders {
		got := rr.Header().Get(hdr)
		if got != expected {
			t.Errorf("Expected %s=%q, got %q", hdr, expected, got)
		}
	}

	hsts := rr.Header().Get("Strict-Transport-Security")
	if !strings.Contains(hsts, "max-age=31536000") {
		t.Errorf("Expected HSTS header with max-age, got %q", hsts)
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("Expected CSP header, got %q", csp)
	}
}

func TestDoHResponseWriter_WithPadding(t *testing.T) {
	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	handler := NewHandlerWithPadding(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: r.Questions,
		}
		w.Write(resp)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rr.Code)
	}

	// Response should be larger than MinPaddingSize due to RFC 7830 padding
	if rr.Body.Len() < MinPaddingSize {
		t.Errorf("Expected padded response > %d bytes, got %d", MinPaddingSize, rr.Body.Len())
	}
}

func TestJSONResponseWriter_DoubleWrite(t *testing.T) {
	rw := &jsonResponseWriter{}

	resp1 := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}
	_, err := rw.Write(resp1)
	if err != nil {
		t.Fatalf("First write should succeed: %v", err)
	}

	resp2 := &protocol.Message{
		Header: protocol.Header{Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
	}
	n, err := rw.Write(resp2)
	if err == nil {
		t.Error("Second write should return error")
	}
	if n != 0 {
		t.Errorf("Second write should return 0, got %d", n)
	}
}

func TestServeJSON_POST_ReadBodyError(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// POST with JSON content type but name parameter and body that's invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/dns-query?name=x", strings.NewReader(""))
	req.Header.Set("Content-Type", ContentTypeDNSJSON)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Empty body should fail JSON decode
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for empty JSON body, got %d", rr.Code)
	}
}

func TestServeJSON_AcceptHeader(t *testing.T) {
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header:    protocol.Header{ID: r.Header.ID, Flags: protocol.NewResponseFlags(protocol.RcodeSuccess)},
			Questions: r.Questions,
		}
		w.Write(resp)
	}))

	// Use Accept header to trigger JSON mode
	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=A", nil)
	req.Header.Set("Accept", ContentTypeDNSJSON)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
	if rr.Header().Get("Content-Type") != ContentTypeDNSJSON {
		t.Errorf("Expected Content-Type %s, got %s", ContentTypeDNSJSON, rr.Header().Get("Content-Type"))
	}
}

func TestHandlePOST_InvalidDNS(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Valid content type but invalid DNS message
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader("not-a-dns-message"))
	req.Header.Set("Content-Type", ContentTypeDNSMessage)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid DNS body, got %d", rr.Code)
	}
}
