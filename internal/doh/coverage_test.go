package doh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// unsafeName constructs a protocol.Name without validation. Use only in tests
// that intentionally exercise pack-time name validation failures.
func unsafeName(labels []string, fqdn bool) *protocol.Name {
	return protocol.NewUnsafeName(labels, fqdn)
}

// TestDoHPOST_BodyExceedsMaxSize tests that handlePOST rejects bodies
// above MaxDNSMessageSize instead of silently truncating them.
func TestDoHPOST_BodyExceedsMaxSize(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Create a body larger than MaxDNSMessageSize (65535 bytes)
	oversizedBody := make([]byte, MaxDNSMessageSize+1)
	for i := range oversizedBody {
		oversizedBody[i] = byte('A')
	}

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(oversizedBody))
	req.Header.Set("Content-Type", ContentTypeDNSMessage)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status %d for oversized body, got %d", http.StatusRequestEntityTooLarge, rr.Code)
	}
}

// TestDoHResponseWriter_PackError tests the dohResponseWriter.Write error path
// where msg.Pack(buf) fails. This is triggered by creating a response message
// containing a Question with a label exceeding MaxLabelLength (63 bytes).
// WireLength() will compute a valid buffer size, but Pack() will fail because
// the label is too long.
func TestDoHResponseWriter_PackError(t *testing.T) {
	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	// Create a handler that returns a response with an invalidly long label.
	// WireLength computes size fine, but Pack fails with ErrLabelTooLong.
	longLabel := strings.Repeat("a", 64) // 64 > MaxLabelLength(63)

	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: []*protocol.Question{
				{
					Name:   unsafeName([]string{longLabel, "com"}, true),
					QType:  protocol.TypeA,
					QClass: protocol.ClassIN,
				},
			},
		}
		n, err := w.Write(resp)
		if err == nil {
			t.Error("Expected error from Write with invalid label")
		}
		if n != 0 {
			t.Errorf("Expected 0 bytes written, got %d", n)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

// TestServeJSON_GET tests the JSON API GET path via ?name= parameter
func TestServeJSON_GET(t *testing.T) {
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
			Answers: []*protocol.ResourceRecord{
				{
					Name:  r.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				},
			},
		}
		w.Write(resp)
	}))

	// Use ?name= to trigger JSON mode
	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=A", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	if rr.Header().Get("Content-Type") != ContentTypeDNSJSON {
		t.Errorf("Expected Content-Type %s, got %s", ContentTypeDNSJSON, rr.Header().Get("Content-Type"))
	}

	// Verify response is valid JSON
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Response is not valid JSON: %v", err)
	}

	if resp["Status"] != float64(0) {
		t.Errorf("Expected Status 0 (NOERROR), got %v", resp["Status"])
	}
}

func TestServeJSONHandlesResponseWriteError(t *testing.T) {
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
			Answers: []*protocol.ResourceRecord{
				{
					Name:  r.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				},
			},
		}
		w.Write(resp)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=A", nil)
	w := &failingJSONResponseWriter{header: make(http.Header)}

	handler.ServeHTTP(w, req)

	if w.status != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.status, http.StatusOK)
	}
	if w.writes != 1 {
		t.Fatalf("writes = %d, want 1", w.writes)
	}
	if ct := w.Header().Get("Content-Type"); ct != ContentTypeDNSJSON {
		t.Fatalf("Content-Type = %q, want %q", ct, ContentTypeDNSJSON)
	}
}

// TestServeJSON_GET_NoType defaults to A record
func TestServeJSON_GET_NoType(t *testing.T) {
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		// Verify the query type is A when not specified
		if len(r.Questions) > 0 && r.Questions[0].QType != protocol.TypeA {
			t.Errorf("Expected TypeA when type not specified, got %d", r.Questions[0].QType)
		}
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
		}
		w.Write(resp)
	}))

	// Use ?name= without type (should default to A)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

type failingJSONResponseWriter struct {
	header http.Header
	status int
	writes int
}

func (w *failingJSONResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingJSONResponseWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("write failed")
}

func (w *failingJSONResponseWriter) WriteHeader(status int) {
	w.status = status
}

// TestServeJSON_POST tests the JSON API POST path
func TestServeJSON_POST(t *testing.T) {
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
			Answers: []*protocol.ResourceRecord{
				{
					Name:  r.Questions[0].Name,
					Type:  protocol.TypeA,
					Class: protocol.ClassIN,
					TTL:   300,
					Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
				},
			},
		}
		w.Write(resp)
	}))

	// Create JSON POST body - must include ?name= to trigger JSON mode
	jsonBody := `{"name":"example.com","type":"A"}`
	req := httptest.NewRequest(http.MethodPost, "/dns-query?name=example.com", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", ContentTypeDNSJSON)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	if rr.Header().Get("Content-Type") != ContentTypeDNSJSON {
		t.Errorf("Expected Content-Type %s, got %s", ContentTypeDNSJSON, rr.Header().Get("Content-Type"))
	}
}

// TestServeJSON_POST_InvalidContentType tests POST with wrong content type
func TestServeJSON_POST_InvalidContentType(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	jsonBody := `{"name":"example.com","type":"A"}`
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "text/plain") // Wrong content type
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for wrong content type, got %d", rr.Code)
	}
}

// TestServeJSON_POST_InvalidJSON tests POST with invalid JSON body
func TestServeJSON_POST_InvalidJSON(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Invalid JSON body
	req := httptest.NewRequest(http.MethodPost, "/dns-query", strings.NewReader("{invalid}"))
	req.Header.Set("Content-Type", ContentTypeDNSJSON)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestServeJSON_POST_BodyExceedsMaxSize(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodPost, "/dns-query?name=example.com", bytes.NewReader(make([]byte, MaxDNSMessageSize+1)))
	req.Header.Set("Content-Type", ContentTypeDNSJSON)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status %d for oversized JSON body, got %d", http.StatusRequestEntityTooLarge, rr.Code)
	}
}

// TestServeJSON_NoDNSResponse tests when DNS handler doesn't produce a response
func TestServeJSON_NoDNSResponse(t *testing.T) {
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		// Don't write any response
	}))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=A", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 when no DNS response, got %d", rr.Code)
	}
}

func TestServeHTTP_WireNoDNSResponse(t *testing.T) {
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		// Don't write any response
	}))

	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 when no DNS response, got %d", rr.Code)
	}
}

// TestServeJSON_EncodeError tests when JSON encoding fails
func TestServeJSON_EncodeError(t *testing.T) {
	// This is harder to trigger because our mock always produces valid messages
	// Skip for now - would require mocking EncodeJSON
}

// TestServeJSON_MethodNotAllowed tests invalid HTTP method for JSON API
func TestServeJSON_MethodNotAllowed(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodDelete, "/dns-query?name=example.com", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405 for DELETE, got %d", rr.Code)
	}

	// Verify Allow header is set
	if rr.Header().Get("Allow") != "GET, POST" {
		t.Errorf("Expected Allow header 'GET, POST', got %s", rr.Header().Get("Allow"))
	}
}

// TestServeJSON_ClientInfo tests that ClientInfo is properly extracted from request
func TestServeJSON_ClientInfo(t *testing.T) {
	var capturedInfo *server.ClientInfo

	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		capturedInfo = w.ClientInfo()
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
		}
		w.Write(resp)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=A", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if capturedInfo == nil {
		t.Fatal("Expected ClientInfo to be captured")
	}

	if capturedInfo.Protocol != "https" {
		t.Errorf("Expected Protocol 'https', got %s", capturedInfo.Protocol)
	}
}

// TestServeJSON_MaxSize tests that MaxSize returns correct value for JSON mode
func TestServeJSON_MaxSize(t *testing.T) {
	// This is tested indirectly through the jsonResponseWriter.MaxSize() method
	// which returns MaxDNSMessageSize. Direct testing requires the Write path.
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		ms := w.MaxSize()
		if ms != MaxDNSMessageSize {
			t.Errorf("Expected MaxSize %d, got %d", MaxDNSMessageSize, ms)
		}
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
		}
		w.Write(resp)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=A", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

// TestIsJSONRequest tests isJSONRequest detection logic
func TestIsJSONRequest(t *testing.T) {
	h := NewHandler(&mockDNSHandler{})

	tests := []struct {
		name      string
		acceptHdr string
		query     string
		want      bool
	}{
		{"Accept header", "application/dns-json", "", true},
		{"name parameter", "", "name=example.com", true},
		{"both", "application/dns-json", "name=example.com", true},
		{"neither", "", "", false},
		{"type param only", "", "type=A", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/dns-query?"+tt.query, nil)
			if tt.acceptHdr != "" {
				req.Header.Set("Accept", tt.acceptHdr)
			}
			got := h.isJSONRequest(req)
			if got != tt.want {
				t.Errorf("isJSONRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewHandler(t *testing.T) {
	h := NewHandler(nil)
	if h == nil {
		t.Fatal("NewHandler returned nil")
	}
	if h.padding {
		t.Error("padding should be false by default")
	}
}

func TestNewHandlerWithPadding(t *testing.T) {
	h := NewHandlerWithPadding(nil)
	if h == nil {
		t.Fatal("NewHandlerWithPadding returned nil")
	}
	if !h.padding {
		t.Error("padding should be true")
	}
}

func TestHandlerServeHTTPRejectsUninitializedHandler(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler *Handler
	}{
		{name: "nil handler", handler: nil},
		{name: "zero value handler", handler: &Handler{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
			rr := httptest.NewRecorder()

			tc.handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusServiceUnavailable)
			}
		})
	}
}

func TestQueryHasPaddingOption(t *testing.T) {
	if queryHasPaddingOption(nil) {
		t.Error("nil query must not report a padding option")
	}
	plain := &protocol.Message{}
	if queryHasPaddingOption(plain) {
		t.Error("query without OPT must not report a padding option")
	}
	withOpt := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{Type: protocol.TypeOPT, Data: &protocol.RDataOPT{}},
		},
	}
	if queryHasPaddingOption(withOpt) {
		t.Error("OPT without padding option must not report one")
	}
	withPadding := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{Type: protocol.TypeOPT, Data: &protocol.RDataOPT{
				Options: []protocol.EDNS0Option{{Code: EDNS0OptionPadding, Data: []byte{0, 0}}},
			}},
		},
	}
	if !queryHasPaddingOption(withPadding) {
		t.Error("OPT with padding option must be detected")
	}
}

func TestPadResponseMessage(t *testing.T) {
	// No OPT record → nothing to pad.
	noOpt := &protocol.Message{}
	if padResponseMessage(noOpt, 100) {
		t.Error("padResponseMessage must return false without an OPT record")
	}

	// With OPT: option data sizes the message up to the next 468 block.
	msg := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{Type: protocol.TypeOPT, Data: &protocol.RDataOPT{}},
		},
	}
	const packedLen = 100
	if !padResponseMessage(msg, packedLen) {
		t.Fatal("padResponseMessage must pad when an OPT record exists")
	}
	opt := msg.Additionals[0].Data.(*protocol.RDataOPT)
	po := opt.GetOption(EDNS0OptionPadding)
	if po == nil {
		t.Fatal("padding option not added")
	}
	// RFC 8467 §4.1 block-level padding: padLen = blockFill + extra,
	// where blockFill = next-block - (packedLen+4) mod blockSize (∈ [0, blockSize))
	// and extra = rand16 % blockSize (∈ [0, blockSize-1]).
	// Therefore: padLen ∈ [blockFill, blockFill + blockSize).
	withOptionHeader := packedLen + 4
	blockFill := (paddingBlockSize - withOptionHeader%paddingBlockSize) % paddingBlockSize
	padLen := len(po.Data)
	if padLen < blockFill || padLen >= blockFill+paddingBlockSize {
		t.Errorf("padLen %d is outside the valid range [%d, %d)",
			padLen, blockFill, blockFill+paddingBlockSize)
	}
}

// padResponseMessage sizing edge: a message already at a block boundary
// (after the 4-byte option header) gets a zero-length padding option, not
// an extra full block.
func TestPadResponseMessage_ExactBoundary(t *testing.T) {
	msg := &protocol.Message{
		Additionals: []*protocol.ResourceRecord{
			{Type: protocol.TypeOPT, Data: &protocol.RDataOPT{}},
		},
	}
	packedLen := paddingBlockSize - 4 // header lands exactly on the boundary
	if !padResponseMessage(msg, packedLen) {
		t.Fatal("padResponseMessage must pad when an OPT record exists")
	}
	opt := msg.Additionals[0].Data.(*protocol.RDataOPT)
	po := opt.GetOption(EDNS0OptionPadding)
	if po == nil {
		t.Fatal("padding option not added")
	}
	// With block-level randomization (RFC 8467 §4.1), padLen ∈ [0, paddingBlockSize)
	// even at exact boundary. The blockFill is 0 but extra is sampled.
	padLen := len(po.Data)
	if padLen < 0 || padLen >= paddingBlockSize {
		t.Errorf("padLen %d is outside the valid range [0, %d)", padLen, paddingBlockSize)
	}
	// At exact boundary (withOptionHeader == blockSize), blockFill is 0,
	// so totalPadded ∈ [blockSize, 2*blockSize).
	totalPadded := packedLen + 4 + padLen
	if totalPadded < paddingBlockSize {
		t.Errorf("padded size %d is below the minimum block size %d", totalPadded, paddingBlockSize)
	}
	if totalPadded > 2*paddingBlockSize {
		t.Errorf("padded size %d exceeds 2× block size %d", totalPadded, paddingBlockSize)
	}
}

func TestDohResponseWriter_MaxSize(t *testing.T) {
	rw := &dohResponseWriter{}
	if rw.MaxSize() != MaxDNSMessageSize {
		t.Errorf("MaxSize should be %d, got %d", MaxDNSMessageSize, rw.MaxSize())
	}
}

func TestWsResponseWriter_MaxSize(t *testing.T) {
	rw := &wsResponseWriter{}
	if rw.MaxSize() != MaxDNSMessageSize {
		t.Errorf("MaxSize should be %d, got %d", MaxDNSMessageSize, rw.MaxSize())
	}
}

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
