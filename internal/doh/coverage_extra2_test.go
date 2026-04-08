package doh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// TestDoHPOST_BodyExceedsMaxSize tests that handlePOST returns an error when
// the POST body exceeds MaxDNSMessageSize (65535 bytes), triggering the
// io.ReadAll error path from http.MaxBytesReader.
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

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for oversized body, got %d", http.StatusBadRequest, rr.Code)
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
					Name:   &protocol.Name{Labels: []string{longLabel, "com"}, FQDN: true},
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
