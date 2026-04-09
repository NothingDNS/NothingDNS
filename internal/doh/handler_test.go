package doh

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

// mockDNSHandler is a test DNS handler that returns a simple response.
type mockDNSHandler struct {
	response *protocol.Message
}

func (h *mockDNSHandler) ServeDNS(w server.ResponseWriter, r *protocol.Message) {
	if h.response != nil {
		w.Write(h.response)
	} else {
		// Return a simple response
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    r.Header.ID,
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: r.Questions,
		}
		w.Write(resp)
	}
}

// createTestQuery creates a simple DNS query for testing.
func createTestQuery() ([]byte, *protocol.Message) {
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{"www", "example", "com"}, FQDN: true},
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	buf := make([]byte, msg.WireLength())
	n, _ := msg.Pack(buf)
	return buf[:n], msg
}

func TestDoHGETRequest(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Create test query
	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	// Create request
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	// Serve request
	handler.ServeHTTP(rr, req)

	// Check response
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		t.Errorf("Expected Content-Type %s, got %s", ContentTypeDNSMessage, contentType)
	}

	// Verify we got a valid DNS response
	if len(rr.Body.Bytes()) == 0 {
		t.Error("Expected non-empty response body")
	}
}

func TestDoHPOSTRequest(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Create test query
	queryData, _ := createTestQuery()

	// Create request
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(queryData))
	req.Header.Set("Content-Type", ContentTypeDNSMessage)
	rr := httptest.NewRecorder()

	// Serve request
	handler.ServeHTTP(rr, req)

	// Check response
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		t.Errorf("Expected Content-Type %s, got %s", ContentTypeDNSMessage, contentType)
	}
}

func TestDoHMissingDNSParameter(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestDoHInvalidBase64(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns=!!!invalid!!!", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestDoHWrongContentType(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	queryData, _ := createTestQuery()

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(queryData))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestDoHInvalidDNSMessage(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Send invalid DNS data
	invalidData := []byte("not a valid dns message")
	encoded := base64.RawURLEncoding.EncodeToString(invalidData)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestDoHMethodNotAllowed(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodPut, "/dns-query", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}

	allow := rr.Header().Get("Allow")
	if allow != "GET, POST" {
		t.Errorf("Expected Allow header 'GET, POST', got %s", allow)
	}
}

func TestDoHSecurityHeaders(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	xcto := rr.Header().Get("X-Content-Type-Options")
	if xcto != "nosniff" {
		t.Errorf("Expected X-Content-Type-Options 'nosniff', got %s", xcto)
	}
}

func TestDoHResponseWriterClientInfo(t *testing.T) {
	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	var capturedClientInfo *server.ClientInfo
	testHandler := server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		capturedClientInfo = w.ClientInfo()
		w.Write(&protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	handler := NewHandler(testHandler)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if capturedClientInfo == nil {
		t.Fatal("Expected ClientInfo to be captured")
	}

	if capturedClientInfo.Protocol != "https" {
		t.Errorf("Expected protocol 'https', got %s", capturedClientInfo.Protocol)
	}
}

func TestDoHResponseIDMatching(t *testing.T) {
	queryData, query := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	testHandler := server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		// Create response with different ID - handler should fix it
		resp := &protocol.Message{
			Header: protocol.Header{
				ID:    9999, // Different from query
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		}
		w.Write(resp)
	})

	handler := NewHandler(testHandler)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	// Decode response and verify ID matches query
	resp, err := protocol.UnpackMessage(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if resp.Header.ID != query.Header.ID {
		t.Errorf("Response ID %d should match query ID %d", resp.Header.ID, query.Header.ID)
	}
}

func TestDoHLargeRequest(t *testing.T) {
	handler := NewHandler(&mockDNSHandler{})

	// Create a large query (but still within limits)
	queryData := make([]byte, 1000)
	for i := range queryData {
		queryData[i] = byte(i % 256)
	}

	// This should fail as it's not a valid DNS message, but size is OK
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Should fail validation, not with "request too large"
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for invalid DNS, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestDoHMaxSize(t *testing.T) {
	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	testHandler := server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		if w.MaxSize() != MaxDNSMessageSize {
			t.Errorf("Expected MaxSize %d, got %d", MaxDNSMessageSize, w.MaxSize())
		}
		w.Write(&protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})
	})

	handler := NewHandler(testHandler)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
}
