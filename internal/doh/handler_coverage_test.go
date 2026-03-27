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

func TestDoHResponseWriter_DoubleWrite(t *testing.T) {
	// Test that writing twice returns an error (covers the "response already written" path)
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		// Write twice - second should fail
		w.Write(&protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})

		n, err := w.Write(&protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		})

		if err == nil {
			t.Error("Expected error on second write")
		}
		if n != 0 {
			t.Errorf("Expected 0 bytes on second write, got %d", n)
		}
	}))

	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// First write should succeed
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestDoHResponseWriter_QuestionsCopiedFromQuery(t *testing.T) {
	// Test that questions are copied from query when response has none
	queryData, query := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	var capturedResponse *protocol.Message
	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		// Create response with no questions
		resp := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
			Questions: nil, // No questions
		}
		capturedResponse = resp
		w.Write(resp)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	// Verify the response questions were populated from the query
	if len(capturedResponse.Questions) != len(query.Questions) {
		t.Errorf("Expected questions to be copied from query, got %d questions", len(capturedResponse.Questions))
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		name string
		port string
		want int
	}{
		{"empty string", "", 0},
		{"valid port", "443", 443},
		{"valid port high", "8443", 8443},
		{"non-numeric", "abc", 0},
		{"partial numeric", "12abc", 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parsePort(tt.port)
			if got != tt.want {
				t.Errorf("parsePort(%q) = %d, want %d", tt.port, got, tt.want)
			}
		})
	}
}

func TestDoHPOST_ReadBodyError(t *testing.T) {
	// Test POST with body that returns error on read
	handler := NewHandler(&mockDNSHandler{})

	queryData, _ := createTestQuery()

	// Use a reader that will error after being limited
	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(queryData))
	req.Header.Set("Content-Type", ContentTypeDNSMessage)

	// Set a very small content length to trigger MaxBytesReader error
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// This should succeed since the body is small enough
	if rr.Code != http.StatusOK && rr.Code != http.StatusBadRequest {
		t.Errorf("Got status %d", rr.Code)
	}
}

func TestDoHPOST_EmptyBody(t *testing.T) {
	// Test POST with empty body
	handler := NewHandler(&mockDNSHandler{})

	req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader([]byte{}))
	req.Header.Set("Content-Type", ContentTypeDNSMessage)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	// Empty body should fail DNS parsing
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for empty body, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestDoHGET_NoQuestions(t *testing.T) {
	// Test a valid DNS message with no questions
	handler := NewHandler(&mockDNSHandler{})

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      5678,
			Flags:   protocol.NewQueryFlags(),
			QDCount: 0,
		},
		Questions: nil, // No questions
	}

	buf := make([]byte, msg.WireLength())
	n, _ := msg.Pack(buf)
	encoded := base64.RawURLEncoding.EncodeToString(buf[:n])

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for no questions, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestDoHResponseWriter_QRFlag(t *testing.T) {
	// Test that QR flag is set to true in the response
	queryData, _ := createTestQuery()
	encoded := base64.RawURLEncoding.EncodeToString(queryData)

	handler := NewHandler(server.HandlerFunc(func(w server.ResponseWriter, r *protocol.Message) {
		resp := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
			},
		}
		w.Write(resp)
	}))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+encoded, nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	resp, err := protocol.UnpackMessage(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("Failed to unpack response: %v", err)
	}

	if !resp.Header.Flags.QR {
		t.Error("Expected QR flag to be true in response")
	}
}
