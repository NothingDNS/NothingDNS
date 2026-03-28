package doh

import (
	"bytes"
	"encoding/base64"
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
