package doh

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
)

const (
	// MaxDNSMessageSize is the maximum size of a DNS message (RFC 1035)
	MaxDNSMessageSize = 65535
	// ContentTypeDNSMessage is the MIME type for DNS wire format (RFC 8484)
	ContentTypeDNSMessage = "application/dns-message"
)

// Handler handles DNS over HTTPS requests (RFC 8484).
type Handler struct {
	dnsHandler server.Handler
}

// NewHandler creates a new DoH handler.
func NewHandler(dnsHandler server.Handler) *Handler {
	return &Handler{
		dnsHandler: dnsHandler,
	}
}

// ServeHTTP implements http.Handler for DoH.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")

	var queryData []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		queryData, err = h.handleGET(r)
	case http.MethodPost:
		queryData, err = h.handlePOST(r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse the DNS query from wire format
	query, err := protocol.UnpackMessage(queryData)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid DNS message: %v", err), http.StatusBadRequest)
		return
	}

	// Validate query has questions
	if len(query.Questions) == 0 {
		http.Error(w, "No questions in DNS query", http.StatusBadRequest)
		return
	}

	// Create DoH response writer and handle the query
	rw := newDoHResponseWriter(w, r, query)
	h.dnsHandler.ServeDNS(rw, query)
}

// handleGET processes GET requests with base64url-encoded DNS query.
func (h *Handler) handleGET(r *http.Request) ([]byte, error) {
	dnsParam := r.URL.Query().Get("dns")
	if dnsParam == "" {
		return nil, fmt.Errorf("missing 'dns' parameter")
	}

	// Decode base64url (RFC 8484 - no padding)
	data, err := base64.RawURLEncoding.DecodeString(dnsParam)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding: %w", err)
	}

	return data, nil
}

// handlePOST processes POST requests with DNS query in body.
func (h *Handler) handlePOST(r *http.Request) ([]byte, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		return nil, fmt.Errorf("unsupported Content-Type: %s (expected %s)", contentType, ContentTypeDNSMessage)
	}

	// Limit body size to prevent abuse
	r.Body = http.MaxBytesReader(nil, r.Body, MaxDNSMessageSize)
	defer r.Body.Close()

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	return data, nil
}

// dohResponseWriter adapts http.ResponseWriter for DNS responses.
type dohResponseWriter struct {
	w       http.ResponseWriter
	r       *http.Request
	query   *protocol.Message
	written bool
}

// newDoHResponseWriter creates a new DoH response writer.
func newDoHResponseWriter(w http.ResponseWriter, r *http.Request, query *protocol.Message) *dohResponseWriter {
	return &dohResponseWriter{
		w:     w,
		r:     r,
		query: query,
	}
}

// Write implements server.ResponseWriter by encoding the DNS message to wire format.
func (rw *dohResponseWriter) Write(msg *protocol.Message) (int, error) {
	if rw.written {
		return 0, fmt.Errorf("response already written")
	}
	rw.written = true

	// Ensure response has the same ID as the query
	msg.Header.ID = rw.query.Header.ID
	msg.Header.Flags.QR = true

	// Copy questions if not present
	if len(msg.Questions) == 0 && len(rw.query.Questions) > 0 {
		msg.Questions = rw.query.Questions
	}

	// Pack the message to wire format
	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		http.Error(rw.w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return 0, err
	}

	// Write HTTP response
	rw.w.Header().Set("Content-Type", ContentTypeDNSMessage)
	rw.w.WriteHeader(http.StatusOK)
	return rw.w.Write(buf[:n])
}

// ClientInfo returns information about the client.
func (rw *dohResponseWriter) ClientInfo() *server.ClientInfo {
	host, port, _ := net.SplitHostPort(rw.r.RemoteAddr)
	ip := net.ParseIP(host)

	return &server.ClientInfo{
		Addr: &net.TCPAddr{
			IP:   ip,
			Port: parsePort(port),
		},
		Protocol: "https",
	}
}

// MaxSize returns the maximum response size for DoH.
func (rw *dohResponseWriter) MaxSize() int {
	return MaxDNSMessageSize
}

// parsePort parses a port string to int.
func parsePort(port string) int {
	if port == "" {
		return 0
	}
	var p int
	if _, err := fmt.Sscanf(port, "%d", &p); err != nil {
		return 0
	}
	return p
}
