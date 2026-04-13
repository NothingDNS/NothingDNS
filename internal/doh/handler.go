package doh

import (
	"crypto/rand"
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
	// MinPaddingSize is the minimum padding size per RFC 7830
	MinPaddingSize = 32
	// MaxPaddingSize is the maximum padding size per RFC 7830
	MaxPaddingSize = 512
)

// Handler handles DNS over HTTPS requests (RFC 8484).
type Handler struct {
	dnsHandler server.Handler
	padding    bool // Enable RFC 7830 padding
}

// NewHandler creates a new DoH handler.
func NewHandler(dnsHandler server.Handler) *Handler {
	return &Handler{
		dnsHandler: &server.ServeDNSWithRecovery{Handler: dnsHandler},
	}
}

// NewHandlerWithPadding creates a new DoH handler with RFC 7830 padding enabled.
func NewHandlerWithPadding(dnsHandler server.Handler) *Handler {
	return &Handler{
		dnsHandler: &server.ServeDNSWithRecovery{Handler: dnsHandler},
		padding:    true,
	}
}

// ServeHTTP implements http.Handler for DoH.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Route to JSON API handler if the client accepts DNS JSON or uses
	// the ?name= query parameter (Google/Cloudflare JSON API convention).
	if h.isJSONRequest(r) {
		h.serveJSON(w, r)
		return
	}

	var queryData []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		queryData, err = h.handleGET(r)
	case http.MethodPost:
		queryData, err = h.handlePOST(w, r)
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
	rw := newDoHResponseWriter(w, r, query, h.padding)
	h.dnsHandler.ServeDNS(rw, query)
}

// isJSONRequest returns true if the request should be handled as a JSON API
// request rather than wire-format DoH. This is determined by the Accept header
// or the presence of a ?name= query parameter.
func (h *Handler) isJSONRequest(r *http.Request) bool {
	if r.Header.Get("Accept") == ContentTypeDNSJSON {
		return true
	}
	if r.URL.Query().Get("name") != "" {
		return true
	}
	return false
}

// serveJSON handles DNS-over-HTTPS JSON API requests in the
// Google/Cloudflare format.
func (h *Handler) serveJSON(w http.ResponseWriter, r *http.Request) {
	var query *protocol.Message
	var err error

	switch r.Method {
	case http.MethodGet:
		name := r.URL.Query().Get("name")
		qtype := r.URL.Query().Get("type")
		query, err = ParseJSONQueryParams(name, qtype)

	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		if ct != ContentTypeDNSJSON {
			http.Error(w, fmt.Sprintf("unsupported Content-Type: %s (expected %s)", ct, ContentTypeDNSJSON), http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxDNSMessageSize)
		defer r.Body.Close()

		var data []byte
		// Use LimitReader to prevent unbounded allocation even if MaxBytesReader
		// limit is reached
		data, err = io.ReadAll(io.LimitReader(r.Body, MaxDNSMessageSize))
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to read body: %v", err), http.StatusBadRequest)
			return
		}
		query, err = DecodeJSONQuery(data)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create a JSON response writer that captures the DNS response
	jrw := &jsonResponseWriter{
		httpWriter: w,
		httpReq:    r,
	}
	h.dnsHandler.ServeDNS(jrw, query)

	// If the handler didn't produce a response, return a server error
	if jrw.response == nil {
		http.Error(w, "no DNS response generated", http.StatusInternalServerError)
		return
	}

	// Encode the captured response as JSON
	jsonData, err := EncodeJSON(jrw.response)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to encode JSON response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeDNSJSON)
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

// jsonResponseWriter captures a DNS response for subsequent JSON encoding.
// It implements server.ResponseWriter.
type jsonResponseWriter struct {
	httpWriter http.ResponseWriter
	httpReq    *http.Request
	response   *protocol.Message
}

// Write captures the DNS message for later JSON encoding.
func (rw *jsonResponseWriter) Write(msg *protocol.Message) (int, error) {
	if rw.response != nil {
		return 0, fmt.Errorf("response already written")
	}
	rw.response = msg
	return 0, nil
}

// ClientInfo returns information about the client from the HTTP request.
func (rw *jsonResponseWriter) ClientInfo() *server.ClientInfo {
	host, port, err := net.SplitHostPort(rw.httpReq.RemoteAddr)
	if err != nil {
		return &server.ClientInfo{
			Protocol: "https",
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0)
	}

	return &server.ClientInfo{
		Addr: &net.TCPAddr{
			IP:   ip,
			Port: parsePort(port),
		},
		Protocol: "https",
	}
}

// MaxSize returns the maximum response size for JSON DoH.
func (rw *jsonResponseWriter) MaxSize() int {
	return MaxDNSMessageSize
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
func (h *Handler) handlePOST(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	contentType := r.Header.Get("Content-Type")
	if contentType != ContentTypeDNSMessage {
		return nil, fmt.Errorf("unsupported Content-Type: %s (expected %s)", contentType, ContentTypeDNSMessage)
	}

	// Limit body size to prevent abuse
	r.Body = http.MaxBytesReader(w, r.Body, MaxDNSMessageSize)
	defer r.Body.Close()

	data, err := io.ReadAll(io.LimitReader(r.Body, MaxDNSMessageSize))
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
	written  bool
	padding bool
}

// newDoHResponseWriter creates a new DoH response writer.
func newDoHResponseWriter(w http.ResponseWriter, r *http.Request, query *protocol.Message, padding bool) *dohResponseWriter {
	return &dohResponseWriter{
		w:       w,
		r:       r,
		query:   query,
		padding: padding,
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

	// Add RFC 7830 padding if enabled
	if rw.padding {
		buf, _ = padMessage(buf[:n])
		n = len(buf)
	}

	// Write HTTP response
	rw.w.Header().Set("Content-Type", ContentTypeDNSMessage)
	rw.w.WriteHeader(http.StatusOK)
	return rw.w.Write(buf[:n])
}

// ClientInfo returns information about the client.
func (rw *dohResponseWriter) ClientInfo() *server.ClientInfo {
	host, port, err := net.SplitHostPort(rw.r.RemoteAddr)
	if err != nil {
		return &server.ClientInfo{
			Protocol: "https",
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0)
	}

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

// generatePadding generates random padding per RFC 7830.
// Returns a byte slice of random size between MinPaddingSize and MaxPaddingSize.
func generatePadding() ([]byte, error) {
	// Random size between MinPaddingSize and MaxPaddingSize
	size := make([]byte, 1)
	if _, err := rand.Read(size); err != nil {
		return nil, err
	}
	padSize := MinPaddingSize + int(size[0])%(MaxPaddingSize-MinPaddingSize+1)

	// Generate random padding data
	padding := make([]byte, padSize)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	return padding, nil
}

// padMessage adds RFC 7830 padding to a DNS message wire format.
// Padding is appended as trailing bytes to obfuscate response size.
func padMessage(wire []byte) ([]byte, error) {
	padding, err := generatePadding()
	if err != nil {
		return wire, nil // Fallback: return unpadded
	}
	return append(wire, padding...), nil
}
