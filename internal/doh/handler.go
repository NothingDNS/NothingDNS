package doh

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
)

const (
	// MaxDNSMessageSize is the maximum size of a DNS message (RFC 1035)
	MaxDNSMessageSize = 65535
	// MaxBase64DNSSize is the maximum base64url-encoded DNS query size.
	// 65535 bytes -> ~87384 base64 characters. Limit to 90000 to allow overhead.
	MaxBase64DNSSize = 90000
	// ContentTypeDNSMessage is the MIME type for DNS wire format (RFC 8484)
	ContentTypeDNSMessage = "application/dns-message"
)

var errBodyTooLarge = errors.New("doh body too large")

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
	if h == nil || h.dnsHandler == nil {
		http.Error(w, "DoH handler not initialised", http.StatusServiceUnavailable)
		return
	}

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
		if errors.Is(err, errBodyTooLarge) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Parse the DNS query from wire format
	query, err := protocol.UnpackMessage(queryData)
	if err != nil {
		http.Error(w, "Invalid DNS message", http.StatusBadRequest)
		return
	}
	defer query.Release()

	// Validate query has questions
	if len(query.Questions) == 0 {
		http.Error(w, "No questions in DNS query", http.StatusBadRequest)
		return
	}

	// Create DoH response writer and handle the query
	rw := newDoHResponseWriter(w, r, query, h.padding)
	h.dnsHandler.ServeDNS(rw, query)
	if !rw.written {
		http.Error(w, "no DNS response generated", http.StatusInternalServerError)
	}
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
		// mime.ParseMediaType tolerates parameters (charset=...) — plain
		// string equality rejected "application/dns-json; charset=utf-8"
		// while handlePOST accepted the equivalent for wire format.
		ct, _, ctErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if ctErr != nil || ct != ContentTypeDNSJSON {
			http.Error(w, "unsupported Content-Type", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxDNSMessageSize+1)
		defer r.Body.Close()

		var data []byte
		data, err = readLimitedDoHBody(r.Body)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		query, err = DecodeJSONQuery(data)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, "Invalid DNS query", http.StatusBadRequest)
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
	defer jrw.response.Release()

	// Encode the captured response as JSON
	jsonData, err := EncodeJSON(jrw.response)
	if err != nil {
		http.Error(w, "failed to encode JSON response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", ContentTypeDNSJSON)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(jsonData); err != nil {
		util.Warnf("doh: failed to write JSON response: %v", err)
	}
}

// jsonResponseWriter captures a DNS response for subsequent JSON encoding.
// It implements server.ResponseWriter.
type jsonResponseWriter struct {
	httpWriter http.ResponseWriter
	httpReq    *http.Request
	response   *protocol.Message
}

// Write snapshots the DNS message as a detached copy for later JSON encoding.
func (rw *jsonResponseWriter) Write(msg *protocol.Message) (int, error) {
	if rw.response != nil {
		return 0, fmt.Errorf("response already written")
	}
	// Single ownership: the DNS pipeline Releases pooled response messages
	// at stage exit (upstreamStage's defer resp.Release()), while the JSON
	// encoding and this handler's own Release run after ServeDNS returns.
	// Field-faithful deep copy — a wire round-trip would mask extended
	// RCODEs (Header.Flags.RCODE & 0x0F) and lose in-memory-only state.
	rw.response = msg.Copy()
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
// SECURITY (MED-009): GET-based DoH can theoretically be used for amplification.
// This endpoint shares the same per-IP rate limiter as UDP queries.
func (h *Handler) handleGET(r *http.Request) ([]byte, error) {
	dnsParam := r.URL.Query().Get("dns")
	if dnsParam == "" {
		return nil, fmt.Errorf("missing 'dns' parameter")
	}

	// SECURITY: Limit base64 input size to prevent memory exhaustion.
	// 65535 bytes DNS message -> ~87384 base64 chars. Reject oversized inputs.
	if len(dnsParam) > MaxBase64DNSSize {
		return nil, fmt.Errorf("dns parameter too large (max %d characters)", MaxBase64DNSSize)
	}

	// Decode base64url (RFC 8484 - no padding)
	data, err := base64.RawURLEncoding.DecodeString(dnsParam)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding")
	}

	return data, nil
}

// handlePOST processes POST requests with DNS query in body.
func (h *Handler) handlePOST(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	// Parse Content-Type with mime.ParseMediaType so parameters
	// (charset, boundary, etc. — permitted by RFC 7231 §3.1.1.1) don't
	// trip a strict-equality check. A previously-rejected
	// `application/dns-message; charset=utf-8` now passes the type
	// check while still locking out actual other media types.
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != ContentTypeDNSMessage {
		return nil, fmt.Errorf("unsupported Content-Type")
	}

	// Limit body size to prevent abuse
	r.Body = http.MaxBytesReader(w, r.Body, MaxDNSMessageSize+1)
	defer r.Body.Close()

	data, err := readLimitedDoHBody(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	return data, nil
}

func readLimitedDoHBody(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxDNSMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxDNSMessageSize {
		return nil, errBodyTooLarge
	}
	return data, nil
}

// dohResponseWriter adapts http.ResponseWriter for DNS responses.
type dohResponseWriter struct {
	w       http.ResponseWriter
	r       *http.Request
	query   *protocol.Message
	written bool
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
		http.Error(rw.w, "Failed to encode response", http.StatusInternalServerError)
		return 0, err
	}

	// RFC 7830 §4: pad the response if and only if the query was padded.
	// The Padding option lives inside the OPT record, so the message is
	// re-packed after the option is added.
	if rw.padding && queryHasPaddingOption(rw.query) {
		if padResponseMessage(msg, n) {
			buf = make([]byte, msg.WireLength())
			n, err = msg.Pack(buf)
			if err != nil {
				http.Error(rw.w, "Failed to encode response", http.StatusInternalServerError)
				return 0, err
			}
		}
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
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0
	}
	return int(p)
}

// EDNS0OptionPadding is the RFC 7830 Padding option code (12).
const EDNS0OptionPadding = 12

// paddingBlockSize is the RFC 8467 §4.1 recommended block size for
// server response padding (468 bytes).
const paddingBlockSize = 468

// queryHasPaddingOption reports whether the client's query carried an
// RFC 7830 Padding option. Per RFC 7830 §4 a server MUST pad a response
// if and only if the corresponding query was padded.
func queryHasPaddingOption(query *protocol.Message) bool {
	if query == nil {
		return false
	}
	for _, rr := range query.Additionals {
		if rr == nil || rr.Type != protocol.TypeOPT {
			continue
		}
		if opt, ok := rr.Data.(*protocol.RDataOPT); ok && opt.GetOption(EDNS0OptionPadding) != nil {
			return true
		}
	}
	return false
}

// padResponseMessage appends a zero-filled RFC 7830 Padding option to the
// response's OPT record, sizing the packed response up to a multiple of
// paddingBlockSize (RFC 8467 §4.1). The previous implementation appended
// random bytes AFTER the packed wire message — trailing garbage that
// breaks RFC 1035 framing rather than valid padding. Returns false when
// the response carries no OPT record to hold the option (nothing padded).
func padResponseMessage(msg *protocol.Message, packedLen int) bool {
	var opt *protocol.RDataOPT
	for _, rr := range msg.Additionals {
		if rr == nil || rr.Type != protocol.TypeOPT {
			continue
		}
		if o, ok := rr.Data.(*protocol.RDataOPT); ok {
			opt = o
			break
		}
	}
	if opt == nil {
		return false
	}
	// The option itself costs 4 header bytes; the zero-filled data brings
	// the total up to the next block boundary.
	withOptionHeader := packedLen + 4
	padLen := (paddingBlockSize - withOptionHeader%paddingBlockSize) % paddingBlockSize
	opt.AddOption(EDNS0OptionPadding, make([]byte, padLen))
	return true
}
