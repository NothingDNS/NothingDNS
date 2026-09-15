package doh

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/websocket"
)

const (
	// wsReadTimeout is the maximum time to wait for a WebSocket message
	// before closing the connection.
	wsReadTimeout = 30 * time.Second

	// wsBinaryMessage is the WebSocket binary frame opcode.
	wsBinaryMessage = 2

	// wsCloseMessage is the WebSocket close frame opcode.
	wsCloseMessage = 8

	// wsRateLimitMessages caps the number of DNS queries one DoWS
	// connection may issue per wsRateLimitWindow. The HTTP-layer rate
	// limiter only throttles new connections, not per-message DNS
	// traffic, and the 30-second read deadline resets on every frame
	// — without a per-connection limit one unauthenticated client can
	// flood the resolver indefinitely (M-7). 100 q/s matches the
	// dashboard's WebSocket limit and is well above any plausible
	// real DNS-over-WebSocket client.
	wsRateLimitMessages = 100
	wsRateLimitWindow   = time.Second
)

// WSHandler handles DNS over WebSocket requests.
type WSHandler struct {
	dnsHandler     server.Handler
	allowedOrigins []string
}

// NewWSHandler creates a new DNS-over-WebSocket handler.
func NewWSHandler(dnsHandler server.Handler, allowedOrigins []string) *WSHandler {
	return &WSHandler{
		dnsHandler:     &server.ServeDNSWithRecovery{Handler: dnsHandler},
		allowedOrigins: allowedOrigins,
	}
}

// ServeHTTP implements http.Handler for DNS-over-WebSocket.
// It upgrades the HTTP connection to a WebSocket and processes DNS queries
// as binary frames in a loop until the client disconnects or a timeout occurs.
func (h *WSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Handshake(w, r, h.allowedOrigins...)
	if err != nil {
		// Handshake already wrote an HTTP error response.
		return
	}
	defer func() {
		if err := closeDoWSConn(conn); err != nil {
			util.Warnf("dows: failed to close WebSocket connection: %v", err)
		}
	}()

	// Per-connection rate limit (M-7). Without this, a single
	// unauthenticated DoWS connection can flood the resolver — the
	// HTTP-layer apiRateLimiter only gates the initial Upgrade.
	conn.SetRateLimit(wsRateLimitMessages, wsRateLimitWindow)

	for {
		// Set a read deadline to prevent hanging connections.
		if err := conn.SetReadDeadline(time.Now().Add(wsReadTimeout)); err != nil {
			util.Warnf("dows: failed to set read deadline: %v", err)
			return
		}

		msgType, data, err := conn.ReadMessage()
		if err != nil {
			// Connection closed or read error; exit silently.
			return
		}

		if msgType == wsCloseMessage {
			return
		}

		if msgType != wsBinaryMessage {
			// DNS-over-WebSocket only accepts binary frames; skip others.
			continue
		}

		query, err := protocol.UnpackMessage(data)
		if err != nil {
			util.Warnf("dows: invalid DNS message: %v", err)
			continue
		}

		if len(query.Questions) == 0 {
			query.Release()
			continue
		}

		defer query.Release() // runs even if ServeDNS panics
		rw := &wsResponseWriter{
			conn:    conn,
			httpReq: r,
			query:   query,
		}
		h.dnsHandler.ServeDNS(rw, query) // guarded by ServeDNSWithRecovery; Release is nil-safe
	}
}

type doWSCloser interface {
	Close() error
}

func closeDoWSConn(conn doWSCloser) error {
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// wsResponseWriter implements server.ResponseWriter for DNS-over-WebSocket.
type wsResponseWriter struct {
	conn    *websocket.Conn
	httpReq *http.Request
	query   *protocol.Message
}

// Write packs the DNS message to wire format and sends it as a binary
// WebSocket frame.
func (rw *wsResponseWriter) Write(msg *protocol.Message) (int, error) {
	msg.Header.ID = rw.query.Header.ID
	msg.Header.Flags.QR = true

	if len(msg.Questions) == 0 && len(rw.query.Questions) > 0 {
		msg.Questions = rw.query.Questions
	}

	buf := make([]byte, msg.WireLength())
	n, err := msg.Pack(buf)
	if err != nil {
		return 0, fmt.Errorf("dows: failed to pack response: %w", err)
	}

	// Set write deadline to prevent blocking indefinitely on slow clients
	if err := rw.conn.SetWriteDeadline(time.Now().Add(wsReadTimeout)); err != nil {
		return 0, fmt.Errorf("dows: failed to set write deadline: %w", err)
	}

	if err := rw.conn.WriteMessage(wsBinaryMessage, buf[:n]); err != nil {
		return 0, fmt.Errorf("dows: failed to write frame: %w", err)
	}

	return n, nil
}

// ClientInfo returns information about the client from the HTTP request.
func (rw *wsResponseWriter) ClientInfo() *server.ClientInfo {
	host, port, err := net.SplitHostPort(rw.httpReq.RemoteAddr)
	if err != nil {
		return &server.ClientInfo{
			Protocol: "wss",
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
		Protocol: "wss",
	}
}

// MaxSize returns the maximum response size for WebSocket DNS.
// WebSocket frames are length-delimited, so no 512-byte UDP constraint applies.
func (rw *wsResponseWriter) MaxSize() int {
	return MaxDNSMessageSize
}
