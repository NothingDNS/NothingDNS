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
	wsReadTimeout = 5 * time.Minute

	// wsBinaryMessage is the WebSocket binary frame opcode.
	wsBinaryMessage = 2

	// wsCloseMessage is the WebSocket close frame opcode.
	wsCloseMessage = 8
)

// WSHandler handles DNS over WebSocket requests.
type WSHandler struct {
	dnsHandler server.Handler
}

// NewWSHandler creates a new DNS-over-WebSocket handler.
func NewWSHandler(dnsHandler server.Handler) *WSHandler {
	return &WSHandler{
		dnsHandler: &server.ServeDNSWithRecovery{Handler: dnsHandler},
	}
}

// ServeHTTP implements http.Handler for DNS-over-WebSocket.
// It upgrades the HTTP connection to a WebSocket and processes DNS queries
// as binary frames in a loop until the client disconnects or a timeout occurs.
func (h *WSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Handshake(w, r)
	if err != nil {
		// Handshake already wrote an HTTP error response.
		return
	}
	defer conn.Close()

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
			continue
		}

		rw := &wsResponseWriter{
			conn:    conn,
			httpReq: r,
			query:   query,
		}
		h.dnsHandler.ServeDNS(rw, query)
	}
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
