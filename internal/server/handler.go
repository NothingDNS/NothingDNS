package server

import (
	"fmt"
	"net"
	"strings"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ClientInfo contains information about the client making the DNS request.
type ClientInfo struct {
	// Addr is the client's network address
	Addr net.Addr

	// Protocol is the transport protocol ("udp" or "tcp")
	Protocol string

	// EDNS0UDPSize is the client's advertised UDP payload size (from OPT record)
	EDNS0UDPSize uint16

	// HasEDNS0 indicates if the client sent an EDNS0 OPT record
	HasEDNS0 bool

	// ClientSubnet is the client's subnet from EDNS0 Client Subnet (ECS) option
	// This is nil if no ECS option was present
	ClientSubnet *protocol.EDNS0ClientSubnet
}

func populateEDNS0ClientInfo(client *ClientInfo, msg *protocol.Message) {
	if client == nil || msg == nil {
		return
	}

	for _, rr := range msg.Additionals {
		if rr == nil || rr.Type != protocol.TypeOPT {
			continue
		}

		client.HasEDNS0 = true
		client.EDNS0UDPSize = rr.Class

		optData, ok := rr.Data.(*protocol.RDataOPT)
		if !ok || optData == nil {
			break
		}
		for _, opt := range optData.Options {
			if opt.Code == protocol.OptionCodeClientSubnet {
				if ecs, err := protocol.UnpackEDNS0ClientSubnet(opt.Data); err == nil {
					client.ClientSubnet = ecs
				}
				break
			}
		}
		break
	}
}

// String returns the client's address as a string.
func (c *ClientInfo) String() string {
	if c == nil || c.Addr == nil {
		return "<nil>"
	}
	return c.Addr.String()
}

// IP returns the client's IP address.
func (c *ClientInfo) IP() net.IP {
	if c == nil || c.Addr == nil {
		return nil
	}

	switch addr := c.Addr.(type) {
	case *net.UDPAddr:
		return addr.IP
	case *net.TCPAddr:
		return addr.IP
	default:
		// Try to parse from string
		host, _, err := net.SplitHostPort(c.Addr.String())
		if err != nil {
			host = c.Addr.String()
		}
		return parseZonedIP(host)
	}
}

// parseZonedIP parses an IP literal, ignoring an IPv6 "%zone" suffix
// ("fe80::1%eth0"). net.ParseIP rejects zoned literals; returning nil for a
// link-local peer would make every client-IP-keyed stage (ACL, recursion
// policy, RPZ client-IP, rate limiting) see "no client" (F428).
func parseZonedIP(host string) net.IP {
	if i := strings.LastIndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	return net.ParseIP(host)
}

// ResponseWriter is used by handlers to write a DNS response.
type ResponseWriter interface {
	// Write writes a response message to the client.
	// Returns the number of bytes written and any error.
	Write(msg *protocol.Message) (int, error)

	// ClientInfo returns information about the client.
	ClientInfo() *ClientInfo

	// MaxSize returns the maximum response size for this client.
	// This accounts for UDP payload size limits and TCP.
	MaxSize() int
}

// Handler is the interface for DNS request handlers.
type Handler interface {
	// ServeDNS handles a single DNS request.
	// Implementations should write a response to the ResponseWriter.
	ServeDNS(w ResponseWriter, req *protocol.Message)
}

// DSOConnHandler handles DNS Stateful Operations messages (RFC 8490,
// opcode 6) for connection-oriented transports. DSO is per-connection
// state: implementations own the session bound to each conn.
//
// HandleDSO processes one DSO message received on conn and returns the
// response to write (nil for no response). An error is a fatal session
// error per RFC 8490 §5.2 — the caller MUST forcibly abort the connection.
// ConnClosed MUST be called exactly once when the transport connection
// terminates so the session state can be torn down.
type DSOConnHandler interface {
	HandleDSO(conn net.Conn, msg *protocol.Message) (*protocol.Message, error)
	ConnClosed(conn net.Conn)
	// Touch resets the DSO inactivity timer for conn. The transport calls
	// it on every message (DSO or regular DNS) so that traffic on a
	// connection that also hosts a DSO session keeps that session alive
	// (RFC 8490 §7.1.1). A no-op if conn has no session.
	Touch(conn net.Conn)
}

// dsoErrorResponse builds a minimal DSO response (opcode 6, zero section
// counts) carrying the given RCODE, echoing the request ID.
func dsoErrorResponse(req *protocol.Message, rcode uint8) *protocol.Message {
	resp := &protocol.Message{}
	resp.Header.ID = req.Header.ID
	resp.Header.Flags.QR = true
	resp.Header.Flags.Opcode = protocol.OpcodeDSO
	resp.Header.Flags.RCODE = rcode
	return resp
}

// HandlerFunc is an adapter to allow use of functions as handlers.
type HandlerFunc func(w ResponseWriter, req *protocol.Message)

// ServeDNSWithRecovery wraps a Handler to recover from panics and return
// a SERVFAIL response instead of crashing the server.
type ServeDNSWithRecovery struct {
	Handler Handler
}

// ServeDNS calls h.ServeDNS, recovering from any panic and sending
// a SERVFAIL response to prevent server crash.
func (h *ServeDNSWithRecovery) ServeDNS(w ResponseWriter, req *protocol.Message) {
	defer func() {
		if r := recover(); r != nil {
			util.Warnf("ServeDNS panic recovered: %v", r)
			sendSERVFAIL(w, req)
		}
	}()
	h.Handler.ServeDNS(w, req)
}

// sendSERVFAIL sends a minimal SERVFAIL response.
func sendSERVFAIL(w ResponseWriter, req *protocol.Message) {
	if w == nil || req == nil || len(req.Questions) == 0 {
		return
	}
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    req.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeServerFailure),
		},
		Questions: req.Questions,
	}
	if _, err := w.Write(resp); err != nil {
		util.Warnf("failed to write SERVFAIL response: %v", err)
	}
}

// ServeDNS calls f(w, req).
func (f HandlerFunc) ServeDNS(w ResponseWriter, req *protocol.Message) {
	f(w, req)
}

// NewResponseWriter creates a ResponseWriter from a connection and client info.
// This is the base implementation; specific transports may wrap it.
func NewResponseWriter(client *ClientInfo, maxSize int) ResponseWriter {
	return &baseResponseWriter{
		client:  client,
		maxSize: maxSize,
	}
}

// baseResponseWriter is a basic ResponseWriter implementation.
type baseResponseWriter struct {
	client  *ClientInfo
	maxSize int
}

func (w *baseResponseWriter) ClientInfo() *ClientInfo {
	return w.client
}

func (w *baseResponseWriter) MaxSize() int {
	return w.maxSize
}

func (w *baseResponseWriter) Write(msg *protocol.Message) (int, error) {
	return 0, fmt.Errorf("baseResponseWriter.Write not implemented for this transport")
}

// ResponseSizeLimit calculates the maximum response size for a client.
// For UDP, it considers EDNS0 buffer size and falls back to 512 bytes.
// For TCP, there's no practical limit (but we cap at 64KB).
func ResponseSizeLimit(client *ClientInfo) int {
	if client == nil {
		return 512
	}

	if client.Protocol == "tcp" {
		return 65535
	}

	// UDP: check EDNS0 buffer size
	if client.HasEDNS0 && client.EDNS0UDPSize > 512 {
		// Cap at reasonable maximum to avoid fragmentation issues
		if client.EDNS0UDPSize > 4096 {
			return 4096
		}
		return int(client.EDNS0UDPSize)
	}

	// RFC 1035 default
	return 512
}
