// NothingDNS - DNS over QUIC (RFC 9250) using quic-go.

package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/nothingdns/nothingdns/internal/util"
)

// DoQ constants (RFC 9250).
const (
	// DefaultDoQPort is the default port for DNS over QUIC.
	DefaultDoQPort = 853

	// DoQMaxMessageSize is the maximum DNS message size over QUIC.
	DoQMaxMessageSize = 65535

	// DoQStreamIdleTimeout is how long a stream can be idle before closing.
	DoQStreamIdleTimeout = 30 * time.Second

	// DoQConnectionIdleTimeout is how long a connection can be idle.
	DoQConnectionIdleTimeout = 60 * time.Second

	// DoQMaxConnections is the maximum concurrent QUIC connections.
	DoQMaxConnections = 500

	// DoQMaxStreamsPerConnection is the maximum concurrent streams per connection.
	DoQMaxStreamsPerConnection = 100

	// DoQMaxConnectionsPerIP is the maximum concurrent QUIC connections per source IP.
	DoQMaxConnectionsPerIP = 10

	// Connection ID limits
	MaxConnIDLen        = 20
	MinInitialConnIDLen = 8
)

// ConnectionID represents a QUIC Connection ID.
type ConnectionID []byte

// String returns a hex representation of the Connection ID.
func (c ConnectionID) String() string {
	return fmt.Sprintf("%x", []byte(c))
}

// Equal returns true if the connection IDs are equal.
func (c ConnectionID) Equal(other ConnectionID) bool {
	if len(c) != len(other) {
		return false
	}
	for i := range c {
		if c[i] != other[i] {
			return false
		}
	}
	return true
}

// GenerateConnectionID generates a random connection ID of the given length.
func GenerateConnectionID(length int) (ConnectionID, error) {
	if length <= 0 || length > MaxConnIDLen {
		return nil, fmt.Errorf("quic: invalid connection ID length %d", length)
	}
	cid := make(ConnectionID, length)
	if _, err := rand.Read(cid); err != nil {
		return nil, err
	}
	return cid, nil
}

// GenerateInitialConnectionID generates a random 8-byte connection ID
// suitable for QUIC Initial packets.
func GenerateInitialConnectionID() (ConnectionID, error) {
	return GenerateConnectionID(MinInitialConnIDLen)
}

// DoQHandler processes DNS queries received over QUIC.
type DoQHandler interface {
	// ServeDoQ handles a DNS query received over QUIC.
	// The handler should write the response to the stream and close it.
	ServeDoQ(stream *Stream, query []byte)
}

// DoQHandlerFunc is an adapter for functions as DoQHandler.
type DoQHandlerFunc func(stream *Stream, query []byte)

// ServeDoQ calls fn(stream, query).
func (fn DoQHandlerFunc) ServeDoQ(stream *Stream, query []byte) {
	fn(stream, query)
}

// Stream wraps a quic-go stream for the DoQ handler interface.
type Stream struct {
	stream     *quic.Stream
	remoteAddr net.Addr
}

// RemoteAddr returns the client's network address (the QUIC connection's
// remote address). Used so DoQ queries carry the real client IP into the
// request pipeline (ACL, rate limiting, RPZ client policy, split-horizon,
// DNS cookies) instead of an empty address.
func (s *Stream) RemoteAddr() net.Addr {
	return s.remoteAddr
}

// Read reads data from the stream.
func (s *Stream) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

// Write writes data to the stream.
func (s *Stream) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

// Close closes the stream (sends FIN).
func (s *Stream) Close() error {
	return s.stream.Close()
}

// CancelRead aborts reading with the given error code.
func (s *Stream) CancelRead(code quic.StreamErrorCode) {
	s.stream.CancelRead(code)
}

// CancelWrite aborts writing with the given error code.
func (s *Stream) CancelWrite(code quic.StreamErrorCode) {
	s.stream.CancelWrite(code)
}

// StreamID returns the stream ID.
func (s *Stream) StreamID() uint64 {
	return uint64(s.stream.StreamID())
}

// SetReadDeadline sets the read deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	return s.stream.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	return s.stream.SetWriteDeadline(t)
}

// SetDeadline sets the read and write deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	return s.stream.SetDeadline(t)
}

// Context returns the stream's context.
func (s *Stream) Context() context.Context {
	return s.stream.Context()
}

// DoQServer is a DNS over QUIC server.
type DoQServer struct {
	addr      string
	handler   DoQHandler
	tlsConfig *tls.Config
	config    *quic.Config

	// UDP listener
	conn *net.UDPConn

	// QUIC listener
	listener *quic.Listener

	// Lifecycle
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	closeMu sync.Mutex

	// Connection limiting
	activeConns   int
	activeConnsMu sync.Mutex

	// Per-IP connection counting
	ipConns   map[string]int
	ipConnsMu sync.Mutex

	// Metrics
	connectionsAccepted uint64
	connectionsClosed   uint64
	queriesReceived     uint64
	queriesResponded    uint64
	errors              uint64
}

// NewDoQServer creates a new DNS over QUIC server.
func NewDoQServer(addr string, handler DoQHandler, tlsConfig *tls.Config) *DoQServer {
	return NewDoQServerWithConfig(addr, handler, tlsConfig, nil)
}

// NewDoQServerWithConfig creates a new DoQ server with a custom QUIC config.
func NewDoQServerWithConfig(addr string, handler DoQHandler, tlsConfig *tls.Config, config *quic.Config) *DoQServer {
	if config == nil {
		config = &quic.Config{
			MaxIncomingStreams:    DoQMaxStreamsPerConnection,
			MaxIncomingUniStreams: 0, // DoQ doesn't use unidirectional streams
			MaxIdleTimeout:        DoQConnectionIdleTimeout,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &DoQServer{
		addr:      addr,
		handler:   handler,
		tlsConfig: tlsConfig,
		config:    config,
		ipConns:   make(map[string]int),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Listen starts listening for QUIC connections.
func (s *DoQServer) Listen() error {
	addr, err := net.ResolveUDPAddr("udp", s.addr)
	if err != nil {
		return fmt.Errorf("doq: resolve addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("doq: listen: %w", err)
	}

	listener, err := quic.Listen(conn, s.tlsConfig, s.config)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			return errors.Join(
				fmt.Errorf("doq: quic listen: %w", err),
				fmt.Errorf("doq: close udp listener after quic listen failure: %w", closeErr),
			)
		}
		return fmt.Errorf("doq: quic listen: %w", err)
	}

	s.conn = conn
	s.listener = listener
	return nil
}

// ListenWithConn uses an existing UDP connection (for testing).
func (s *DoQServer) ListenWithConn(conn *net.UDPConn) {
	s.conn = conn

	var err error
	s.listener, err = quic.Listen(conn, s.tlsConfig, s.config)
	if err != nil {
		// In test mode, the error might be acceptable; store nil listener
		s.listener = nil
	}
}

// Serve starts the DoQ server loop.
func (s *DoQServer) Serve() error {
	// Register the root accept goroutine while holding the same lock Stop uses
	// to close the listener. This keeps WaitGroup.Add ordered before Stop's
	// Wait and prevents the listener from being cleared during the startup
	// check.
	s.closeMu.Lock()
	if s.listener == nil {
		s.closeMu.Unlock()
		return errors.New("doq: server not listening")
	}
	if s.ctx.Err() != nil {
		s.closeMu.Unlock()
		return nil
	}
	s.wg.Add(1)
	s.closeMu.Unlock()

	go s.acceptLoop()

	<-s.ctx.Done()

	if err := s.closeListener(); err != nil {
		return err
	}
	s.wg.Wait()
	return nil
}

// acceptLoop accepts QUIC connections and handles them.
func (s *DoQServer) acceptLoop() {
	defer s.wg.Done()

	for {
		// Acquire closeMu to safely read s.listener, preventing a data race
		// with Stop() -> closeListener() which writes s.listener = nil.
		s.closeMu.Lock()
		listener := s.listener
		s.closeMu.Unlock()

		if listener == nil {
			return
		}

		conn, err := listener.Accept(s.ctx)
		if err != nil {
			// Context cancelled means shutdown
			if s.ctx.Err() != nil {
				return
			}
			atomic.AddUint64(&s.errors, 1)
			continue
		}

		// Check global connection limit
		s.activeConnsMu.Lock()
		if s.activeConns >= DoQMaxConnections {
			s.activeConnsMu.Unlock()
			if err := conn.CloseWithError(0x05, "connection limit reached"); err != nil {
				atomic.AddUint64(&s.errors, 1)
				util.Warnf("doq: failed to close over-limit connection: %v", err)
			}
			continue
		}
		s.activeConns++

		// Check per-IP connection limit
		ip := doqRemoteIP(conn.RemoteAddr())
		s.ipConnsMu.Lock()
		if s.ipConns[ip] >= DoQMaxConnectionsPerIP {
			s.ipConnsMu.Unlock()
			s.activeConns--
			s.activeConnsMu.Unlock()
			if err := conn.CloseWithError(0x05, "per-IP connection limit reached"); err != nil {
				atomic.AddUint64(&s.errors, 1)
				util.Warnf("doq: failed to close per-IP over-limit connection: %v", err)
			}
			continue
		}
		s.ipConns[ip]++
		s.ipConnsMu.Unlock()
		s.activeConnsMu.Unlock()

		atomic.AddUint64(&s.connectionsAccepted, 1)

		s.wg.Add(1)
		go s.handleConnection(conn, ip)
	}
}

func doqRemoteIP(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		if udpAddr.IP != nil {
			return udpAddr.IP.String()
		}
		return udpAddr.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && host != "" {
		return host
	}
	return addr.String()
}

// handleConnection handles a single QUIC connection.
func (s *DoQServer) handleConnection(conn *quic.Conn, ip string) {
	defer s.wg.Done()
	defer func() {
		s.activeConnsMu.Lock()
		s.activeConns--
		s.activeConnsMu.Unlock()
		s.ipConnsMu.Lock()
		if s.ipConns[ip] <= 1 {
			// Delete the key at zero so ipConns does not accumulate a permanent
			// entry for every distinct client IP ever seen (unbounded map growth
			// over long uptime).
			delete(s.ipConns, ip)
		} else {
			s.ipConns[ip]--
		}
		s.ipConnsMu.Unlock()
		atomic.AddUint64(&s.connectionsClosed, 1)
	}()

	ctx := conn.Context()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			// Connection closed or context cancelled
			return
		}

		s.wg.Add(1)
		go s.handleStream(conn, stream)
	}
}

// handleStream processes a single DNS query stream.
func (s *DoQServer) handleStream(conn *quic.Conn, stream *quic.Stream) {
	defer s.wg.Done()
	// DOQ_NO_ERROR (0x0) per RFC 9250 §4.3. Cancels are cleanup for error/
	// panic paths; after a clean response + stream.Close() they would emit
	// gratuitous STOP_SENDING/RESET_STREAM frames.
	streamDone := false
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&s.errors, 1)
		}
		if !streamDone {
			stream.CancelRead(0x00) // STOP_SENDING
			stream.CancelWrite(0x00)
		}
	}()

	wrappedStream := &Stream{stream: stream, remoteAddr: conn.RemoteAddr()}

	// Set stream deadline to prevent slow clients from holding resources.
	if err := stream.SetReadDeadline(time.Now().Add(DoQStreamIdleTimeout)); err != nil {
		atomic.AddUint64(&s.errors, 1)
		util.Warnf("doq: failed to set stream read deadline: %v", err)
		return
	}

	// RFC 9250 §4.2: each DNS message on a QUIC stream is prefixed by a
	// 2-octet length field, identical to DNS-over-TCP framing per RFC 1035
	// §4.2.2. Earlier code claimed the opposite — that produced garbage
	// queries for any RFC-9250-conformant client (kdig, Unbound, Knot,
	// dnscrypt-proxy) because the first two bytes were treated as the DNS
	// header ID.
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		if !errors.Is(err, io.EOF) {
			atomic.AddUint64(&s.errors, 1)
		}
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen == 0 {
		return
	}
	if uint64(msgLen) > DoQMaxMessageSize {
		atomic.AddUint64(&s.errors, 1)
		return
	}
	query := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, query); err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	atomic.AddUint64(&s.queriesReceived, 1)

	// Reset deadline before writing.
	if err := stream.SetWriteDeadline(time.Now().Add(DoQStreamIdleTimeout)); err != nil {
		atomic.AddUint64(&s.errors, 1)
		util.Warnf("doq: failed to set stream write deadline: %v", err)
		return
	}

	s.handler.ServeDoQ(wrappedStream, query)

	atomic.AddUint64(&s.queriesResponded, 1)

	// Close the stream (sends FIN to client).
	if err := stream.Close(); err != nil {
		atomic.AddUint64(&s.errors, 1)
		util.Warnf("doq: failed to close stream: %v", err)
		return
	}
	streamDone = true
}

// Stop gracefully shuts down the DoQ server.
func (s *DoQServer) Stop() error {
	s.cancel()
	var err error
	err = errors.Join(err, s.closeListener())
	err = errors.Join(err, s.closePacketConn())
	s.wg.Wait()
	return err
}

func (s *DoQServer) closeListener() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	s.listener = nil
	if err != nil {
		return fmt.Errorf("doq: close quic listener: %w", err)
	}
	return nil
}

func (s *DoQServer) closePacketConn() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("doq: close udp listener: %w", err)
	}
	return nil
}

// Addr returns the server's listener address.
func (s *DoQServer) Addr() net.Addr {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Stats returns DoQ server statistics.
func (s *DoQServer) Stats() DoQServerStats {
	s.activeConnsMu.Lock()
	active := s.activeConns
	s.activeConnsMu.Unlock()

	return DoQServerStats{
		ConnectionsAccepted: atomic.LoadUint64(&s.connectionsAccepted),
		ConnectionsClosed:   atomic.LoadUint64(&s.connectionsClosed),
		QueriesReceived:     atomic.LoadUint64(&s.queriesReceived),
		QueriesResponded:    atomic.LoadUint64(&s.queriesResponded),
		Errors:              atomic.LoadUint64(&s.errors),
		ActiveConnections:   active,
	}
}

// DoQServerStats contains DoQ server metrics.
type DoQServerStats struct {
	ConnectionsAccepted uint64
	ConnectionsClosed   uint64
	QueriesReceived     uint64
	QueriesResponded    uint64
	Errors              uint64
	ActiveConnections   int
}
