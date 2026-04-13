package quic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
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
)

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

// cidKey is a string-based map key for ConnectionID.
type cidKey string

// toKey converts a ConnectionID to a map key.
func toKey(c ConnectionID) cidKey {
	return cidKey(string(c))
}

// DoQServer is a DNS over QUIC server.
type DoQServer struct {
	addr      string
	handler   DoQHandler
	tlsConfig *tls.Config
	config    *Config

	// UDP listener
	conn *net.UDPConn

	// Active connections keyed by ConnectionID string
	conns   map[cidKey]*doqConn
	connsMu sync.RWMutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Connection limiting
	connSem chan struct{}

	// Per-IP connection limiting (Do not reuse variable names like ipConnCount to avoid shadowing in other files)
	ipConns   map[string]int
	ipConnsMu sync.Mutex

	// Metrics
	connectionsAccepted uint64
	connectionsClosed   uint64
	queriesReceived     uint64
	queriesResponded    uint64
	errors              uint64
}

// doqConn wraps a ServerConnection for DoQ management.
type doqConn struct {
	sc       *ServerConnection
	scID     ConnectionID
	remoteIP string // Source IP for per-IP connection counting
	ctx      context.Context
	cancel   context.CancelFunc
	streamCh chan uint64 // Incoming stream IDs
	wg       sync.WaitGroup
}

// NewDoQServer creates a new DNS over QUIC server.
func NewDoQServer(addr string, handler DoQHandler, tlsConfig *tls.Config) *DoQServer {
	return NewDoQServerWithConfig(addr, handler, tlsConfig, nil)
}

// NewDoQServerWithConfig creates a new DoQ server with a custom QUIC config.
func NewDoQServerWithConfig(addr string, handler DoQHandler, tlsConfig *tls.Config, config *Config) *DoQServer {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &DoQServer{
		addr:      addr,
		handler:   handler,
		tlsConfig: tlsConfig,
		config:    config,
		conns:     make(map[cidKey]*doqConn),
		ipConns:   make(map[string]int),
		ctx:       ctx,
		cancel:    cancel,
		connSem:   make(chan struct{}, DoQMaxConnections),
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

	s.conn = conn
	return nil
}

// ListenWithConn uses an existing UDP connection (for testing).
func (s *DoQServer) ListenWithConn(conn *net.UDPConn) {
	s.conn = conn
}

// Serve starts the DoQ server loop.
func (s *DoQServer) Serve() error {
	if s.conn == nil {
		return errors.New("doq: server not listening")
	}

	s.wg.Add(1)
	go s.readLoop()

	s.wg.Add(1)
	go s.reaperLoop()

	<-s.ctx.Done()

	// Close all connections
	s.connsMu.Lock()
	for _, dc := range s.conns {
		dc.cancel()
		dc.sc.Close()
	}
	s.connsMu.Unlock()

	if s.conn != nil {
		s.conn.Close()
	}

	s.wg.Wait()
	return nil
}

// readLoop reads UDP packets and dispatches them to connections.
func (s *DoQServer) readLoop() {
	defer s.wg.Done()

	buf := make([]byte, MaxUDPPayloadSize)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			atomic.AddUint64(&s.errors, 1)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		s.handlePacket(data, remoteAddr)
	}
}

// handlePacket processes a single UDP packet.
func (s *DoQServer) handlePacket(data []byte, remoteAddr *net.UDPAddr) {
	if len(data) == 0 {
		return
	}

	firstByte := data[0]

	if IsLongHeader(firstByte) {
		hdr, _, err := ParseLongHeader(data)
		if err != nil {
			atomic.AddUint64(&s.errors, 1)
			return
		}

		if hdr.Version != uint32(Version1) {
			return
		}

		switch hdr.Type {
		case PacketTypeInitial:
			s.handleInitialPacket(hdr, data, remoteAddr)
		case PacketType0RTT:
			// 0-RTT packets contain early data from the client
			// Route to existing connection for crypto data processing
			s.handle0RTTPacket(hdr, data, remoteAddr)
		default:
			s.routeToConnection(hdr.DestConnID)
		}
	} else {
		s.handleShortHeaderPacket(data)
	}
}

// handleInitialPacket handles an Initial packet (new connection or existing).
func (s *DoQServer) handleInitialPacket(hdr *LongHeader, data []byte, remoteAddr *net.UDPAddr) {
	key := toKey(hdr.DestConnID)

	s.connsMu.RLock()
	dc, exists := s.conns[key]
	s.connsMu.RUnlock()

	if exists {
		if err := dc.sc.HandleCryptoData(tls.QUICEncryptionLevelInitial, hdr.Payload); err != nil {
			atomic.AddUint64(&s.errors, 1)
		}
		return
	}

	// New connection - check global limit
	select {
	case s.connSem <- struct{}{}:
	default:
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Check per-IP connection limit
	ip := remoteAddr.IP.String()
	s.ipConnsMu.Lock()
	if s.ipConns[ip] >= DoQMaxConnectionsPerIP {
		s.ipConnsMu.Unlock()
		<-s.connSem
		atomic.AddUint64(&s.errors, 1)
		return
	}
	s.ipConns[ip]++
	s.ipConnsMu.Unlock()

	// Generate server connection ID
	scid, err := GenerateInitialConnectionID()
	if err != nil {
		s.ipConnsMu.Lock()
		s.ipConns[ip]--
		s.ipConnsMu.Unlock()
		<-s.connSem
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Create new connection
	dc, err = s.newDoQConnection(scid, remoteAddr, ip)
	if err != nil {
		s.ipConnsMu.Lock()
		s.ipConns[ip]--
		s.ipConnsMu.Unlock()
		<-s.connSem
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Feed initial crypto data
	if err := dc.sc.HandleCryptoData(tls.QUICEncryptionLevelInitial, hdr.Payload); err != nil {
		dc.cancel()
		dc.sc.Close()
		s.removeConn(dc)
		<-s.connSem
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Start handshake
	s.wg.Add(1)
	go s.handshakeConnection(dc)
}

// handle0RTTPacket handles a 0-RTT packet (early data from client).
// 0-RTT packets can arrive before the handshake completes and contain
// early data that should be buffered for processing after handshake.
func (s *DoQServer) handle0RTTPacket(hdr *LongHeader, data []byte, remoteAddr *net.UDPAddr) {
	key := toKey(hdr.DestConnID)

	s.connsMu.RLock()
	dc, exists := s.conns[key]
	s.connsMu.RUnlock()

	if !exists {
		// No existing connection for 0-RTT data - discard
		// 0-RTT requires an existing connection (must have done handshake first)
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Feed 0-RTT crypto data to the connection
	// The connection will buffer this until the handshake completes
	if err := dc.sc.HandleCryptoData(tls.QUICEncryptionLevelEarly, hdr.Payload); err != nil {
		atomic.AddUint64(&s.errors, 1)
	}
}

// newDoQConnection creates a new DoQ connection.
func (s *DoQServer) newDoQConnection(scid ConnectionID, remoteAddr net.Addr, remoteIP string) (*doqConn, error) {
	ctx, cancel := context.WithCancel(s.ctx)

	sc := NewServerConnection(s.tlsConfig, scid, s.conn.LocalAddr(), remoteAddr, s.config)

	dc := &doqConn{
		sc:       sc,
		scID:     scid,
		remoteIP: remoteIP,
		ctx:      ctx,
		cancel:   cancel,
		streamCh: make(chan uint64, 64),
	}

	s.connsMu.Lock()
	s.conns[toKey(scid)] = dc
	s.connsMu.Unlock()

	atomic.AddUint64(&s.connectionsAccepted, 1)

	return dc, nil
}

// handshakeConnection runs the TLS handshake for a new connection.
func (s *DoQServer) handshakeConnection(dc *doqConn) {
	defer s.wg.Done()

	if err := dc.sc.StartTLSHandshake(dc.ctx); err != nil {
		s.closeConnection(dc)
		return
	}

	err := dc.sc.ProcessTLSEvents(func(level tls.QUICEncryptionLevel, data []byte) {
		s.sendCryptoPacket(dc, level, data)
	})

	if err != nil {
		s.closeConnection(dc)
		return
	}

	s.wg.Add(1)
	go s.processStreams(dc)
}

// processStreams handles incoming streams for a connection.
func (s *DoQServer) processStreams(dc *doqConn) {
	defer dc.wg.Done()

	for {
		select {
		case <-dc.ctx.Done():
			return
		case streamID := <-dc.streamCh:
			dc.wg.Add(1)
			go s.handleStream(dc, streamID)
		}
	}
}

// handleStream processes a single DNS query stream.
func (s *DoQServer) handleStream(dc *doqConn, streamID uint64) {
	defer dc.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&s.errors, 1)
		}
		// Always clean up the stream, even on panic
		dc.sc.DeleteStream(streamID)
	}()

	stream, err := dc.sc.AcceptStream(streamID)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Set stream deadline to prevent slow clients from holding resources
	_ = stream.SetReadDeadline(time.Now().Add(DoQStreamIdleTimeout))

	// Limit read to prevent unbounded memory allocation
	query, err := io.ReadAll(io.LimitReader(stream, DoQMaxMessageSize))
	if err != nil && !errors.Is(err, io.EOF) {
		atomic.AddUint64(&s.errors, 1)
		return // DeleteStream is called in the defer above
	}

	if len(query) == 0 {
		return // DeleteStream is called in the defer above
	}

	atomic.AddUint64(&s.queriesReceived, 1)

	// Reset deadline before writing
	_ = stream.SetWriteDeadline(time.Now().Add(DoQStreamIdleTimeout))

	s.handler.ServeDoQ(stream, query)

	atomic.AddUint64(&s.queriesResponded, 1)

	stream.Close()
	// DeleteStream is called in the defer above
}

// routeToConnection routes a packet to an existing connection.
func (s *DoQServer) routeToConnection(dcID ConnectionID) {
	// Placeholder for future packet routing implementation.
	_, _ = s, dcID
}

// handleShortHeaderPacket handles a short header (1-RTT) packet.
func (s *DoQServer) handleShortHeaderPacket(data []byte) {
	for cidLen := 4; cidLen <= MaxConnIDLen; cidLen++ {
		if len(data) < 1+cidLen {
			continue
		}
		dcID := ConnectionID(data[1 : 1+cidLen])

		s.connsMu.RLock()
		dc, ok := s.conns[toKey(dcID)]
		s.connsMu.RUnlock()

		if ok {
			// TODO: Route short header packet to connection for decryption
			// and stream processing. This requires implementing the
			// QUIC 1-RTT packet decryption and stream reassembly.
			_ = dc
			return
		}
	}
}

// sendCryptoPacket sends a CRYPTO/Handshake packet to the client.
func (s *DoQServer) sendCryptoPacket(dc *doqConn, level tls.QUICEncryptionLevel, data []byte) {
	if s.conn == nil || dc.ctx.Err() != nil {
		return
	}

	var pktType uint8
	switch level {
	case tls.QUICEncryptionLevelInitial:
		pktType = PacketTypeInitial
	case tls.QUICEncryptionLevelHandshake:
		pktType = PacketTypeHandshake
	default:
		return
	}

	hdr := &LongHeader{
		Type:       pktType,
		Version:    uint32(Version1),
		DestConnID: dc.scID,
		SrcConnID:  dc.scID,
		Payload:    data,
	}

	pkt, err := BuildLongHeader(hdr, 0, 1)
	if err != nil {
		return
	}

	addr, ok := dc.sc.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return
	}

	s.conn.WriteToUDP(pkt, addr)
}

// closeConnection closes and removes a DoQ connection.
func (s *DoQServer) closeConnection(dc *doqConn) {
	dc.cancel()
	dc.sc.Close()

	// Wait with timeout to prevent goroutine leaks blocking shutdown.
	// Stream handlers that are mid-I/O will still leak until the I/O
	// completes or the underlying conn closes — but we no longer block forever.
	done := make(chan struct{}, 1)
	go func() {
		dc.wg.Wait()
		done <- struct{}{}
	}()
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-done:
		timer.Stop()
	case <-timer.C:
		// Log but continue — streams may be stuck on I/O; conn is already closed
	}

	s.removeConn(dc)
	<-s.connSem

	// Decrement per-IP connection counter
	if dc.remoteIP != "" {
		s.ipConnsMu.Lock()
		s.ipConns[dc.remoteIP]--
		s.ipConnsMu.Unlock()
	}

	atomic.AddUint64(&s.connectionsClosed, 1)
}

func (s *DoQServer) removeConn(dc *doqConn) {
	s.connsMu.Lock()
	delete(s.conns, toKey(dc.scID))
	s.connsMu.Unlock()
}

// reaperLoop periodically checks for idle connections.
func (s *DoQServer) reaperLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(DoQConnectionIdleTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.reapIdleConnections()
		}
	}
}

// reapIdleConnections closes idle connections.
func (s *DoQServer) reapIdleConnections() {
	s.connsMu.RLock()
	var dead []*doqConn
	for _, dc := range s.conns {
		if dc.ctx.Err() != nil {
			dead = append(dead, dc)
		}
	}
	s.connsMu.RUnlock()

	for _, dc := range dead {
		s.closeConnection(dc)
	}
}

// Stop gracefully shuts down the DoQ server.
func (s *DoQServer) Stop() error {
	s.cancel()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// Addr returns the server's listener address.
func (s *DoQServer) Addr() net.Addr {
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Stats returns DoQ server statistics.
func (s *DoQServer) Stats() DoQServerStats {
	s.connsMu.RLock()
	active := len(s.conns)
	s.connsMu.RUnlock()

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
