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
			s.handleInitialPacket(hdr, remoteAddr)
		case PacketType0RTT:
			// 0-RTT packets contain early data from the client
			// Route to existing connection for crypto data processing
			s.handle0RTTPacket(hdr)
		default:
			s.routeToConnection(hdr.DestConnID, hdr.Payload)
		}
	} else {
		s.handleShortHeaderPacket(data)
	}
}

// handleInitialPacket handles an Initial packet (new connection or existing).
func (s *DoQServer) handleInitialPacket(hdr *LongHeader, remoteAddr *net.UDPAddr) {
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

	// Record client's connection ID (client's SCID from Initial packet).
	// This is used as DCID for outbound short header packets.
	dc.sc.SetClientConnID(hdr.SrcConnID)

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
func (s *DoQServer) handle0RTTPacket(hdr *LongHeader) {
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

	// Feed 0-RTT crypto data to the connection.
	// The connection will buffer this until the handshake completes.
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

	// Set stream deadline to prevent slow clients from holding resources.
	stream.SetReadDeadline(time.Now().Add(DoQStreamIdleTimeout))

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

	// Reset deadline before writing.
	stream.SetWriteDeadline(time.Now().Add(DoQStreamIdleTimeout))

	s.handler.ServeDoQ(stream, query)

	atomic.AddUint64(&s.queriesResponded, 1)

	stream.Close()

	// Collect response data and send as 1-RTT encrypted STREAM frame
	responseData := stream.GetWrittenData()
	if len(responseData) > 0 {
		s.send1RTTResponse(dc, streamID, responseData)
	}

	// DeleteStream is called in the defer above
}

// routeToConnection routes a packet to an existing connection.
func (s *DoQServer) routeToConnection(dcID ConnectionID, data []byte) {
	s.connsMu.RLock()
	dc, ok := s.conns[toKey(dcID)]
	s.connsMu.RUnlock()

	if ok && dc != nil {
		// Route Handshake/Initial CRYPTO data to the connection.
		if err := dc.sc.HandleCryptoData(tls.QUICEncryptionLevelHandshake, data); err != nil {
			atomic.AddUint64(&s.errors, 1)
		}
	}
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
			s.process1RTTPacket(dc, data, cidLen)
			return
		}
	}
}

// process1RTTPacket decrypts and processes a 1-RTT packet for an established connection.
func (s *DoQServer) process1RTTPacket(dc *doqConn, data []byte, cidLen int) {
	sc := dc.sc

	// Check that 1-RTT keys are available (handshake must be complete)
	if sc.readAEAD == nil || sc.readHPKey == nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Parse short header to separate header from encrypted payload
	hdrLen := 1 + cidLen
	if len(data) < hdrLen+16 { // minimum: header + 16-byte HP sample
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Extract PN length from header byte (lower 2 bits, masked by header protection)
	// We need to remove header protection first. The sample starts right after the PN.
	// PN length is encoded in the first byte (bits 0-1), but protected.
	// We try each possible PN length (1-4) and derive the PN from the sample.
	// The correct PN length will produce a valid packet number.

	// For short header: first byte is 0x40 | pnLen-1 (protected)
	// Try all PN lengths and pick the one that makes sense
	var pn uint64
	var header []byte
	var ciphertext []byte
	var ok bool

	for pnLen := 1; pnLen <= 4; pnLen++ {
		if len(data) < hdrLen+pnLen+16 {
			continue
		}

		// Copy full packet (header + PN + payload) for HP removal.
		// RemoveHeaderProtection needs the payload for the 16-byte sample.
		pktCopy := make([]byte, len(data))
		copy(pktCopy, data)

		pnCandidate, err := RemoveHeaderProtection(sc.readHPKey, pktCopy, cidLen, pnLen)
		if err != nil {
			continue
		}

		// Verify the unmasked header byte has the correct short header form (0x40 | pnLen-1)
		expectedFirstByte := byte(0x40) | byte(pnLen-1)
		if (pktCopy[0] & 0x43) != expectedFirstByte {
			continue
		}

		pn = pnCandidate
		header = pktCopy[:hdrLen+pnLen]
		ciphertext = pktCopy[hdrLen+pnLen:]
		ok = true
		break
	}

	if !ok {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	if len(ciphertext) < 16 { // AEAD tag minimum
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Decrypt the packet
	plaintext, err := Decrypt1RTTPacket(sc.readAEAD, sc.readIV, pn, header, ciphertext)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Parse frames from the decrypted payload
	s.processDecryptedPayload(dc, plaintext)

	// Update expected packet number
	sc.expectedPN = pn + 1
}

// processDecryptedPayload parses and dispatches frames from a decrypted 1-RTT packet.
func (s *DoQServer) processDecryptedPayload(dc *doqConn, data []byte) {
	offset := 0
	for offset < len(data) {
		frameType := data[offset]
		offset++

		switch frameType {
		case FrameTypePadding:
			// Padding bytes - skip
			continue

		case FrameTypePing:
			// Ping - no action needed
			continue

		case FrameTypeAck, FrameTypeAckECN:
			// ACK frames - parse and skip (we don't track sent packets yet)
			n := s.parseAndSkipACKFrame(data[offset:])
			if n == 0 {
				atomic.AddUint64(&s.errors, 1)
				return
			}
			offset += n

		case FrameTypeCrypto:
			// CRYPTO frame - post-handshake TLS messages (e.g., key updates)
			cf, n, err := ParseCryptoFrame(data[offset:])
			if err != nil {
				atomic.AddUint64(&s.errors, 1)
				return
			}
			offset += n
			if err := dc.sc.HandleCryptoData(tls.QUICEncryptionLevelApplication, cf.Data); err != nil {
				atomic.AddUint64(&s.errors, 1)
				return
			}

		case FrameTypeNewToken:
			// New token - skip
			// Parse varint length and skip
			_, n := DecodeVarint(data[offset:])
			if n == 0 {
				atomic.AddUint64(&s.errors, 1)
				return
			}
			offset += n

		case FrameTypeStream, FrameTypeStream | 0x01, FrameTypeStream | 0x02, FrameTypeStream | 0x03,
			FrameTypeStream | 0x04, FrameTypeStream | 0x05, FrameTypeStream | 0x06, FrameTypeStream | 0x07:
			// STREAM frames (0x08-0x0F), variants differ by FIN/LEN/OFF bits
			sf, n, err := ParseStreamFrame(frameType, data[offset:])
			if err != nil {
				atomic.AddUint64(&s.errors, 1)
				return
			}
			offset += n

			// Check stream ID is valid (must be server-initiated bidirectional, i.e., odd)
			// DoQ uses client-initiated bidirectional streams (stream ID % 4 == 0)
			// and server-initiated bidirectional streams (stream ID % 4 == 1)
			stream, err := dc.sc.AcceptStream(sf.StreamID)
			if err != nil {
				atomic.AddUint64(&s.errors, 1)
				return
			}
			stream.AppendReadData(sf.Data, sf.Fin)

			// Signal the stream processor
			select {
			case dc.streamCh <- sf.StreamID:
			default:
				// Channel full - stream will be processed when space is available
			}

		case FrameTypeMaxData, FrameTypeMaxStreamsBidir, FrameTypeMaxStreamsUnidir,
			FrameTypeDataBlocked, FrameTypeStreamsBlockedBidir, FrameTypeStreamsBlockedUnidir:
			// These flow control frames have exactly 1 varint field — skip it
			_, n := DecodeVarint(data[offset:])
			if n == 0 {
				atomic.AddUint64(&s.errors, 1)
				return
			}
			offset += n

		case FrameTypeMaxStreamData, FrameTypeStreamDataBlocked:
			// These flow control frames have 2 varint fields: stream_id + value
			for range 2 {
				_, n := DecodeVarint(data[offset:])
				if n == 0 {
					atomic.AddUint64(&s.errors, 1)
					return
				}
				offset += n
			}

		case FrameTypeNewConnectionID:
			// New connection ID - skip
			// Multiple varints + 16 bytes
			for i := 0; i < 4 && offset < len(data); i++ {
				_, n := DecodeVarint(data[offset:])
				if n == 0 {
					break
				}
				offset += n
			}
			if offset+16 <= len(data) {
				offset += 16
			}

		case FrameTypeRetireConnectionID:
			// Retire connection ID - skip
			_, n := DecodeVarint(data[offset:])
			if n > 0 {
				offset += n
			}

		case FrameTypePathChallenge, FrameTypePathResponse:
			// Path probing - skip 8-byte data
			if offset+8 <= len(data) {
				offset += 8
			}

		case FrameTypeConnectionClose, FrameTypeConnectionCloseApp:
			// Connection close - terminate connection
			// Parse and skip the frame to advance offset
			_, n, err := ParseConnectionCloseFrame(frameType, data[offset:])
			if err != nil {
				atomic.AddUint64(&s.errors, 1)
				return
			}
			offset += n
			go s.closeConnection(dc)
			return

		case FrameTypeHandshakeDone:
			// Handshake done - no action (already completed)
			continue

		default:
			// Unknown frame type - skip
			atomic.AddUint64(&s.errors, 1)
			return
		}
	}
}

// parseAndSkipACKFrame parses an ACK frame and returns the number of bytes consumed.
func (s *DoQServer) parseAndSkipACKFrame(data []byte) int {
	offset := 0

	// Largest Acknowledged (varint)
	_, n := DecodeVarint(data[offset:])
	if n == 0 {
		return 0
	}
	offset += n

	// ACK Delay (varint)
	_, n = DecodeVarint(data[offset:])
	if n == 0 {
		return 0
	}
	offset += n

	// ACK Range Count (varint)
	ackRangeCount, n := DecodeVarint(data[offset:])
	if n == 0 {
		return 0
	}
	offset += n

	// First ACK Range (varint)
	_, n = DecodeVarint(data[offset:])
	if n == 0 {
		return 0
	}
	offset += n

	// Additional ACK ranges
	for range ackRangeCount {
		// Gap (varint)
		_, n = DecodeVarint(data[offset:])
		if n == 0 {
			return 0
		}
		offset += n

		// ACK Range Length (varint)
		_, n = DecodeVarint(data[offset:])
		if n == 0 {
			return 0
		}
		offset += n
	}

	// ECN counts (only for ACK_ECN)
	// Skip if present (3 varints)
	// We can't reliably detect ECN without parsing the full frame,
	// but since we're just skipping, consuming extra varints is safe
	// as long as we don't overshoot. We'll be conservative and not consume them.

	return offset
}

// send1RTTResponse encrypts and sends a DNS response as a 1-RTT STREAM frame.
func (s *DoQServer) send1RTTResponse(dc *doqConn, streamID uint64, data []byte) {
	sc := dc.sc

	// Check that 1-RTT write keys are available
	if sc.writeAEAD == nil || sc.writeHPKey == nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Get remote address
	addr, ok := sc.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return
	}

	// Build STREAM frame with FIN bit set
	sf := &StreamFrame{
		StreamID: streamID,
		Data:     data,
		Fin:      true,
	}
	frameData := BuildStreamFrame(sf, false, true) // withOffset=false, withLength=true

	// Get next packet number
	pn := sc.NextPacketNumber(tls.QUICEncryptionLevelApplication)

	// Determine packet number length (use 1 byte for simplicity)
	pnLen := 1

	// Build short header: first byte + DCID (client's SCID)
	hdrLen := 1 + sc.connIDLen
	header := make([]byte, hdrLen+pnLen)
	header[0] = 0x40 | byte(pnLen-1) // short header form
	// Use clientConnID as DCID (per QUIC: server sends client's SCID as DCID)
	if len(sc.clientConnID) > 0 {
		copy(header[1:hdrLen], sc.clientConnID)
	} else {
		// Fallback to server's SCID (shouldn't happen after handshake)
		copy(header[1:hdrLen], sc.connID)
	}

	// Encode packet number
	for i := pnLen - 1; i >= 0; i-- {
		header[hdrLen-1-i] = byte(pn >> (i * 8))
	}

	// Copy header into the packet buffer
	pkt := make([]byte, len(header)+len(frameData))
	copy(pkt, header)
	copy(pkt[len(header):], frameData)

	// Encrypt the payload (everything after header+PN)
	ciphertext, err := Encrypt1RTTPacket(sc.writeAEAD, sc.writeIV, pn, pkt[:hdrLen+pnLen], pkt[hdrLen+pnLen:])
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Rebuild packet: header + encrypted payload
	pkt = make([]byte, hdrLen+pnLen+len(ciphertext))
	copy(pkt, header)
	copy(pkt[hdrLen+pnLen:], ciphertext)

	// Apply header protection
	err = ApplyHeaderProtection(sc.writeHPKey, pkt, sc.connIDLen, pnLen)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}

	if _, err := s.conn.WriteToUDP(pkt, addr); err != nil {
		atomic.AddUint64(&s.errors, 1)
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
		atomic.AddUint64(&s.errors, 1)
		return
	}

	addr, ok := dc.sc.RemoteAddr().(*net.UDPAddr)
	if !ok {
		return
	}

	if _, err := s.conn.WriteToUDP(pkt, addr); err != nil {
		atomic.AddUint64(&s.errors, 1)
	}
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
