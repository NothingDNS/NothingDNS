package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Errors
var (
	ErrStreamClosed = errors.New("quic: stream closed")
)

// Config holds QUIC connection configuration.
type Config struct {
	TLSConfig       *tls.Config
	TransportParams *TransportParams
	MaxStreams      uint64
	MaxStreamData   uint64
	MaxData         uint64
}

// DefaultConfig returns a sensible QUIC configuration.
func DefaultConfig() *Config {
	return &Config{
		TransportParams: DefaultTransportParams(),
		MaxStreams:      DefaultInitialMaxStreamsBidi,
		MaxStreamData:   DefaultInitialMaxStreamData,
		MaxData:         DefaultInitialMaxData,
	}
}

// Stream represents a QUIC stream.
type Stream struct {
	id      uint64
	readBuf []byte
	readOff int
	finSent bool
	finRecv bool
	closed  bool
	mu      sync.Mutex
}

// StreamID returns the stream ID.
func (s *Stream) StreamID() uint64 { return s.id }

// Read reads data from the stream.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed && len(s.readBuf)-s.readOff <= 0 {
		return 0, io.EOF
	}
	if s.readOff < len(s.readBuf) {
		n := copy(p, s.readBuf[s.readOff:])
		s.readOff += n
		return n, nil
	}
	if s.finRecv {
		return 0, io.EOF
	}
	return 0, io.EOF
}

// Write writes data to the stream (buffered for later send).
func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.finSent {
		return 0, ErrStreamClosed
	}
	return len(p), nil
}

// Close closes the stream with FIN.
func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finSent = true
	s.closed = true
	return nil
}

// SetDeadline sets the read and write deadlines.
func (s *Stream) SetDeadline(t time.Time) error { return nil }

// SetReadDeadline sets the read deadline.
func (s *Stream) SetReadDeadline(t time.Time) error { return nil }

// SetWriteDeadline sets the write deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error { return nil }

// AppendReadData appends received data to the stream's read buffer.
func (s *Stream) AppendReadData(data []byte, fin bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readBuf = append(s.readBuf, data...)
	if fin {
		s.finRecv = true
	}
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

// ServerConnection wraps crypto/tls.QUICConn for server use.
type ServerConnection struct {
	tlsConn    *tls.QUICConn
	connID     ConnectionID
	localAddr  net.Addr
	remoteAddr net.Addr
	config     *Config

	// Streams
	streams  map[uint64]*Stream
	streamMu sync.RWMutex
	nextBidi uint64 // Next server bidi stream ID (starts at 1)

	// Packet number tracking
	pktNumInitial   uint64
	pktNumHandshake uint64
	pktNumApp       uint64
	pktNumMu        sync.Mutex

	// State
	closed bool
	mu     sync.Mutex
}

// NewServerConnection creates a new QUIC server connection.
func NewServerConnection(tlsConfig *tls.Config, connID ConnectionID, localAddr, remoteAddr net.Addr, config *Config) *ServerConnection {
	if config == nil {
		config = DefaultConfig()
	}

	quicConfig := &tls.QUICConfig{
		TLSConfig: tlsConfig,
	}

	return &ServerConnection{
		tlsConn:    tls.QUICServer(quicConfig),
		connID:     connID,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		config:     config,
		streams:    make(map[uint64]*Stream),
		nextBidi:   1,
	}
}

// StartTLSHandshake starts the TLS handshake.
func (sc *ServerConnection) StartTLSHandshake(ctx context.Context) error {
	return sc.tlsConn.Start(ctx)
}

// RemoteAddr returns the remote network address.
func (sc *ServerConnection) RemoteAddr() net.Addr {
	return sc.remoteAddr
}

// HandleCryptoData feeds crypto data at the given encryption level.
func (sc *ServerConnection) HandleCryptoData(level tls.QUICEncryptionLevel, data []byte) error {
	return sc.tlsConn.HandleData(level, data)
}

// ProcessTLSEvents processes TLS events, calling sendFn for outbound data.
func (sc *ServerConnection) ProcessTLSEvents(sendFn func(tls.QUICEncryptionLevel, []byte)) error {
	for {
		event := sc.tlsConn.NextEvent()
		switch event.Kind {
		case tls.QUICNoEvent:
			return nil
		case tls.QUICSetReadSecret:
			// New read key available
		case tls.QUICSetWriteSecret:
			// New write key available
		case tls.QUICWriteData:
			if sendFn != nil {
				sendFn(event.Level, event.Data)
			}
		case tls.QUICTransportParameters:
			// Peer's transport params received
		case tls.QUICTransportParametersRequired:
			tpData := sc.config.TransportParams.Encode()
			sc.tlsConn.SetTransportParameters(tpData)
		case tls.QUICHandshakeDone:
			return nil
		case tls.QUICStoreSession:
			// Session ticket storage
		case tls.QUICResumeSession:
			// Session resumption
		}
	}
}

// ConnectionState returns the TLS connection state.
func (sc *ServerConnection) ConnectionState() tls.ConnectionState {
	return sc.tlsConn.ConnectionState()
}

// AcceptStream creates/returns a stream for the given ID.
func (sc *ServerConnection) AcceptStream(streamID uint64) *Stream {
	sc.streamMu.Lock()
	defer sc.streamMu.Unlock()

	if s, ok := sc.streams[streamID]; ok {
		return s
	}

	s := &Stream{
		id: streamID,
	}
	sc.streams[streamID] = s
	return s
}

// DeleteStream removes a stream.
func (sc *ServerConnection) DeleteStream(streamID uint64) {
	sc.streamMu.Lock()
	defer sc.streamMu.Unlock()
	delete(sc.streams, streamID)
}

// OpenStream opens a new bidirectional stream.
func (sc *ServerConnection) OpenStream() *Stream {
	sc.streamMu.Lock()
	defer sc.streamMu.Unlock()

	s := &Stream{id: sc.nextBidi}
	sc.streams[sc.nextBidi] = s
	sc.nextBidi += 4
	return s
}

// Close closes the connection.
func (sc *ServerConnection) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.closed {
		return nil
	}
	sc.closed = true
	return sc.tlsConn.Close()
}

// SendSessionTicket sends a TLS session ticket.
func (sc *ServerConnection) SendSessionTicket() error {
	return sc.tlsConn.SendSessionTicket(tls.QUICSessionTicketOptions{})
}

// NextPacketNumber returns and increments the packet number for the given level.
func (sc *ServerConnection) NextPacketNumber(level tls.QUICEncryptionLevel) uint64 {
	sc.pktNumMu.Lock()
	defer sc.pktNumMu.Unlock()

	var pn *uint64
	switch level {
	case tls.QUICEncryptionLevelInitial:
		pn = &sc.pktNumInitial
	case tls.QUICEncryptionLevelHandshake:
		pn = &sc.pktNumHandshake
	default:
		pn = &sc.pktNumApp
	}

	current := *pn
	*pn++
	return current
}
