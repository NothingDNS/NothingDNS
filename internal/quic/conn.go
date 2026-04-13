package quic

import (
	"context"
	"crypto/cipher"
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
	ErrStreamLimit  = errors.New("quic: stream limit reached")
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
	id       uint64
	readBuf  []byte
	readOff  int
	writeBuf []byte
	writeOff int
	finSent  bool
	finRecv  bool
	closed   bool
	mu       sync.Mutex

	// Deadline support
	readDeadline  time.Time
	writeDeadline time.Time
}

// StreamID returns the stream ID.
func (s *Stream) StreamID() uint64 { return s.id }

// Read reads data from the stream.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check read deadline
	if !s.readDeadline.IsZero() && time.Now().After(s.readDeadline) {
		return 0, errors.New("i/o timeout")
	}

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

	// Check write deadline
	if !s.writeDeadline.IsZero() && time.Now().After(s.writeDeadline) {
		return 0, errors.New("i/o timeout")
	}

	if s.closed || s.finSent {
		return 0, ErrStreamClosed
	}
	s.writeBuf = append(s.writeBuf, p...)
	return len(p), nil
}

// GetWrittenData returns all written data and resets the write buffer.
// This is used by the QUIC stack to collect data to send.
func (s *Stream) GetWrittenData() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.writeBuf
	s.writeBuf = nil
	s.writeOff = 0
	return data
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
func (s *Stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	s.writeDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return nil
}

// SetWriteDeadline sets the write deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = t
	return nil
}

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
	connID     ConnectionID // Server's SCID (used as map key)
	clientConnID ConnectionID // Client's SCID (used as DCID for outbound short header)
	localAddr  net.Addr
	remoteAddr net.Addr
	config     *Config

	// Streams
	streams    map[uint64]*Stream
	streamMu   sync.RWMutex
	nextBidi   uint64 // Next server bidi stream ID (starts at 1)
	maxStreams uint64 // Maximum concurrent streams (0 = unlimited)

	// Packet number tracking
	pktNumInitial   uint64
	pktNumHandshake uint64
	pktNumApp       uint64
	pktNumMu        sync.Mutex

	// 1-RTT key material (populated from TLS events)
	readAEAD  cipher.AEAD // AEAD cipher for decrypting inbound 1-RTT packets
	readIV    []byte      // 12-byte IV for decryption nonce
	readHPKey []byte      // header protection key
	expectedPN uint64    // expected inbound packet number
	writeAEAD cipher.AEAD // AEAD cipher for encrypting outbound 1-RTT packets
	writeIV   []byte      // 12-byte IV for encryption nonce
	writeHPKey []byte     // header protection key
	connIDLen int         // connection ID length (for short header parsing)

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
		connIDLen:  len(connID),
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		config:     config,
		streams:    make(map[uint64]*Stream),
		nextBidi:   1,
		maxStreams: config.MaxStreams,
	}
}

// StartTLSHandshake starts the TLS handshake.
func (sc *ServerConnection) StartTLSHandshake(ctx context.Context) error {
	return sc.tlsConn.Start(ctx)
}

// SetClientConnID sets the client's connection ID (SCID from Initial packet).
// This is used as the DCID for outbound short header packets.
func (sc *ServerConnection) SetClientConnID(cid ConnectionID) {
	sc.clientConnID = cid
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
			// Capture 1-RTT read secret for packet decryption
			if event.Level == tls.QUICEncryptionLevelApplication {
				aead, iv, err := DeriveAEADKeyAndIV(event.Suite, event.Data)
				if err != nil {
					return fmt.Errorf("quic: derive read AEAD key: %w", err)
				}
				hpKey, err := DeriveHeaderProtectionKey(event.Suite, event.Data)
				if err != nil {
					return fmt.Errorf("quic: derive read HP key: %w", err)
				}
				sc.readAEAD = aead
				sc.readIV = iv
				sc.readHPKey = hpKey
				sc.expectedPN = 0
			}
		case tls.QUICSetWriteSecret:
			// Capture 1-RTT write secret for packet encryption
			if event.Level == tls.QUICEncryptionLevelApplication {
				aead, iv, err := DeriveAEADKeyAndIV(event.Suite, event.Data)
				if err != nil {
					return fmt.Errorf("quic: derive write AEAD key: %w", err)
				}
				hpKey, err := DeriveHeaderProtectionKey(event.Suite, event.Data)
				if err != nil {
					return fmt.Errorf("quic: derive write HP key: %w", err)
				}
				sc.writeAEAD = aead
				sc.writeIV = iv
				sc.writeHPKey = hpKey
			}
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
func (sc *ServerConnection) AcceptStream(streamID uint64) (*Stream, error) {
	sc.streamMu.Lock()
	defer sc.streamMu.Unlock()

	if s, ok := sc.streams[streamID]; ok {
		return s, nil
	}

	// Check stream limit
	if sc.maxStreams > 0 && uint64(len(sc.streams)) >= sc.maxStreams {
		return nil, ErrStreamLimit
	}

	s := &Stream{
		id: streamID,
	}
	sc.streams[streamID] = s
	return s, nil
}

// DeleteStream removes a stream.
func (sc *ServerConnection) DeleteStream(streamID uint64) {
	sc.streamMu.Lock()
	defer sc.streamMu.Unlock()
	delete(sc.streams, streamID)
}

// OpenStream opens a new bidirectional stream.
func (sc *ServerConnection) OpenStream() (*Stream, error) {
	sc.streamMu.Lock()
	defer sc.streamMu.Unlock()

	// Check stream limit
	if sc.maxStreams > 0 && uint64(len(sc.streams)) >= sc.maxStreams {
		return nil, ErrStreamLimit
	}

	s := &Stream{id: sc.nextBidi}
	sc.streams[sc.nextBidi] = s
	sc.nextBidi += 4
	return s, nil
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
