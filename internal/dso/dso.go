// Package dso implements DNS Stateful Operations (DSO) per RFC 8490.
// DSO enables long-lived TCP connections with session management,
// keepalive, and redirect functionality.
package dso

import (
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

// ErrDSOFatal marks a DSO protocol violation that RFC 8490 §5.2 requires
// be handled by forcibly aborting the connection (malformed framing,
// nonzero section counts, an unsolicited response, or a misplaced TLV).
// Recoverable conditions (unknown primary TLV → DSOTYPENI, resource
// exhaustion → error RCODE) return a response with a nil error instead,
// so the transport keeps the session — and any pipelined regular DNS
// queries on it — alive.
var ErrDSOFatal = errors.New("dso: fatal protocol error")

// ErrMaxSessions is returned by CreateSession when the session table is
// full. The transport answers such a request with SERVFAIL and keeps the
// connection open (a resource limit is not a reason to abort an otherwise
// healthy connection carrying regular DNS traffic), rather than treating
// it as fatal.
var ErrMaxSessions = errors.New("dso: maximum sessions reached")

var sessionIDRandReader io.Reader = cryptorand.Reader

// DSO Header constants per RFC 8490
const (
	// Message type flags
	DSOTypeRequest  = 0x0000
	DSOTypeResponse = 0x8000

	// TLV types per RFC 8490 Section 10.3 / IANA DSO Type Codes.
	DSOTLVReserved   = 0x00 // Reserved; never a valid DSO TLV type
	DSOTLVKeepalive  = 0x01 // Keepalive TLV
	DSOTLVRetryDelay = 0x02 // Retry Delay TLV
	DSOTLVPadding    = 0x03 // Encryption Padding TLV

	// NothingDNS-private experimental TLVs. RFC 8490 reserves F800-FBFF for
	// experimental/local use; keep non-standard helpers out of the IANA
	// session-management range so they do not collide with registered TLVs.
	DSOTLVSessionID      = 0xF800 // Experimental Session ID TLV
	DSOTLVEncryption     = 0xF801 // Experimental Encryption Negotiation TLV
	DSOTLVMaximumPayload = 0xF802 // Experimental Maximum Payload Size TLV

	// RFC 8490 Section 4.1.1: Default inactivity timeout is 15 seconds
	DefaultInactivityTimeout = 15 * time.Second

	// RFC 8490 Section 7.1: Keepalive interval MUST NOT be less than 10 seconds.
	MinKeepaliveInterval = 10 * time.Second

	// Default maximum payload size
	DefaultMaxPayloadSize = 65535
)

// DSORCode represents DSO-specific response codes per RFC 8490.
type DSORCode uint16

const (
	// DSO success
	DSOCodeNoError DSORCode = 0

	// DSO-specific errors (RFC 8490 Section 5)
	DSOCodeInvalidDSO     DSORCode = 1 // Malformed DSO message
	DSOCodeUnsolicited    DSORCode = 2 // Unsolicited response
	DSOCodeRetry          DSORCode = 3 // Retry with delay
	DSOCodeEncryptionReq  DSORCode = 4 // Encryption required
	DSOCodeEncryptionNot  DSORCode = 5 // Encryption not available
	DSOCodeSessionExpired DSORCode = 6 // Session expired
	DSOCodeSessionClosed  DSORCode = 7 // Session closed
)

// Session represents a DSO session.
type Session struct {
	ID            uint64
	Conn          net.Conn
	RemoteAddr    net.Addr
	CreatedAt     time.Time
	LastActivity  time.Time
	KeepaliveTime time.Duration
	MaxPayload    uint16

	// Session state
	mu                sync.RWMutex
	closed            bool
	keepalivesEnabled bool

	// Channels for coordination
	stopCh chan struct{}
	doneCh chan struct{}
}

// IsExpired returns true if the session has exceeded its inactivity timeout.
func (s *Session) IsExpired(timeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return sessionExpiredAt(s.LastActivity, time.Now(), timeout)
}

func sessionExpiredAt(lastActivity, now time.Time, timeout time.Duration) bool {
	return !now.Before(lastActivity.Add(timeout))
}

// Close closes the session.
func (s *Session) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()

	close(s.stopCh)
	if s.Conn != nil {
		s.Conn.Close()
	}
	close(s.doneCh)
}

// UpdateActivity updates the last activity timestamp.
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// IsClosed returns true if the session is closed.
func (s *Session) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// TLV represents a DSO Type-Length-Value structure.
type TLV struct {
	Type   uint16
	Length uint16
	Value  []byte
}

// Size returns the total size of the TLV in bytes.
func (t *TLV) Size() int {
	return 4 + len(t.Value) // Type(2) + Length(2) + Value
}

// Pack serializes the TLV to wire format.
func (t *TLV) Pack(buf []byte, offset int) (int, error) {
	if err := t.validateLength(); err != nil {
		return 0, err
	}
	if offset < 0 || offset > len(buf) || t.Size() > len(buf)-offset {
		return 0, fmt.Errorf("buffer too small for TLV")
	}

	binary.BigEndian.PutUint16(buf[offset:], t.Type)
	binary.BigEndian.PutUint16(buf[offset+2:], uint16(len(t.Value)))
	copy(buf[offset+4:], t.Value)

	return t.Size(), nil
}

func (t *TLV) validateLength() error {
	if len(t.Value) > 0xffff {
		return fmt.Errorf("DSO TLV type %d value too large: %d bytes (max 65535)", t.Type, len(t.Value))
	}
	return nil
}

// UnpackTLV deserializes a TLV from wire format.
func UnpackTLV(buf []byte, offset int) (*TLV, int, error) {
	if offset < 0 || offset > len(buf) || len(buf)-offset < 4 {
		return nil, 0, fmt.Errorf("buffer too small for TLV header")
	}

	tlv := &TLV{
		Type:   binary.BigEndian.Uint16(buf[offset:]),
		Length: binary.BigEndian.Uint16(buf[offset+2:]),
	}

	if int(tlv.Length) > len(buf)-offset-4 {
		return nil, 0, fmt.Errorf("buffer too small for TLV value")
	}

	tlv.Value = make([]byte, tlv.Length)
	copy(tlv.Value, buf[offset+4:offset+4+int(tlv.Length)])

	return tlv, 4 + int(tlv.Length), nil
}

// NewKeepaliveTLV creates a Keepalive TLV with primary and secondary timeouts.
func NewKeepaliveTLV(primaryTimeout, secondaryTimeout time.Duration) *TLV {
	// RFC 8490 Section 4.1: Keepalive TLV format
	// Timeout values are unsigned 32-bit milliseconds.
	primary := durationMillis32(primaryTimeout)
	secondary := durationMillis32(secondaryTimeout)

	value := make([]byte, 8)
	binary.BigEndian.PutUint32(value[0:], primary)
	binary.BigEndian.PutUint32(value[4:], secondary)

	return &TLV{
		Type:  DSOTLVKeepalive,
		Value: value,
	}
}

// ParseKeepaliveTLV extracts timeout values from a Keepalive TLV.
func ParseKeepaliveTLV(tlv *TLV) (primary, secondary time.Duration, err error) {
	if tlv.Type != DSOTLVKeepalive {
		return 0, 0, fmt.Errorf("not a keepalive TLV")
	}
	if len(tlv.Value) != 8 {
		return 0, 0, fmt.Errorf("invalid keepalive TLV length: %d", len(tlv.Value))
	}

	primaryUnits := binary.BigEndian.Uint32(tlv.Value[0:])
	secondaryUnits := binary.BigEndian.Uint32(tlv.Value[4:])

	primary = time.Duration(primaryUnits) * time.Millisecond
	secondary = time.Duration(secondaryUnits) * time.Millisecond

	return primary, secondary, nil
}

// NewSessionIDTLV creates a Session ID TLV.
func NewSessionIDTLV(sessionID uint64) *TLV {
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, sessionID)

	return &TLV{
		Type:  DSOTLVSessionID,
		Value: value,
	}
}

// ParseSessionIDTLV extracts the session ID from a Session ID TLV.
func ParseSessionIDTLV(tlv *TLV) (uint64, error) {
	if tlv.Type != DSOTLVSessionID {
		return 0, fmt.Errorf("not a session ID TLV")
	}
	if len(tlv.Value) != 8 {
		return 0, fmt.Errorf("invalid session ID TLV length: %d", len(tlv.Value))
	}

	return binary.BigEndian.Uint64(tlv.Value), nil
}

// NewRetryDelayTLV creates a Retry Delay TLV.
func NewRetryDelayTLV(delay time.Duration) *TLV {
	delayMS := durationMillis32(delay)

	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value, delayMS)

	return &TLV{
		Type:  DSOTLVRetryDelay,
		Value: value,
	}
}

func durationMillis32(d time.Duration) uint32 {
	ms := d.Milliseconds()
	if ms <= 0 {
		return 0
	}
	if ms > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(ms)
}

// NewMaximumPayloadTLV creates a Maximum Payload Size TLV.
func NewMaximumPayloadTLV(maxPayload uint16) *TLV {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, maxPayload)

	return &TLV{
		Type:  DSOTLVMaximumPayload,
		Value: value,
	}
}

// NewPaddingTLV creates a Padding TLV with specified length.
func NewPaddingTLV(length uint16) *TLV {
	return &TLV{
		Type:  DSOTLVPadding,
		Value: make([]byte, length),
	}
}

// Manager manages DSO sessions.
type Manager struct {
	sessions   map[uint64]*Session
	sessionsMu sync.RWMutex

	// Configuration
	inactivityTimeout time.Duration
	keepaliveInterval time.Duration
	maxSessions       int
	allowPlainTCP     bool
	maxPayloadSize    uint16

	// startOnce guards Start() from racy double-fires
	startOnce sync.Once
	// stopOnce guards Stop() from a double close(stopCh) panic
	stopOnce sync.Once

	// Logger
	logger *util.Logger

	// Control
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// Config holds DSO manager configuration.
type Config struct {
	Enabled           bool
	InactivityTimeout time.Duration
	KeepaliveInterval time.Duration
	MaxSessions       int
	MaxPayloadSize    uint16

	// AllowPlainTCP relaxes the RFC 8490 §5.1 requirement that DSO sessions
	// run only over TLS / DoT / DoQ. Default false (TLS required). Only enable
	// for unit tests or trusted-network deployments where the underlying
	// transport is independently secured (e.g. WireGuard tunnels).
	AllowPlainTCP bool
}

// DefaultConfig returns default DSO configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:           false,
		InactivityTimeout: DefaultInactivityTimeout,
		KeepaliveInterval: MinKeepaliveInterval,
		MaxSessions:       1000,
		MaxPayloadSize:    DefaultMaxPayloadSize,
	}
}

// NewManager creates a new DSO session manager.
func NewManager(config Config, logger *util.Logger) *Manager {
	if config.InactivityTimeout == 0 {
		config.InactivityTimeout = DefaultInactivityTimeout
	}
	if config.KeepaliveInterval == 0 {
		config.KeepaliveInterval = config.InactivityTimeout / 3
	}
	if config.KeepaliveInterval < MinKeepaliveInterval {
		config.KeepaliveInterval = MinKeepaliveInterval
	}
	if config.MaxPayloadSize == 0 {
		config.MaxPayloadSize = DefaultMaxPayloadSize
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 1000
	}

	return &Manager{
		sessions:          make(map[uint64]*Session),
		inactivityTimeout: config.InactivityTimeout,
		keepaliveInterval: config.KeepaliveInterval,
		maxSessions:       config.MaxSessions,
		maxPayloadSize:    config.MaxPayloadSize,
		allowPlainTCP:     config.AllowPlainTCP,
		logger:            logger,
		stopCh:            make(chan struct{}),
	}
}

// Start starts the DSO manager's background tasks. Idempotent: subsequent
// calls are no-ops thanks to the startOnce gate (TryLock-based deduplication
// was racy because two callers could each observe a free lock in different
// microseconds and both fire cleanupLoop).
func (m *Manager) Start() {
	m.startOnce.Do(func() {
		m.wg.Add(1)
		go m.cleanupLoop()
		if m.logger != nil {
			m.logger.Info("DSO manager started")
		}
	})
}

// Stop stops the DSO manager.
func (m *Manager) Stop() {
	// Idempotent close. A second Stop call would otherwise panic on
	// the close(m.stopCh) — symmetric with the startOnce guard above.
	closed := false
	m.stopOnce.Do(func() {
		close(m.stopCh)
		closed = true
	})
	if !closed {
		return
	}

	// Close all sessions
	m.sessionsMu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = make(map[uint64]*Session)
	m.sessionsMu.Unlock()

	for _, s := range sessions {
		s.Close()
	}

	m.wg.Wait()

	if m.logger != nil {
		m.logger.Info("DSO manager stopped")
	}
}

// CreateSession creates a new DSO session.
//
// RFC 8490 §5.1 mandates that DSO operate ONLY over an encrypted transport
// (DoT / DoH / DoQ). We enforce that here by requiring conn to be a
// *tls.Conn unless the operator has explicitly opted in to plain TCP via
// Config.AllowPlainTCP (intended for tests / trusted internal networks).
func (m *Manager) CreateSession(conn net.Conn) (*Session, error) {
	if !m.allowPlainTCP {
		if _, ok := conn.(*tls.Conn); !ok {
			return nil, fmt.Errorf("dso: RFC 8490 §5.1 requires TLS; refusing plain TCP connection from %s", conn.RemoteAddr())
		}
	}

	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	select {
	case <-m.stopCh:
		return nil, fmt.Errorf("dso: manager stopped")
	default:
	}

	if len(m.sessions) >= m.maxSessions {
		return nil, fmt.Errorf("%w: %d", ErrMaxSessions, m.maxSessions)
	}

	id, err := m.generateSessionID()
	if err != nil {
		return nil, err
	}
	now := time.Now()

	session := &Session{
		ID:            id,
		Conn:          conn,
		RemoteAddr:    conn.RemoteAddr(),
		CreatedAt:     now,
		LastActivity:  now,
		KeepaliveTime: m.keepaliveInterval,
		MaxPayload:    m.maxPayloadSize,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	m.sessions[id] = session

	if m.logger != nil {
		m.logger.Infof("DSO session %d created from %s", id, conn.RemoteAddr())
	}

	return session, nil
}

// GetSession retrieves a session by ID.
func (m *Manager) GetSession(id uint64) *Session {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	return m.sessions[id]
}

// RemoveSession removes a session.
func (m *Manager) RemoveSession(id uint64) {
	m.sessionsMu.Lock()
	session, ok := m.sessions[id]
	delete(m.sessions, id)
	m.sessionsMu.Unlock()

	if ok {
		session.Close()
		if m.logger != nil {
			m.logger.Infof("DSO session %d removed", id)
		}
	}
}

// SessionCount returns the number of active sessions.
func (m *Manager) SessionCount() int {
	m.sessionsMu.RLock()
	defer m.sessionsMu.RUnlock()
	return len(m.sessions)
}

// generateSessionID returns a fresh, unpredictable 64-bit session ID.
//
// RFC 8490 §6.6.1.2 requires session identifiers to be unpredictable so an
// off-path attacker cannot guess and hijack an active session. The previous
// implementation just incremented a uint64 counter — that gave attackers the
// next session's ID with zero work. We draw from crypto/rand and fail closed
// if the system entropy source is unavailable.
func (m *Manager) generateSessionID() (uint64, error) {
	var b [8]byte
	for i := 0; i < 8; i++ {
		if _, err := io.ReadFull(sessionIDRandReader, b[:]); err != nil {
			return 0, fmt.Errorf("dso: generate unpredictable session ID: %w", err)
		}
		id := binary.BigEndian.Uint64(b[:])
		// Reserve ID 0 as "unassigned" sentinel; redraw rather than return it.
		if id != 0 {
			return id, nil
		}
	}
	return 0, fmt.Errorf("dso: crypto/rand returned reserved zero session ID repeatedly")
}

// cleanupLoop periodically removes expired sessions.
func (m *Manager) cleanupLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.cleanupExpiredSessions()
		}
	}
}

// cleanupExpiredSessions removes expired sessions.
func (m *Manager) cleanupExpiredSessions() {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	for id, session := range m.sessions {
		// Read LastActivity through IsExpired, which takes s.mu.RLock.
		// Reading session.LastActivity directly here raced with
		// UpdateActivity (which writes it under s.mu) on the DSO
		// request path: the two accesses are ordered by different locks
		// (m.sessionsMu vs s.mu), so the pair was a data race and a
		// multi-word time.Time could be read torn. Lock order stays
		// m.sessionsMu -> s.mu, which this loop already used via
		// session.Close() below.
		if session.IsExpired(m.inactivityTimeout) {
			session.Close()
			delete(m.sessions, id)
			if m.logger != nil {
				m.logger.Infof("DSO session %d expired and removed", id)
			}
		}
	}
}

// HandleDSORequest handles a DSO request message.
func (m *Manager) HandleDSORequest(session *Session, msg *protocol.Message) (*protocol.Message, error) {
	// RFC 8490 §5.4: receiving an unsolicited DSO *response* (QR=1) is a
	// fatal protocol error — a server must never treat it as a request or
	// answer it.
	if msg.Header.Flags.QR {
		return nil, fmt.Errorf("%w: unsolicited DSO response (QR=1)", ErrDSOFatal)
	}

	// Update activity
	session.UpdateActivity()

	// Parse TLVs from additional section
	tlvBuf, err := m.extractTLVs(msg)
	if err != nil {
		// Malformed framing / nonzero section counts are fatal per §5.2.
		return nil, fmt.Errorf("%w: extracting TLVs: %w", ErrDSOFatal, err)
	}

	// Process TLVs
	var responseTLVs []*TLV
	isPrimary := true
	for len(tlvBuf) > 0 {
		tlv, consumed, err := UnpackTLV(tlvBuf, 0)
		if err != nil {
			return nil, fmt.Errorf("%w: unpacking TLV: %w", ErrDSOFatal, err)
		}

		switch tlv.Type {
		case DSOTLVKeepalive:
			// Process keepalive request and respond
			_, keepaliveInterval, err := ParseKeepaliveTLV(tlv)
			if err != nil {
				return nil, err
			}
			if keepaliveInterval < MinKeepaliveInterval {
				keepaliveInterval = MinKeepaliveInterval
			}
			// Writes to session.KeepaliveTime / keepalivesEnabled race
			// against SendKeepalive (which reads KeepaliveTime under no
			// lock) and against any reader of keepalivesEnabled. Guard
			// the field update with session.mu so the keepalive ticker
			// and this handler stay coherent.
			session.mu.Lock()
			session.KeepaliveTime = keepaliveInterval
			session.keepalivesEnabled = true
			session.mu.Unlock()
			responseTLVs = append(responseTLVs, NewKeepaliveTLV(m.inactivityTimeout, keepaliveInterval))

		case DSOTLVMaximumPayload:
			// Acknowledge max payload
			if len(tlv.Value) >= 2 {
				maxPayload := binary.BigEndian.Uint16(tlv.Value)
				// MaxPayload is read by every send path; mutation must
				// be serialised. Read-update-read under the write lock,
				// then capture the resulting value for the response TLV
				// after dropping the lock.
				session.mu.Lock()
				if maxPayload > 0 && maxPayload < session.MaxPayload {
					session.MaxPayload = maxPayload
				}
				cur := session.MaxPayload
				session.mu.Unlock()
				responseTLVs = append(responseTLVs, NewMaximumPayloadTLV(cur))
			}

		case DSOTLVPadding:
			// Encryption Padding is only valid as an Additional TLV.
			if isPrimary {
				return nil, fmt.Errorf("%w: padding TLV not allowed as primary", ErrDSOFatal)
			}
			// Ignore padding Additional TLVs in requests.

		case DSOTLVRetryDelay:
			// Not valid in requests
			return nil, fmt.Errorf("%w: retry delay TLV not allowed in requests", ErrDSOFatal)

		default:
			if isPrimary {
				// RFC 8490 §5.1.1: an unrecognized PRIMARY TLV is answered
				// with DSOTYPENI and the session STAYS OPEN — it is not a
				// fatal error. (Aborting the connection here would tear
				// down any pipelined regular DNS queries riding on it.)
				return m.buildDSOErrorResponse(msg, protocol.RcodeDSOTypeNI)
			}
			// Unknown additional TLVs are ignored per RFC 8490 TLV handling.
		}

		isPrimary = false
		tlvBuf = tlvBuf[consumed:]
	}

	// Build response
	response, err := m.buildDSOResponse(msg, responseTLVs)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// buildDSOErrorResponse builds a DSO response (opcode 6, zero section
// counts, empty TLV body) carrying the given RCODE, echoing the request
// ID. Used for recoverable conditions (DSOTYPENI, resource exhaustion)
// where the session must stay open — returned with a nil error so the
// transport writes it rather than aborting the connection.
func (m *Manager) buildDSOErrorResponse(request *protocol.Message, rcode uint8) (*protocol.Message, error) {
	resp := &protocol.Message{Header: request.Header}
	resp.Header.Flags.QR = true
	resp.Header.Flags.RCODE = rcode
	resp.Header.QDCount = 0
	resp.Header.ANCount = 0
	resp.Header.NSCount = 0
	resp.Header.ARCount = 0
	resp.RawBody = nil
	return resp, nil
}

// extractTLVs returns the TLV bytes carried by a DSO message body.
//
// RFC 8490 §5.2 puts the TLV stream directly after the header, not inside
// a Question/Additional section. NothingDNS's UnpackMessage detects
// OPCODE 6 and stashes the body in msg.RawBody; we just hand that back.
//
// A DSO message MUST have all section counts equal to zero (RFC 8490
// §5.2). Reject messages that violate this so a buggy or malicious peer
// can't smuggle records past the DSO handler.
func (m *Manager) extractTLVs(msg *protocol.Message) ([]byte, error) {
	if msg.Header.Flags.Opcode != protocol.OpcodeDSO {
		return nil, fmt.Errorf("dso: not a DSO message (opcode=%d)", msg.Header.Flags.Opcode)
	}
	if msg.Header.QDCount != 0 || msg.Header.ANCount != 0 ||
		msg.Header.NSCount != 0 || msg.Header.ARCount != 0 {
		return nil, fmt.Errorf("dso: RFC 8490 §5.2 requires all section counts to be zero (got Q=%d A=%d NS=%d AR=%d)",
			msg.Header.QDCount, msg.Header.ANCount, msg.Header.NSCount, msg.Header.ARCount)
	}
	return msg.RawBody, nil
}

// buildDSOResponse builds a DSO response message.
func (m *Manager) buildDSOResponse(request *protocol.Message, tlvs []*TLV) (*protocol.Message, error) {
	// Clone the request header
	response := &protocol.Message{
		Header: request.Header,
	}

	// Set response flag (QR = true for response)
	response.Header.Flags.QR = true

	response.Header.QDCount = 0
	response.Header.ANCount = 0
	response.Header.NSCount = 0
	response.Header.ARCount = 0

	body, err := packTLVs(tlvs)
	if err != nil {
		return nil, err
	}
	response.RawBody = body

	return response, nil
}

// SendKeepalive sends an unsolicited DSO keepalive TLV on the session
// per RFC 8490 §6.5. It is a "unidirectional message" (DNS header ID = 0,
// QR = 1, OPCODE = 6) carrying a single Keepalive TLV that advertises the
// inactivity- and keepalive-intervals the server is willing to honour.
//
// Wire layout (RFC 8490 §5.1, §5.2, §6.5.1):
//
//	+----- DNS header (12 bytes) -----+--- TLV stream ---+
//	| ID=0 | QR=1 OPCODE=6 ...        | KEEPALIVE TLV    |
//	|     0 in QD/AN/NS/AR counts      | (Type=1, Len=8) |
//	+---------------------------------+------------------+
//
// The TLV body is two uint32 milliseconds values: inactivity timeout and
// keepalive interval.
func (m *Manager) SendKeepalive(session *Session) error {
	if session.IsClosed() {
		return fmt.Errorf("session closed")
	}
	if session.Conn == nil {
		return fmt.Errorf("dso: session %d has no connection", session.ID)
	}

	// Snapshot KeepaliveTime under the session lock — it can be
	// concurrently updated by HandleDSORequest when the peer renegotiates.
	session.mu.RLock()
	keepaliveTime := session.KeepaliveTime
	session.mu.RUnlock()

	// Build the keepalive TLV (Type=1, two uint32 ms values).
	tlv := NewKeepaliveTLV(m.inactivityTimeout, keepaliveTime)
	tlvBytes := make([]byte, tlv.Size())
	if _, err := tlv.Pack(tlvBytes, 0); err != nil {
		return fmt.Errorf("dso: pack keepalive TLV: %w", err)
	}

	// Build the message: 12-byte DNS header + TLV stream.
	body := tlvBytes
	frame := make([]byte, protocol.HeaderLen+len(body))

	// Header: ID=0 (unidirectional per RFC 8490 §5.4), QR=1, OPCODE=6,
	// all section counts = 0.
	hdr := protocol.Header{
		ID: 0,
		Flags: protocol.Flags{
			QR:     true,
			Opcode: protocol.OpcodeDSO,
		},
	}
	if err := hdr.Pack(frame[:protocol.HeaderLen]); err != nil {
		return fmt.Errorf("dso: pack header: %w", err)
	}
	copy(frame[protocol.HeaderLen:], body)

	// DSO runs over TCP (RFC 8490 §5.1); messages are length-prefixed per
	// RFC 1035 §4.2.2 (2-octet big-endian length).
	out := make([]byte, 2+len(frame))
	out[0] = byte(len(frame) >> 8)
	out[1] = byte(len(frame))
	copy(out[2:], frame)

	// Set a write deadline so a stuck peer can't hang us forever.
	deadline := time.Now().Add(5 * time.Second)
	if err := session.Conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("dso: set keepalive write deadline: %w", err)
	}
	if err := util.WriteFull(session.Conn, out); err != nil {
		return fmt.Errorf("dso: write keepalive: %w", err)
	}
	// Reset write deadline.
	if err := session.Conn.SetWriteDeadline(time.Time{}); err != nil {
		return fmt.Errorf("dso: reset keepalive write deadline: %w", err)
	}

	session.UpdateActivity()
	if m.logger != nil {
		m.logger.Debugf("DSO keepalive sent for session %d", session.ID)
	}
	return nil
}

// IsDSOMessage checks if a message is a DSO message.
func IsDSOMessage(msg *protocol.Message) bool {
	if msg == nil {
		return false
	}
	// DSO messages have OPCODE 6
	return msg.Header.Flags.Opcode == 6
}

// CreateDSOMessage creates a new DSO message with given TLVs.
func CreateDSOMessage(tlvs []*TLV) (*protocol.Message, error) {
	body, err := packTLVs(tlvs)
	if err != nil {
		return nil, err
	}
	if protocol.HeaderLen+len(body) > 0xffff {
		return nil, fmt.Errorf("DSO message too large: %d bytes (max 65535)", protocol.HeaderLen+len(body))
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID: 0,
			Flags: protocol.Flags{
				QR:     false,
				Opcode: 6,
			},
			QDCount: 0,
			ANCount: 0,
			NSCount: 0,
			ARCount: 0,
		},
		RawBody: body,
	}

	return msg, nil
}

func packTLVs(tlvs []*TLV) ([]byte, error) {
	if len(tlvs) == 0 {
		return nil, nil
	}

	size := 0
	for _, tlv := range tlvs {
		if tlv == nil {
			return nil, fmt.Errorf("nil DSO TLV")
		}
		size += tlv.Size()
	}

	body := make([]byte, size)
	offset := 0
	for _, tlv := range tlvs {
		n, err := tlv.Pack(body, offset)
		if err != nil {
			return nil, err
		}
		offset += n
	}
	return body, nil
}

// Handler is an interface for handling DSO messages.
type Handler interface {
	HandleDSO(session *Session, msg *protocol.Message) (*protocol.Message, error)
}
