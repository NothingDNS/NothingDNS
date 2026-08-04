package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TLS Constants.
const (
	// TLSMaxMessageSize is the maximum DNS message size over TLS (same as TCP).
	TLSMaxMessageSize = 65535

	// TLSReadTimeout is the read timeout for TLS connections.
	TLSReadTimeout = 30 * time.Second

	// TLSWriteTimeout is the write timeout for TLS connections.
	TLSWriteTimeout = 30 * time.Second

	// TLSWorkerMultiplier determines workers per CPU core.
	TLSWorkerMultiplier = 2

	// TLSMaxConnections is the maximum number of concurrent TLS connections.
	TLSMaxConnections = 1000
	// TLSMaxConnectionsPerIP caps concurrent DoT connections from a single
	// source IP so one client cannot monopolize the global pool and deny
	// service to every other DoT client (the TCP server enforces the same kind
	// of per-IP limit). Set well above a single stub/forwarder's needs but far
	// below TLSMaxConnections so no single IP can take more than a fraction of
	// total capacity.
	TLSMaxConnectionsPerIP = 100

	// DefaultTLSPort is the default port for DNS over TLS.
	DefaultTLSPort = 853
)

// TLS Profile types per RFC 8310.
type TLSProfile int

const (
	// TLSProfileOpportunistic allows fallback to plaintext.
	TLSProfileOpportunistic TLSProfile = iota
	// TLSProfileStrict requires valid certificate, no fallback.
	TLSProfileStrict
	// TLSProfilePrivacy prefers privacy, similar to strict but with privacy hints.
	TLSProfilePrivacy
)

func (p TLSProfile) String() string {
	switch p {
	case TLSProfileStrict:
		return "strict"
	case TLSProfilePrivacy:
		return "privacy"
	default:
		return "opportunistic"
	}
}

// TLSProfileConfig contains RFC 8310 profile-specific configuration.
type TLSProfileConfig struct {
	// Profile is the TLS usage profile.
	Profile TLSProfile

	// VerifyCertificate if true, verifies the certificate chain.
	VerifyCertificate bool

	// VerifyHostname if true, verifies the hostname matches certificate CN/SAN.
	VerifyHostname bool

	// MinimumTLSVersion is the minimum acceptable TLS version.
	MinimumTLSVersion uint16

	// Pointer to hostname for verification
	Hostname string

	// TrustedCACertPool is the CA cert pool for certificate validation.
	TrustedCACertPool *x509.CertPool

	// InsecureSkipVerify skips certificate verification (for testing only).
	// SECURITY (LOW-001): Setting this in production config disables all cert
	// validation. This field exists for test environments; operators must ensure
	// it is never enabled in production YAML.
	InsecureSkipVerify bool
}

// DefaultTLSProfileConfig returns the default profile configuration.
func DefaultTLSProfileConfig() *TLSProfileConfig {
	return &TLSProfileConfig{
		Profile:           TLSProfileOpportunistic,
		VerifyCertificate: true,
		VerifyHostname:    true,
		MinimumTLSVersion: tls.VersionTLS13,
	}
}

// StrictTLSProfileConfig returns configuration for strict mode per RFC 8310.
func StrictTLSProfileConfig(hostname string, caPool *x509.CertPool) *TLSProfileConfig {
	return &TLSProfileConfig{
		Profile:           TLSProfileStrict,
		VerifyCertificate: true,
		VerifyHostname:    true,
		MinimumTLSVersion: tls.VersionTLS13,
		Hostname:          hostname,
		TrustedCACertPool: caPool,
	}
}

// PrivacyTLSProfileConfig returns configuration for privacy mode per RFC 8310.
func PrivacyTLSProfileConfig(hostname string, caPool *x509.CertPool) *TLSProfileConfig {
	return &TLSProfileConfig{
		Profile:           TLSProfilePrivacy,
		VerifyCertificate: true,
		VerifyHostname:    true,
		MinimumTLSVersion: tls.VersionTLS13,
		Hostname:          hostname,
		TrustedCACertPool: caPool,
	}
}

// BuildTLSConfigForProfile builds a tls.Config from a profile configuration.
func BuildTLSConfigForProfile(profile *TLSProfileConfig, certFile, keyFile string) (*tls.Config, error) {
	if err := ValidateTLSProfile(profile); err != nil {
		return nil, err
	}

	config := &tls.Config{
		MinVersion: profile.MinimumTLSVersion, /* #nosec G402 -- ValidateTLSProfile ensures MinVersion >= 1.2 */
		MaxVersion: tls.VersionTLS13,
		ServerName: profile.Hostname,
		NextProtos: profile.Profile.GetNextProtos(), // Enforce ALPN protocols (RFC 7301)
	}

	// Set cipher suites per RFC 7525
	config.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	config.CipherSuites = []uint16{
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	if profile.TrustedCACertPool != nil {
		config.ClientCAs = profile.TrustedCACertPool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	config.InsecureSkipVerify = profile.InsecureSkipVerify

	return config, nil
}

// ValidateTLSProfile validates a TLS profile configuration.
func ValidateTLSProfile(profile *TLSProfileConfig) error {
	if profile == nil {
		return errors.New("nil TLS profile config")
	}

	if profile.Profile == TLSProfileStrict || profile.Profile == TLSProfilePrivacy {
		if profile.Hostname == "" {
			return errors.New("strict/privacy profile requires hostname")
		}
	}

	if profile.MinimumTLSVersion < tls.VersionTLS12 {
		return errors.New("minimum TLS version must be at least 1.2")
	}

	if profile.InsecureSkipVerify {
		return errors.New("insecure skip verify is not allowed in TLS profiles")
	}

	return nil
}

// GetNextProtos returns the ALPN protocols for the profile.
func (p TLSProfile) GetNextProtos() []string {
	switch p {
	case TLSProfileStrict, TLSProfilePrivacy:
		return []string{"dot"}
	default:
		return []string{"dot", "dns"}
	}
}

// ShouldFallback returns true if the profile allows plaintext fallback.
func (p TLSProfile) ShouldFallback() bool {
	return p == TLSProfileOpportunistic
}

// RequiresTLS returns true if TLS is required for this profile.
func (p TLSProfile) RequiresTLS() bool {
	return p != TLSProfileOpportunistic
}

// TLSServer handles DNS over TLS queries.
type TLSServer struct {
	addr      string
	handler   Handler
	tlsConfig *tls.Config
	listener  net.Listener
	workers   int

	// Context and lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Connection limiting
	connSem     chan struct{}
	ipConnMu    sync.Mutex
	ipConnCount map[string]int

	// dsoHandler, when non-nil, receives DSO (RFC 8490, opcode 6) messages
	// instead of the regular handler. Set before Serve; not safe to change
	// while serving.
	dsoHandler DSOConnHandler

	// Metrics
	connectionsAccepted uint64
	connectionsClosed   uint64
	messagesReceived    uint64
	errors              uint64
}

// NewTLSServer creates a new DNS over TLS server.
func NewTLSServer(addr string, handler Handler, tlsConfig *tls.Config) *TLSServer {
	return NewTLSServerWithWorkers(addr, handler, tlsConfig, 0)
}

// NewTLSServerWithWorkers creates a new DNS over TLS server with a specific worker count.
// If workers is 0, it defaults to runtime.NumCPU() * TLSWorkerMultiplier.
func NewTLSServerWithWorkers(addr string, handler Handler, tlsConfig *tls.Config, workers int) *TLSServer {
	if workers == 0 {
		workers = runtime.NumCPU() * TLSWorkerMultiplier
	}
	if workers < 1 {
		workers = 1
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TLSServer{
		addr:        addr,
		handler:     &ServeDNSWithRecovery{Handler: handler},
		tlsConfig:   tlsConfig,
		workers:     workers,
		ctx:         ctx,
		cancel:      cancel,
		connSem:     make(chan struct{}, TLSMaxConnections),
		ipConnCount: make(map[string]int),
	}
}

// Listen starts listening on the TLS address.
func (s *TLSServer) Listen() error {
	ln, err := tls.Listen("tcp", s.addr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("listen tls: %w", err)
	}

	s.listener = ln
	return nil
}

// ListenWithListener uses an existing listener (for testing).
func (s *TLSServer) ListenWithListener(ln net.Listener) {
	s.listener = ln
}

// Serve starts serving DNS requests.
// This blocks until the server is stopped.
func (s *TLSServer) Serve() error {
	if s.listener == nil {
		return errors.New("server not listening")
	}

	// Start connection handler workers
	connChan := make(chan net.Conn, s.workers*2)

	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(connChan)
	}

	// Accept loop
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				// Shutting down
				close(connChan)
				s.wg.Wait()
				return nil
			}
			atomic.AddUint64(&s.errors, 1)
			continue
		}

		// Check global connection limit
		select {
		case s.connSem <- struct{}{}:
			atomic.AddUint64(&s.connectionsAccepted, 1)
		default:
			// Too many connections, close this one
			conn.Close()
			atomic.AddUint64(&s.errors, 1)
			continue
		}

		// Check per-IP connection limit so a single source cannot monopolize
		// the global pool.
		ip := getIP(conn.RemoteAddr())
		s.ipConnMu.Lock()
		if s.ipConnCount[ip] >= TLSMaxConnectionsPerIP {
			s.ipConnMu.Unlock()
			conn.Close()
			<-s.connSem
			atomic.AddUint64(&s.errors, 1)
			continue
		}
		s.ipConnCount[ip]++
		s.ipConnMu.Unlock()

		// Send to worker, respecting shutdown
		select {
		case connChan <- conn:
		case <-s.ctx.Done():
			s.decrementIPConn(ip)
			conn.Close()
			<-s.connSem
		}
	}
}

// worker handles TLS connections.
func (s *TLSServer) worker(connChan <-chan net.Conn) {
	defer s.wg.Done()

	for conn := range connChan {
		ip := getIP(conn.RemoteAddr())
		s.handleConnection(conn)
		s.decrementIPConn(ip)
		<-s.connSem // Release slot
	}
}

// decrementIPConn releases one per-IP connection slot, deleting the map entry
// at zero so ipConnCount does not grow unbounded over time.
func (s *TLSServer) decrementIPConn(ip string) {
	s.ipConnMu.Lock()
	defer s.ipConnMu.Unlock()
	if s.ipConnCount[ip] <= 1 {
		delete(s.ipConnCount, ip)
		return
	}
	s.ipConnCount[ip]--
}

// handleConnection processes a single TLS connection.
func (s *TLSServer) handleConnection(conn net.Conn) {
	defer func() {
		if s.dsoHandler != nil {
			s.dsoHandler.ConnClosed(conn)
		}
		conn.Close()
		atomic.AddUint64(&s.connectionsClosed, 1)
	}()

	// Cast to TLS connection to get connection state
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		// This shouldn't happen with tls.Listen, but handle it gracefully
		atomic.AddUint64(&s.errors, 1)
		return
	}

	// Perform TLS handshake with timeout
	if err := tlsConn.SetDeadline(time.Now().Add(TLSReadTimeout)); err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}
	_ = tlsConn.SetDeadline(time.Time{}) // best-effort: clear deadline after handshake

	// Handle DNS messages over the TLS connection
	for {
		// Set read timeout
		if err := tlsConn.SetReadDeadline(time.Now().Add(TLSReadTimeout)); err != nil {
			atomic.AddUint64(&s.errors, 1)
			return
		}

		// Read and process message using the same format as TCP
		if !s.handleMessage(tlsConn) {
			return
		}
	}
}

// handleMessage processes a single DNS message over TLS.
// Returns false if the connection should be closed.
func (s *TLSServer) handleMessage(conn *tls.Conn) bool {
	// Read 2-byte length prefix
	var lengthBuf [2]byte
	if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
		if !errors.Is(err, io.EOF) {
			atomic.AddUint64(&s.errors, 1)
		}
		return false
	}

	msgLen := binary.BigEndian.Uint16(lengthBuf[:])

	// Sanity check message length
	if msgLen == 0 || msgLen > TLSMaxMessageSize {
		atomic.AddUint64(&s.errors, 1)
		return false
	}

	// Read message body
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msgBuf); err != nil {
		atomic.AddUint64(&s.errors, 1)
		return false
	}

	atomic.AddUint64(&s.messagesReceived, 1)

	// Process the message using TCP handler logic
	s.processMessage(conn, msgBuf)
	return true
}

// processMessage unpacks and handles a DNS message.
func (s *TLSServer) processMessage(conn *tls.Conn, data []byte) {
	// L-N7: per-message recover. UnpackMessage / EDNS0 parsing run
	// before any ServeDNSWithRecovery wrapper sees the message, so
	// the integratedHandler's recover at cmd/nothingdns/handler.go
	// doesn't cover them. L-2 added this gate to TCP+UDP; DoT was
	// the missed sibling.
	defer func() {
		if r := recover(); r != nil {
			atomic.AddUint64(&s.errors, 1)
		}
	}()

	// Unpack the message
	msg, err := protocol.UnpackMessage(data)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		return
	}
	defer msg.Release()

	// Any message on this connection resets a co-hosted DSO session's
	// inactivity timer (RFC 8490 §7.1.1).
	if s.dsoHandler != nil {
		s.dsoHandler.Touch(conn)
	}

	// DSO (RFC 8490, opcode 6) is per-connection stateful and never enters
	// the regular query pipeline. DoT is the RFC 8490 §5.1 recommended
	// transport for DSO.
	if msg.Header.Flags.Opcode == protocol.OpcodeDSO {
		s.handleDSO(conn, msg)
		return
	}

	// Build client info
	client := &ClientInfo{
		Addr:     conn.RemoteAddr(),
		Protocol: "dot", // DNS over TLS
	}
	populateEDNS0ClientInfo(client, msg)

	// Create response writer
	rw := &tlsResponseWriter{
		conn:    conn,
		client:  client,
		maxSize: TLSMaxMessageSize,
	}

	// Call handler
	s.handler.ServeDNS(rw, msg)
}

// SetDSOHandler installs the DSO (RFC 8490) handler for this server.
// Must be called before Serve.
func (s *TLSServer) SetDSOHandler(h DSOConnHandler) {
	s.dsoHandler = h
}

// handleDSO dispatches a DSO message (opcode 6) to the configured
// DSOConnHandler. Without a handler the server answers NOTIMP; a handler
// error is fatal per RFC 8490 §5.2 and forcibly aborts the connection.
func (s *TLSServer) handleDSO(conn *tls.Conn, msg *protocol.Message) {
	rw := &tlsResponseWriter{
		conn:    conn,
		client:  &ClientInfo{Addr: conn.RemoteAddr(), Protocol: "dot"},
		maxSize: TLSMaxMessageSize,
	}

	if s.dsoHandler == nil {
		if msg.Header.ID != 0 {
			if _, err := rw.Write(dsoErrorResponse(msg, protocol.RcodeNotImplemented)); err != nil {
				atomic.AddUint64(&s.errors, 1)
			}
		}
		return
	}

	resp, err := s.dsoHandler.HandleDSO(conn, msg)
	if err != nil {
		atomic.AddUint64(&s.errors, 1)
		conn.Close()
		return
	}
	// RFC 8490 §5.4: unidirectional messages (ID 0) MUST NOT be answered.
	if resp != nil && msg.Header.ID != 0 {
		if _, err := rw.Write(resp); err != nil {
			atomic.AddUint64(&s.errors, 1)
		}
	}
}

// tlsResponseWriter implements ResponseWriter for TLS.
type tlsResponseWriter struct {
	conn    *tls.Conn
	client  *ClientInfo
	maxSize int
	written bool
}

func (w *tlsResponseWriter) ClientInfo() *ClientInfo {
	return w.client
}

func (w *tlsResponseWriter) MaxSize() int {
	return w.maxSize
}

func (w *tlsResponseWriter) Write(msg *protocol.Message) (int, error) {
	if w.written {
		return 0, errors.New("response already written")
	}
	w.written = true

	// Pack the response. Single pack attempt into a default-size frame;
	// larger responses take the exact-size fallback inside
	// packFramedDNSPayload (no per-response WireLength traversal here).
	buf := make([]byte, defaultFrameBufSize)
	frame, n, err := packFramedDNSPayload(msg, buf, w.maxSize, "TLS")
	if err != nil {
		return 0, err
	}

	// Write length prefix
	binary.BigEndian.PutUint16(frame[0:], uint16(n))

	// Set write timeout
	if err := w.conn.SetWriteDeadline(time.Now().Add(TLSWriteTimeout)); err != nil {
		return 0, fmt.Errorf("set write deadline: %w", err)
	}

	// Write response
	return writeFullDNSFrame(w.conn, frame[:n+2])
}

// Stop gracefully shuts down the server.
func (s *TLSServer) Stop() error {
	s.cancel()

	if s.listener != nil {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return err
		}
	}
	return nil
}

// Addr returns the server's listener address.
func (s *TLSServer) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Stats returns server statistics.
func (s *TLSServer) Stats() TLSServerStats {
	return TLSServerStats{
		ConnectionsAccepted: atomic.LoadUint64(&s.connectionsAccepted),
		ConnectionsClosed:   atomic.LoadUint64(&s.connectionsClosed),
		MessagesReceived:    atomic.LoadUint64(&s.messagesReceived),
		Errors:              atomic.LoadUint64(&s.errors),
		Workers:             s.workers,
	}
}

// TLSServerStats contains runtime statistics for the TLS server.
type TLSServerStats struct {
	ConnectionsAccepted uint64
	ConnectionsClosed   uint64
	MessagesReceived    uint64
	Errors              uint64
	Workers             int
}
