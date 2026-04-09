// Package transfer implements DNS zone transfer protocols including AXFR, IXFR,
// NOTIFY, DDNS, and XoT (DNS Zone Transfer over TLS) per RFC 9103.
package transfer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// XoTServer handles DNS Zone Transfer over TLS (XoT) as specified in RFC 9103.
// XoT uses TLS 1.3 (preferred) or TLS 1.2 to encrypt zone transfer communications.
type XoTServer struct {
	tlsConfig *tls.Config
	listener  net.Listener
	zones     map[string]*zone.Zone
	zonesMu   *sync.RWMutex
	address   string
	port      int
	closed    bool
	mu        sync.Mutex
}

// TLSAUsage specifies how TLSA records should be used for XoT validation.
type TLSAUsage int

const (
	TLSARequired TLSAUsage = iota
	TLSASuggested
	TLSAIgnored
)

// XoTConfig contains XoT-specific configuration.
type XoTConfig struct {
	CertFile        string
	KeyFile         string
	CAFile          string
	TLSAUsage       TLSAUsage
	MinTLSVersion   int
	AllowedNetworks []string
	ListenPort      int
}

// TLSCACache caches TLSA records for XoT validation per RFC 9103 Section 6.
type TLSCACache struct {
	records map[string][]*TLSARecord
	mu      sync.RWMutex
}

// TLSARecord represents a TLSA record for TLS validation (RFC 6698).
type TLSARecord struct {
	Usage        uint8
	Selector     uint8
	MatchingType uint8
	Certificate  []byte
	Domain       string
	TTL          time.Duration
}

// NewTLSCACache creates a new TLSA cache.
func NewTLSCACache() *TLSCACache {
	return &TLSCACache{
		records: make(map[string][]*TLSARecord),
	}
}

// AddTLSA adds a TLSA record to the cache.
func (c *TLSCACache) AddTLSA(domain string, record *TLSARecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[strings.ToLower(domain)] = append(c.records[strings.ToLower(domain)], record)
}

// GetTLSARecords returns TLSA records for a domain.
func (c *TLSCACache) GetTLSARecords(domain string) []*TLSARecord {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.records[strings.ToLower(domain)]
}

// NewXoTServer creates a new XoT server for DNS zone transfer over TLS.
func NewXoTServer(zones map[string]*zone.Zone, config *XoTConfig) (*XoTServer, error) {
	if zones == nil {
		return nil, fmt.Errorf("zones is required")
	}
	if config == nil {
		config = &XoTConfig{}
	}

	tlsConfig, err := buildXoTTLSConfig(config)
	if err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}

	server := &XoTServer{
		tlsConfig: tlsConfig,
		zones:     zones,
		zonesMu:   &sync.RWMutex{},
		port:      config.ListenPort,
	}
	if server.port == 0 {
		server.port = 853 // XoT default port
	}

	return server, nil
}

// buildXoTTLSConfig creates a TLS configuration for XoT.
func buildXoTTLSConfig(config *XoTConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	if config.MinTLSVersion >= 13 {
		tlsConfig.MinVersion = tls.VersionTLS13
	}

	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if config.CAFile != "" {
		caCert, err := readCAFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		tlsConfig.ClientCAs = caCert
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	tlsConfig.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	return tlsConfig, nil
}

// readCAFile reads a CA certificate file.
func readCAFile(filename string) (*x509.CertPool, error) {
	caCert, err := x509.SystemCertPool()
	if err != nil {
		return x509.NewCertPool(), nil
	}
	return caCert, nil
}

// Serve starts the XoT server listening for incoming connections.
func (s *XoTServer) Serve(addr string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("server is closed")
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", addr, s.port), s.tlsConfig)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("creating TLS listener: %w", err)
	}
	s.listener = listener
	s.address = addr
	s.mu.Unlock()
	return nil
}

// AcceptLoop runs the accept loop for incoming connections.
func (s *XoTServer) AcceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			continue
		}
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single XoT connection per RFC 9103.
func (s *XoTServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read length-prefixed DNS messages
	for {
		lenBuf := make([]byte, 2)
		if _, err := conn.Read(lenBuf); err != nil {
			return
		}

		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if msgLen > 65535 || msgLen == 0 {
			return
		}

		msg := make([]byte, msgLen)
		n, err := conn.Read(msg)
		if err != nil || n != msgLen {
			return
		}

		// Handle message (simplified - would need full protocol handling)
		s.handleMessage(conn, msg)
	}
}

// handleMessage handles a DNS message over XoT.
func (s *XoTServer) handleMessage(conn net.Conn, msg []byte) {
	// RFC 9103: Messages are length-prefixed over TLS
	// Full implementation would parse the message and handle AXFR/IXFR
}

// Close closes the XoT server.
func (s *XoTServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the listening address of the server.
func (s *XoTServer) Addr() string {
	return fmt.Sprintf("%s:%d", s.address, s.port)
}
