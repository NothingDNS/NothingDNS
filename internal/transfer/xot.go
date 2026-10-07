// Package transfer implements DNS zone transfer protocols including AXFR, IXFR,
// NOTIFY, DDNS, and XoT (DNS Zone Transfer over TLS) per RFC 9103.
package transfer

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// XoTServer handles DNS Zone Transfer over TLS (XoT) as specified in RFC 9103.
// XoT requires TLS 1.3 (RFC 9103 §5.1) and offers the "dot" ALPN token.
type XoTServer struct {
	tlsConfig *tls.Config
	// tls holds the reloadable certificate and client-CA pool behind
	// tlsConfig (ReloadTLS).
	tls       *xotTLS
	listener  net.Listener
	zones     map[string]*zone.Zone
	zonesMu   *sync.RWMutex
	address   string
	port      int
	closed    bool
	mu        sync.Mutex
	allowList []net.IPNet
	// requireClientCert is true when mTLS is enforced (CAFile configured). In
	// that case the TLS handshake has already verified the client certificate,
	// so transfers are authenticated independently of allowList.
	requireClientCert bool
	logger            *util.Logger
	journalStore      JournalStore // For IXFR incremental transfers

	stopCh chan struct{}  // closed to signal AcceptLoop stop
	wg     sync.WaitGroup // waits for AcceptLoop and active connections
	// conns holds the live accepted connections (guarded by mu) so Close can
	// tear them down instead of waiting for idle clients (F226).
	conns map[net.Conn]struct{}
}

// TLSAUsage specifies how TLSA records should be used for XoT validation.
type TLSAUsage int

const (
	TLSARequired TLSAUsage = iota
	TLSASuggested
	TLSAIgnored
)

const maxXoTCAFileSize = 1 << 20

// XoTConfig contains XoT-specific configuration. MinTLSVersion is kept for
// compatibility only: XoT always requires TLS 1.3 (RFC 9103 §5.1), so values
// below 13 have no effect.
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
func NewXoTServer(zones map[string]*zone.Zone, config *XoTConfig, logger *util.Logger) (*XoTServer, error) {
	if zones == nil {
		return nil, fmt.Errorf("zones is required")
	}
	if config == nil {
		config = &XoTConfig{}
	}

	xt, err := newXoTTLS(config)
	if err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}
	tlsConfig := xt.listener

	server := &XoTServer{
		tlsConfig: tlsConfig,
		tls:       xt,
		zones:     zones,
		zonesMu:   &sync.RWMutex{},
		port:      config.ListenPort,
		logger:    logger,
		stopCh:    make(chan struct{}),
	}
	if server.port == 0 {
		server.port = 853 // XoT default port
	}

	// Parse allowed networks from config
	for _, cidr := range config.AllowedNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			if logger != nil {
				logger.Warnf("XoT: invalid CIDR in allowed_networks: %s: %v", cidr, err)
			}
			continue
		}
		server.allowList = append(server.allowList, *network)
	}

	// mTLS (CAFile) is the strongest gate: buildXoTTLSConfig sets
	// RequireAndVerifyClientCert when CAFile is configured.
	server.requireClientCert = tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert

	// Deny-by-default: without mTLS and without an IP allowlist, every zone is
	// exposed to any client that completes a server-auth-only TLS handshake.
	// Refuse to start in that configuration so a full zone disclosure cannot be
	// introduced by an empty/forgotten allowlist (matches AXFRServer's posture).
	if !server.requireClientCert && len(server.allowList) == 0 {
		return nil, fmt.Errorf("XoT requires access control: configure server.xot.ca_file (mTLS) or server.xot.allowed_networks")
	}

	return server, nil
}

// SetZonesMu makes the server lock the zones map with mu, the lock its owner
// (the query handler) holds while mutating that shared map. Without it the
// server's private lock does not exclude the owner's writes (F414). A nil mu
// is ignored.
func (s *XoTServer) SetZonesMu(mu *sync.RWMutex) {
	if mu == nil {
		return
	}
	s.mu.Lock()
	s.zonesMu = mu
	s.mu.Unlock()
}

// zonesLock returns the lock guarding the zones map.
func (s *XoTServer) zonesLock() *sync.RWMutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.zonesMu
}

// SetJournalStore sets the persistent journal store for IXFR incremental transfers.
func (s *XoTServer) SetJournalStore(store JournalStore) {
	s.journalStore = store
}

// xotALPN is the ALPN token XoT shares with DNS over TLS (RFC 9103 §7.1).
const xotALPN = "dot"

// xotTLS is the reloadable TLS state of an XoT listener: the server
// certificate (served through GetCertificate for every handshake) and, with
// mTLS, the client-CA pool. The pool is published as a complete per-handshake
// tls.Config through GetConfigForClient so a reload swaps it atomically.
type xotTLS struct {
	listener *tls.Config
	certs    *server.CertReloader // nil when no certificate is configured
	caFile   string
	// client is the config handed to each handshake when caFile is set: the
	// listener settings plus the current ClientCAs. crypto/tls re-checks a
	// resumed session's verified chains against these ClientCAs, so a CA
	// removed by a reload is refused on resumption too.
	client atomic.Pointer[tls.Config]
}

// buildXoTTLSConfig creates a TLS configuration for XoT. RFC 9103 §5.1
// requires TLS 1.3 for XoT, so TLS 1.3 is the floor whatever
// MinTLSVersion says (a lower setting cannot weaken it), and the "dot" ALPN
// token is offered (F415).
func buildXoTTLSConfig(config *XoTConfig) (*tls.Config, error) {
	xt, err := newXoTTLS(config)
	if err != nil {
		return nil, err
	}
	return xt.listener, nil
}

func newXoTTLS(config *XoTConfig) (*xotTLS, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{xotALPN},
	}
	xt := &xotTLS{listener: tlsConfig}

	if config.CertFile != "" && config.KeyFile != "" {
		certs, err := server.NewCertReloader(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		xt.certs = certs
		// Certificates stays empty so GetCertificate serves every
		// handshake, with or without SNI (F609).
		tlsConfig.GetCertificate = certs.GetCertificate
	}

	tlsConfig.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}

	if config.CAFile != "" {
		caCert, err := readCAFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		xt.caFile = config.CAFile
		tlsConfig.ClientCAs = caCert
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		xt.publishClientCAs(caCert)
		tlsConfig.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return xt.client.Load(), nil
		}
	}

	return xt, nil
}

// publishClientCAs installs pool as the client-CA pool for new handshakes.
func (x *xotTLS) publishClientCAs(pool *x509.CertPool) {
	c := x.listener.Clone()
	c.GetConfigForClient = nil
	c.ClientCAs = pool
	c.ClientAuth = tls.RequireAndVerifyClientCert
	x.client.Store(c)
}

// reload re-reads the certificate/key and the CA file. A part that fails to
// load keeps its previous value; the errors are returned joined.
func (x *xotTLS) reload() error {
	var errs []error
	if x.certs != nil {
		if err := x.certs.Reload(); err != nil {
			errs = append(errs, err)
		}
	}
	if x.caFile != "" {
		if pool, err := readCAFile(x.caFile); err != nil {
			errs = append(errs, err)
		} else {
			x.publishClientCAs(pool)
		}
	}
	return errors.Join(errs...)
}

// ReloadTLS re-reads the XoT certificate, key and (with mTLS) CA file
// (F609). New handshakes use the reloaded files; established connections
// are unaffected. When a file fails to load, the previous certificate or CA
// pool stays in use and the error is returned.
func (s *XoTServer) ReloadTLS() error {
	if s == nil || s.tls == nil {
		return nil
	}
	return s.tls.reload()
}

// readCAFile reads a PEM CA bundle from filename into a fresh cert pool. This
// pool is the trust anchor for verifying XoT client certificates (mTLS), so it
// MUST contain the operator's configured CA — NOT the system roots. The previous
// implementation ignored filename and returned x509.SystemCertPool(), so client
// certs were validated against public roots and the private-CA allowlist was
// silently bypassed. Fails closed if the file is unreadable or has no certs.
func readCAFile(filename string) (*x509.CertPool, error) {
	pem, err := readXoTCAFile(filename)
	if err != nil {
		return nil, fmt.Errorf("xot: read CA file %q: %w", filename, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("xot: CA file %q contains no valid PEM certificates", filename)
	}
	return pool, nil
}

func readXoTCAFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxXoTCAFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxXoTCAFileSize {
		return nil, fmt.Errorf("XoT CA file exceeds %d bytes", maxXoTCAFileSize)
	}
	return data, nil
}

// Serve starts the XoT server listening for incoming connections.
func (s *XoTServer) Serve(addr string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("server is closed")
	}

	// addr is either a bare host (the port comes from XoTConfig.ListenPort) or
	// a full listen address such as server.xot.bind's ":853" (F224).
	listenAddr := addr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		listenAddr = net.JoinHostPort(addr, strconv.Itoa(s.port))
	}
	listener, err := tls.Listen("tcp", listenAddr, s.tlsConfig)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("creating TLS listener: %w", err)
	}
	s.listener = listener
	s.address = addr
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		s.address = tcpAddr.IP.String()
		s.port = tcpAddr.Port
	}
	s.mu.Unlock()
	return nil
}

// AcceptLoop runs the accept loop for incoming connections.
func (s *XoTServer) AcceptLoop() {
	s.mu.Lock()
	if s.closed || s.listener == nil {
		s.mu.Unlock()
		return
	}
	listener := s.listener
	stopCh := s.stopCh
	s.wg.Add(1)
	s.mu.Unlock()

	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			if s.logger != nil {
				s.logger.Errorf("XoT AcceptLoop panic recovered: %v", r)
			} else {
				fmt.Printf("XoT AcceptLoop panic recovered: %v\n", r)
			}
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
				continue
			}
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			s.closeConn(conn, "accepted connection after shutdown")
			return
		}
		if s.conns == nil {
			s.conns = make(map[net.Conn]struct{})
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.handleConnection(conn)
		}()
	}
}

// handleConnection handles a single XoT connection per RFC 9103.
func (s *XoTServer) handleConnection(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			// Log panic but don't crash the server
			if s.logger != nil {
				s.logger.Errorf("XoT handleConnection panic recovered: %v", r)
			} else {
				fmt.Printf("XoT handleConnection panic recovered: %v\n", r)
			}
		}
		s.closeConn(conn, "connection")
	}()

	// Read length-prefixed DNS messages
	for {
		// Set read deadline to prevent slow-loris attacks
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return
		}

		// Use io.ReadFull for both length prefix and body. conn.Read
		// may legally return short reads on TLS streams — a TLS
		// record can deliver partial DNS messages. The previous
		// conn.Read(lenBuf) could read only 1 of the 2 length-prefix
		// bytes, leaving lenBuf[1] zero, and conn.Read(msg) could
		// return fewer bytes than msgLen, both silently dropping or
		// truncating the message and (worse) leaving the stream's
		// read offset partway through a DNS message — every
		// subsequent message on the same connection then parses
		// from a wrong offset.
		lenBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}

		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if msgLen > 65535 || msgLen == 0 {
			return
		}

		msg := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}

		// Handle message
		s.handleMessage(conn, msg)
	}
}

// handleMessage handles a DNS message over XoT per RFC 9103.
// XoT uses TLS to encrypt zone transfer communications, with DNS messages
// length-prefixed as in normal TCP DNS.
func (s *XoTServer) handleMessage(conn net.Conn, msg []byte) {
	// RFC 9103: Messages are length-prefixed over TLS (same as TCP)
	// Parse the DNS message
	protocolMsg, err := protocol.UnpackMessage(msg)
	if err != nil {
		// Send FORMERR response
		if err := s.sendErrorResponse(conn, nil, protocol.RcodeFormatError); err != nil {
			return
		}
		return
	}
	defer protocolMsg.Release()

	// Get client IP for access control. Tests and wrapped connections may not
	// expose a *net.TCPAddr even though production XoT uses TCP/TLS.
	clientIP := xotClientIP(conn)

	// Determine message type and handle accordingly
	if len(protocolMsg.Questions) > 0 {
		q := protocolMsg.Questions[0]

		switch q.QType {
		case protocol.TypeAXFR:
			s.handleAXFRRequest(conn, protocolMsg, clientIP)
			return
		case protocol.TypeIXFR:
			s.handleIXFRRequest(conn, protocolMsg, clientIP)
			return
		}
	}

	// Unsupported request type - send NOTIMP
	if err := s.sendErrorResponse(conn, protocolMsg, protocol.RcodeNotImplemented); err != nil {
		return
	}
}

// handleAXFRRequest processes an AXFR request over XoT.
func (s *XoTServer) handleAXFRRequest(conn net.Conn, req *protocol.Message, clientIP net.IP) {
	// Check if client is allowed by IP
	if !s.isAllowed(clientIP) {
		if err := s.sendErrorResponse(conn, req, protocol.RcodeRefused); err != nil {
			return
		}
		return
	}

	// Get zone name from question
	if req == nil || len(req.Questions) != 1 || req.Questions[0].Name == nil {
		if err := s.sendErrorResponse(conn, req, protocol.RcodeFormatError); err != nil {
			return
		}
		return
	}

	zoneName := req.Questions[0].Name.String()

	// Get the zone
	zonesMu := s.zonesLock()
	zonesMu.RLock()
	z, ok := s.zones[strings.ToLower(zoneName)]
	zonesMu.RUnlock()
	if !ok {
		if err := s.sendErrorResponse(conn, req, protocol.RcodeNameError); err != nil {
			return
		}
		return
	}

	// Generate AXFR records using the same logic as AXFRServer
	records, err := s.generateAXFRRecords(z)
	if err != nil {
		if err := s.sendErrorResponse(conn, req, protocol.RcodeServerFailure); err != nil {
			return
		}
		return
	}

	// Send AXFR response: SOA + all records + SOA (multiple messages allowed)
	// RFC 5936: AXFR response is a sequence of messages, each with SOA at start/end of whole transfer
	if err := s.sendAXFRResponse(conn, records, req.Header.ID); err != nil {
		return
	}
}

// handleIXFRRequest processes an IXFR request over XoT.
func (s *XoTServer) handleIXFRRequest(conn net.Conn, req *protocol.Message, clientIP net.IP) {
	// Check if client is allowed by IP
	if !s.isAllowed(clientIP) {
		if err := s.sendErrorResponse(conn, req, protocol.RcodeRefused); err != nil {
			return
		}
		return
	}

	// Get zone name from question
	if req == nil || len(req.Questions) != 1 || req.Questions[0].Name == nil {
		if err := s.sendErrorResponse(conn, req, protocol.RcodeFormatError); err != nil {
			return
		}
		return
	}

	zoneName := req.Questions[0].Name.String()

	// Get zone
	zonesMu := s.zonesLock()
	zonesMu.RLock()
	z, ok := s.zones[strings.ToLower(zoneName)]
	zonesMu.RUnlock()
	if !ok {
		if err := s.sendErrorResponse(conn, req, protocol.RcodeNameError); err != nil {
			return
		}
		return
	}

	// For IXFR, we need to check if the client has a serial number
	// RFC 1995: IXFR uses SOA to determine if incremental transfer is possible
	clientSOASerial := extractIXFRClientSerial(req)

	// Generate IXFR response
	records, err := s.generateIXFRRecords(z, clientSOASerial)
	if err != nil {
		if err := s.sendErrorResponse(conn, req, protocol.RcodeServerFailure); err != nil {
			return
		}
		return
	}

	if err := s.sendAXFRResponse(conn, records, req.Header.ID); err != nil {
		return
	}
}

func extractIXFRClientSerial(req *protocol.Message) uint32 {
	if req == nil {
		return 0
	}
	for _, rr := range req.Authorities {
		if rr == nil {
			continue
		}
		if rr.Type == protocol.TypeSOA {
			if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
				return soa.Serial
			}
		}
	}
	for _, rr := range req.Additionals {
		if rr == nil {
			continue
		}
		if rr.Type == protocol.TypeSOA {
			if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
				return soa.Serial
			}
		}
	}
	return 0
}

func xotClientIP(conn net.Conn) net.IP {
	if conn == nil || conn.RemoteAddr() == nil {
		return nil
	}
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && tcpAddr != nil {
		return tcpAddr.IP
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// isAllowed checks if a client IP is allowed for XoT. Deny-by-default: access is
// granted only when mTLS authenticated the client (requireClientCert) or the
// client IP matches a configured allowed network. NewXoTServer guarantees at
// least one of those controls is present, so an empty allowList denies all.
func (s *XoTServer) isAllowed(clientIP net.IP) bool {
	if s.requireClientCert {
		return true // client certificate already verified during TLS handshake
	}
	for _, network := range s.allowList {
		if network.Contains(clientIP) {
			return true
		}
	}
	return false
}

// generateAXFRRecords generates AXFR response records for a zone. The framing
// SOA and the record walk come from one zone state: the zone read lock is held
// across both, so a concurrent update cannot pair the old serial with the new
// data (F222, mirrors AXFRServer.generateAXFRRecords / F219).
func (s *XoTServer) generateAXFRRecords(z *zone.Zone) ([]*protocol.ResourceRecord, error) {
	if z == nil {
		return nil, fmt.Errorf("zone is nil")
	}
	z.RLock()
	defer z.RUnlock()
	return s.generateAXFRRecordsLocked(z)
}

// generateAXFRRecordsLocked is generateAXFRRecords for a caller that already
// holds z's read lock (zone RWMutex read locks must not be taken recursively).
func (s *XoTServer) generateAXFRRecordsLocked(z *zone.Zone) ([]*protocol.ResourceRecord, error) {
	if z.SOA == nil {
		return nil, fmt.Errorf("zone has no SOA record")
	}

	origin, err := protocol.ParseName(z.Origin)
	if err != nil {
		return nil, fmt.Errorf("parsing zone origin: %w", err)
	}

	mname, err := protocol.ParseName(z.SOA.MName)
	if err != nil {
		return nil, fmt.Errorf("parsing SOA mname: %w", err)
	}

	rname, err := protocol.ParseName(z.SOA.RName)
	if err != nil {
		return nil, fmt.Errorf("parsing SOA rname: %w", err)
	}

	// Create SOA record
	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   z.SOA.TTL,
		Data: &protocol.RDataSOA{
			MName:   mname,
			RName:   rname,
			Serial:  z.SOA.Serial,
			Refresh: z.SOA.Refresh,
			Retry:   z.SOA.Retry,
			Expire:  z.SOA.Expire,
			Minimum: z.SOA.Minimum,
		},
	}

	// Collect all zone records. The apex SOA is emitted separately as the
	// first and last record of the transfer (RFC 5936 §2.2), so it must be
	// skipped here — the parser stores the apex SOA in both z.SOA and
	// z.Records[apex], and re-emitting it mid-stream makes RFC-compliant
	// secondaries treat the second SOA as end-of-transfer and discard every
	// record after it, truncating the zone (mirrors
	// AXFRServer.generateAXFRRecords).
	var zoneRecords []*protocol.ResourceRecord
	for name, recs := range z.Records {
		for _, rec := range recs {
			if protocol.RecordTypeFromText(rec.Type) == protocol.TypeSOA {
				continue
			}
			rr, err := s.zoneRecordToRR(name, rec)
			if err != nil {
				continue
			}
			zoneRecords = append(zoneRecords, rr)
		}
	}

	// Sort records canonically (RFC 4034 Section 6.1)
	s.sortRecordsCanonically(zoneRecords)

	// Build response: SOA + records + SOA
	var records []*protocol.ResourceRecord
	records = append(records, soaRR)
	records = append(records, zoneRecords...)
	records = append(records, soaRR)

	return records, nil
}

// generateIXFRRecords generates IXFR response records.
// If the client serial is current or newer, returns SOA only. Otherwise returns incremental changes
// from the journal store, or falls back to full AXFR if no journal is available.
func (s *XoTServer) generateIXFRRecords(z *zone.Zone, clientSerial uint32) ([]*protocol.ResourceRecord, error) {
	if z == nil {
		return nil, fmt.Errorf("zone is nil")
	}
	// One zone state for the serial decision, the SOAs and any AXFR fallback (F222).
	z.RLock()
	defer z.RUnlock()
	if z.SOA == nil {
		return nil, fmt.Errorf("zone has no SOA record")
	}

	origin, err := protocol.ParseName(z.Origin)
	if err != nil {
		return nil, fmt.Errorf("parsing zone origin: %w", err)
	}

	mname, err := protocol.ParseName(z.SOA.MName)
	if err != nil {
		return nil, fmt.Errorf("parsing SOA mname: %w", err)
	}

	rname, err := protocol.ParseName(z.SOA.RName)
	if err != nil {
		return nil, fmt.Errorf("parsing SOA rname: %w", err)
	}

	// Check if incremental transfer is needed using RFC 1982 serial arithmetic.
	if z.SOA.Serial != 0 && clientSerial != 0 && !serialIsNewer(z.SOA.Serial, clientSerial) {
		// Client has current or newer serial - send SOA only (no changes)
		return []*protocol.ResourceRecord{
			{
				Name:  origin,
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   z.SOA.TTL,
				Data: &protocol.RDataSOA{
					MName:   mname,
					RName:   rname,
					Serial:  z.SOA.Serial,
					Refresh: z.SOA.Refresh,
					Retry:   z.SOA.Retry,
					Expire:  z.SOA.Expire,
					Minimum: z.SOA.Minimum,
				},
			},
		}, nil
	}

	// Try incremental transfer from journal
	if s.journalStore != nil {
		entries, err := s.journalStore.LoadEntries(strings.ToLower(z.Origin))
		if err == nil && len(entries) > 0 {
			return s.buildIncrementalIXFR(entries, z, origin, mname, rname, clientSerial)
		}
	}

	// Fall back to full AXFR
	return s.generateAXFRRecordsLocked(z)
}

// buildIncrementalIXFR builds an incremental IXFR response from journal entries.
// Follows RFC 1995 pattern: SOA, deleted, SOA, added, ... for each change.
func (s *XoTServer) buildIncrementalIXFR(entries []*IXFRJournalEntry, z *zone.Zone, origin *protocol.Name, mname, rname *protocol.Name, clientSerial uint32) ([]*protocol.ResourceRecord, error) {
	// Find starting index using RFC 1982 serial arithmetic.
	startIdx := -1
	for i, entry := range entries {
		if serialIsNewer(entry.Serial, clientSerial) {
			startIdx = i
			break
		}
	}

	if startIdx == -1 {
		// No entries newer than client serial — fall back to AXFR
		return s.generateAXFRRecordsLocked(z)
	}

	// A journal entry is only a usable next version for the client when the
	// entry immediately before the first newer one ends exactly at the
	// client's serial:
	//
	//   startIdx > 0  -> the preceding entry's post-change Serial must equal
	//                    clientSerial.
	//   startIdx == 0 -> the client is at (or before) the oldest retained
	//                    entry, whose PRE-change OldSerial bounds it. A client
	//                    older than that is not covered: the journal was
	//                    trimmed (RecordChange's maxJournalSize) or never
	//                    spanned that far, so the changes between the client
	//                    and entries[0] are gone. Building a delta from
	//                    entries[0] applies the wrong diff onto the wrong base
	//                    version and silently corrupts the secondary.
	//
	// The previous guard was `startIdx > 0 && entries[startIdx-1].Serial !=
	// clientSerial`, which is vacuous when startIdx == 0 — precisely the
	// uncovered case. Mirror IXFRServer.generateIncrementalIXFR (ixfr.go),
	// which already answers a full AXFR here per RFC 1995 §4 / RFC 5936 §4.2.
	uncovered := false
	switch {
	case startIdx > 0:
		uncovered = entries[startIdx-1].Serial != clientSerial
	default:
		uncovered = entries[0].OldSerial != clientSerial
	}
	// The delta must also END at the serial the response announces. A zone
	// change that was not journalled (API record edit, zone-file reload)
	// leaves the journal tail behind z.SOA.Serial; a delta stopping at the
	// tail but framed with the current SOA would mark the secondary as current
	// while it lacks those changes (F225).
	if !uncovered && entries[len(entries)-1].Serial != z.SOA.Serial {
		uncovered = true
	}
	if uncovered {
		// Gap in journal — fall back to AXFR
		return s.generateAXFRRecordsLocked(z)
	}

	var records []*protocol.ResourceRecord

	// RFC 1995 pattern: SOA(del), del, SOA(new), add, ... SOA(final)
	// First, output the SOA with current serial to start
	currentSOA := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   z.SOA.TTL,
		Data: &protocol.RDataSOA{
			MName:   mname,
			RName:   rname,
			Serial:  z.SOA.Serial,
			Refresh: z.SOA.Refresh,
			Retry:   z.SOA.Retry,
			Expire:  z.SOA.Expire,
			Minimum: z.SOA.Minimum,
		},
	}
	records = append(records, currentSOA)

	// Process each journal entry
	previousSerial := clientSerial
	for i := startIdx; i < len(entries); i++ {
		entry := entries[i]

		// SOA with previous serial (ending previous version)
		prevSOA := &protocol.ResourceRecord{
			Name:  origin,
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   z.SOA.TTL,
			Data: &protocol.RDataSOA{
				MName:   mname,
				RName:   rname,
				Serial:  previousSerial,
				Refresh: z.SOA.Refresh,
				Retry:   z.SOA.Retry,
				Expire:  z.SOA.Expire,
				Minimum: z.SOA.Minimum,
			},
		}
		records = append(records, prevSOA)

		// Deleted records
		for _, del := range entry.Deleted {
			rr, err := s.changeToRR(del)
			if err != nil {
				continue
			}
			records = append(records, rr)
		}

		// SOA with new serial (starting this version)
		newSOA := &protocol.ResourceRecord{
			Name:  origin,
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   z.SOA.TTL,
			Data: &protocol.RDataSOA{
				MName:   mname,
				RName:   rname,
				Serial:  entry.Serial,
				Refresh: z.SOA.Refresh,
				Retry:   z.SOA.Retry,
				Expire:  z.SOA.Expire,
				Minimum: z.SOA.Minimum,
			},
		}
		records = append(records, newSOA)

		// Added records
		for _, add := range entry.Added {
			rr, err := s.changeToRR(add)
			if err != nil {
				continue
			}
			records = append(records, rr)
		}

		previousSerial = entry.Serial
	}

	// Final SOA with current serial
	records = append(records, currentSOA)

	return records, nil
}

// zoneRecordToRR converts a zone record to a protocol resource record.
func (s *XoTServer) zoneRecordToRR(name string, rec zone.Record) (*protocol.ResourceRecord, error) {
	owner, err := protocol.ParseName(name)
	if err != nil {
		return nil, err
	}

	rrtype := protocol.RecordTypeFromText(rec.Type)
	if rrtype == 0 {
		return nil, fmt.Errorf("unknown record type: %s", rec.Type)
	}

	// Parse RData based on type
	rdata, err := parseRData(rrtype, rec.RData)
	if err != nil {
		return nil, err
	}

	return &protocol.ResourceRecord{
		Name:  owner,
		Type:  rrtype,
		Class: protocol.ClassIN,
		TTL:   rec.TTL,
		Data:  rdata,
	}, nil
}

// sortRecordsCanonically sorts records in canonical order per RFC 4034.

// changeToRR converts a journal RecordChange to a protocol resource record.
func (s *XoTServer) changeToRR(change zone.RecordChange) (*protocol.ResourceRecord, error) {
	owner, err := protocol.ParseName(change.Name)
	if err != nil {
		return nil, err
	}

	rdata, err := parseRData(change.Type, change.RData)
	if err != nil {
		return nil, err
	}

	return &protocol.ResourceRecord{
		Name:  owner,
		Type:  change.Type,
		Class: protocol.ClassIN,
		TTL:   change.TTL,
		Data:  rdata,
	}, nil
}

// sortRecordsCanonically sorts records in canonical order per RFC 4034.
func (s *XoTServer) sortRecordsCanonically(records []*protocol.ResourceRecord) {
	// O(n log n) stdlib sort — the previous O(n²) selection sort spent multiple
	// seconds sorting a 20,000-record zone on the AXFR/IXFR transfer path.
	sort.Slice(records, func(i, j int) bool {
		return canonicalLess(records[i], records[j])
	})
}

// canonicalLess returns true if a should come before b in canonical order.
func canonicalLess(a, b *protocol.ResourceRecord) bool {
	// Compare owner names (case-insensitive)
	nameA := strings.ToLower(a.Name.String())
	nameB := strings.ToLower(b.Name.String())
	if nameA != nameB {
		return nameA < nameB
	}
	// Compare types
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	return false
}

// sendErrorResponse sends a DNS error response over the TLS connection.
func (s *XoTServer) sendErrorResponse(conn net.Conn, reqMsg *protocol.Message, rcode uint8) error {
	// Use the request ID if available, otherwise 0
	id := uint16(0)
	if reqMsg != nil && reqMsg.Header.ID != 0 {
		id = reqMsg.Header.ID
	}
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:      id,
			Flags:   protocol.Flags{},
			QDCount: 0,
		},
	}
	resp.Header.SetResponse(rcode)

	buf := make([]byte, 2+65535)
	n, err := resp.Pack(buf[2:])
	if err != nil {
		return err
	}

	return writeXoTFrame(conn, buf[:2+n], n)
}

// sendAXFRResponse sends AXFR/IXFR records over the TLS connection.
// Multiple messages may be sent, each length-prefixed.
func (s *XoTServer) sendAXFRResponse(conn net.Conn, records []*protocol.ResourceRecord, requestID uint16) error {
	if len(records) == 0 {
		return nil
	}

	// Split records into messages: at most 50 records, and never more than
	// fits the 16-bit XoT length prefix (WireLength is the bound Pack
	// enforces). A fixed record count alone overflowed 65535 bytes for zones
	// with large records and aborted the transfer (F223).
	const maxRecordsPerMessage = 50
	const maxMessageSize = 65535

	if err := conn.SetWriteDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return err
	}

	for i := 0; i < len(records); {
		end := i
		size := protocol.HeaderLen
		for end < len(records) && end-i < maxRecordsPerMessage {
			rrLen := records[end].WireLength()
			if end > i && size+rrLen > maxMessageSize {
				break
			}
			size += rrLen
			end++
		}

		msg := &protocol.Message{
			Header: protocol.Header{
				ID:      requestID, // RFC 5936 §2.2: every message in the chain carries the query's ID — compliant secondaries reject the stream otherwise
				Flags:   protocol.Flags{QR: true, AA: true},
				ANCount: uint16(end - i),
			},
			Answers: records[i:end],
		}

		buf := make([]byte, 2+65535)
		n, err := msg.Pack(buf[2:])
		if err != nil {
			return err
		}

		if err := writeXoTFrame(conn, buf[:2+n], n); err != nil {
			return err
		}
		i = end
	}
	return nil
}

func writeXoTFrame(conn net.Conn, frame []byte, payloadLen int) error {
	frame[0] = byte(payloadLen >> 8)
	frame[1] = byte(payloadLen)
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func (s *XoTServer) closeConn(conn net.Conn, label string) {
	if err := closeXoTConn(conn); err != nil && !errors.Is(err, net.ErrClosed) {
		if s.logger != nil {
			s.logger.Warnf("XoT: failed to close %s: %v", label, err)
		} else {
			fmt.Printf("XoT: failed to close %s: %v\n", label, err)
		}
	}
}

func closeXoTConn(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// Close closes the XoT server.
func (s *XoTServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.stopCh != nil {
		close(s.stopCh)
	}
	listener := s.listener
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	var err error
	if listener != nil {
		err = listener.Close()
	}
	// Tear down live connections so shutdown neither waits on idle or
	// slow clients nor keeps serving zone data after Close (F226). Closing
	// the raw TCP conn unblocks a handshake, read or write in progress
	// without waiting on the TLS write lock; the handler's own deferred
	// Close then reports net.ErrClosed, which closeConn ignores.
	for _, c := range conns {
		raw := c
		if tc, ok := c.(*tls.Conn); ok {
			raw = tc.NetConn()
		}
		_ = raw.Close()
	}
	s.wg.Wait()
	return err
}

// Addr returns the listening address of the server.
func (s *XoTServer) Addr() string {
	return net.JoinHostPort(s.address, strconv.Itoa(s.port))
}
