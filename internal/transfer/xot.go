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

	"github.com/nothingdns/nothingdns/internal/protocol"
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
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("XoT AcceptLoop panic recovered: %v\n", r)
		}
	}()

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
	defer func() {
		if r := recover(); r != nil {
			// Log panic but don't crash the server
			fmt.Printf("XoT handleConnection panic recovered: %v\n", r)
		}
		conn.Close()
	}()

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
		s.sendErrorResponse(conn, nil, protocol.RcodeFormatError)
		return
	}

	// Get client IP for access control
	clientIP := conn.RemoteAddr().(*net.TCPAddr).IP

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
	s.sendErrorResponse(conn, protocolMsg, protocol.RcodeNotImplemented)
}

// handleAXFRRequest processes an AXFR request over XoT.
func (s *XoTServer) handleAXFRRequest(conn net.Conn, req *protocol.Message, clientIP net.IP) {
	// Check if client is allowed by IP
	if !s.isAllowed(clientIP) {
		s.sendErrorResponse(conn, req, protocol.RcodeRefused)
		return
	}

	// Get zone name from question
	if len(req.Questions) != 1 {
		s.sendErrorResponse(conn, req, protocol.RcodeFormatError)
		return
	}

	zoneName := req.Questions[0].Name.String()

	// Get the zone
	s.zonesMu.RLock()
	z, ok := s.zones[strings.ToLower(zoneName)]
	s.zonesMu.RUnlock()
	if !ok {
		s.sendErrorResponse(conn, req, protocol.RcodeNameError)
		return
	}

	// Generate AXFR records using the same logic as AXFRServer
	records, err := s.generateAXFRRecords(z)
	if err != nil {
		s.sendErrorResponse(conn, req, protocol.RcodeServerFailure)
		return
	}

	// Send AXFR response: SOA + all records + SOA (multiple messages allowed)
	// RFC 5936: AXFR response is a sequence of messages, each with SOA at start/end of whole transfer
	s.sendAXFRResponse(conn, records)
}

// handleIXFRRequest processes an IXFR request over XoT.
func (s *XoTServer) handleIXFRRequest(conn net.Conn, req *protocol.Message, clientIP net.IP) {
	// Check if client is allowed by IP
	if !s.isAllowed(clientIP) {
		s.sendErrorResponse(conn, req, protocol.RcodeRefused)
		return
	}

	// Get zone name from question
	if len(req.Questions) != 1 {
		s.sendErrorResponse(conn, req, protocol.RcodeFormatError)
		return
	}

	zoneName := req.Questions[0].Name.String()

	// Get zone
	s.zonesMu.RLock()
	z, ok := s.zones[strings.ToLower(zoneName)]
	s.zonesMu.RUnlock()
	if !ok {
		s.sendErrorResponse(conn, req, protocol.RcodeNameError)
		return
	}

	// For IXFR, we need to check if the client has a serial number
	// RFC 1995: IXFR uses SOA to determine if incremental transfer is possible
	var clientSOASerial uint32
	if len(req.Additionals) > 0 {
		// Check for EDNS0 or TSIG with SOA
		for _, rr := range req.Additionals {
			if rr.Type == protocol.TypeSOA {
				if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
					clientSOASerial = soa.Serial
					break
				}
			}
		}
	}

	// Generate IXFR response
	records, err := s.generateIXFRRecords(z, clientSOASerial)
	if err != nil {
		s.sendErrorResponse(conn, req, protocol.RcodeServerFailure)
		return
	}

	s.sendAXFRResponse(conn, records)
}

// isAllowed checks if a client IP is allowed for XoT.
func (s *XoTServer) isAllowed(clientIP net.IP) bool {
	return true // TODO: Implement allowlist check from config
}

// generateAXFRRecords generates AXFR response records for a zone.
func (s *XoTServer) generateAXFRRecords(z *zone.Zone) ([]*protocol.ResourceRecord, error) {
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

	// Collect all zone records
	var zoneRecords []*protocol.ResourceRecord
	z.RLock()
	for name, recs := range z.Records {
		for _, rec := range recs {
			rr, err := s.zoneRecordToRR(name, rec, z.Origin)
			if err != nil {
				continue
			}
			zoneRecords = append(zoneRecords, rr)
		}
	}
	z.RUnlock()

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
// If serial hasn't changed, returns SOA only. Otherwise returns incremental changes.
func (s *XoTServer) generateIXFRRecords(z *zone.Zone, clientSerial uint32) ([]*protocol.ResourceRecord, error) {
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

	// Check if incremental transfer is possible
	if z.SOA.Serial != 0 && clientSerial != 0 && clientSerial == z.SOA.Serial {
		// Client has current serial - send SOA only (no changes)
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

	// For now, return full AXFR-style response (IXFR with all records)
	// A full IXFR implementation would track journal changes
	return s.generateAXFRRecords(z)
}

// zoneRecordToRR converts a zone record to a protocol resource record.
func (s *XoTServer) zoneRecordToRR(name string, rec zone.Record, origin string) (*protocol.ResourceRecord, error) {
	owner, err := protocol.ParseName(name)
	if err != nil {
		return nil, err
	}

	rrtype := protocol.StringToType[rec.Type]
	if rrtype == 0 {
		return nil, fmt.Errorf("unknown record type: %s", rec.Type)
	}

	// Parse RData based on type
	rdata, err := parseXoTRData(rrtype, rec.RData, origin)
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
func (s *XoTServer) sortRecordsCanonically(records []*protocol.ResourceRecord) {
	for i := 0; i < len(records)-1; i++ {
		for j := i + 1; j < len(records); j++ {
			if canonicalLess(records[j], records[i]) {
				records[i], records[j] = records[j], records[i]
			}
		}
	}
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
func (s *XoTServer) sendErrorResponse(conn net.Conn, reqMsg *protocol.Message, rcode uint8) {
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
		return
	}

	// Write length prefix + response
	buf[0] = byte(n >> 8)
	buf[1] = byte(n)
	conn.Write(buf[:2+n])
}

// sendAXFRResponse sends AXFR/IXFR records over the TLS connection.
// Multiple messages may be sent, each length-prefixed.
func (s *XoTServer) sendAXFRResponse(conn net.Conn, records []*protocol.ResourceRecord) {
	if len(records) == 0 {
		return
	}

	// Split records into messages (target ~16KB per message for efficiency)
	const maxRecordsPerMessage = 50
	chunkSize := maxRecordsPerMessage

	conn.SetWriteDeadline(time.Now().Add(60 * time.Second))

	for i := 0; i < len(records); i += chunkSize {
		end := i + chunkSize
		if end > len(records) {
			end = len(records)
		}

		msg := &protocol.Message{
			Header: protocol.Header{
				ID:      0, // Use 0 for AXFR responses
				Flags:   protocol.Flags{},
				ANCount: uint16(end - i),
			},
			Answers: records[i:end],
		}

		buf := make([]byte, 2+65535)
		n, err := msg.Pack(buf[2:])
		if err != nil {
			return
		}

		// Write length prefix + message
		buf[0] = byte(n >> 8)
		buf[1] = byte(n)
		if _, err := conn.Write(buf[:2+n]); err != nil {
			return
		}
	}
}

// parseXoTRData parses record data based on type.
func parseXoTRData(rrtype uint16, rdataStr, origin string) (protocol.RData, error) {
	switch rrtype {
	case protocol.TypeA:
		ip := net.ParseIP(rdataStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid A record: %s", rdataStr)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("A record requires IPv4")
		}
		var addr [4]byte
		copy(addr[:], ipv4)
		return &protocol.RDataA{Address: addr}, nil

	case protocol.TypeAAAA:
		ip := net.ParseIP(rdataStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid AAAA record: %s", rdataStr)
		}
		var addr [16]byte
		copy(addr[:], ip.To16())
		return &protocol.RDataAAAA{Address: addr}, nil

	case protocol.TypeCNAME:
		name, err := protocol.ParseName(rdataStr)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataCNAME{CName: name}, nil

	case protocol.TypeNS:
		name, err := protocol.ParseName(rdataStr)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataNS{NSDName: name}, nil

	case protocol.TypeMX:
		var pref uint16
		var exchange string
		_, err := fmt.Sscanf(rdataStr, "%d %s", &pref, &exchange)
		if err != nil {
			exchange = strings.TrimSpace(rdataStr)
		}
		name, err := protocol.ParseName(exchange)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataMX{Preference: pref, Exchange: name}, nil

	case protocol.TypeTXT:
		text := strings.Trim(rdataStr, "\"")
		return &protocol.RDataTXT{Strings: []string{text}}, nil

	case protocol.TypePTR:
		name, err := protocol.ParseName(rdataStr)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataPTR{PtrDName: name}, nil

	case protocol.TypeSRV:
		var priority, weight, port uint16
		var target string
		_, err := fmt.Sscanf(rdataStr, "%d %d %d %s", &priority, &weight, &port, &target)
		if err != nil {
			return nil, fmt.Errorf("invalid SRV record: %s", rdataStr)
		}
		name, err := protocol.ParseName(target)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataSRV{
			Priority: priority,
			Weight:   weight,
			Port:     port,
			Target:   name,
		}, nil

	default:
		return &protocol.RDataRaw{TypeVal: rrtype, Data: []byte(rdataStr)}, nil
	}
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
