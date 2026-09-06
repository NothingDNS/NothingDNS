package transfer

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// maxTransferBytes caps the aggregate wire bytes a client will accept from a
// master during a single AXFR/IXFR. Without it a hostile or misbehaving
// master can stream messages forever (each ≤65535 bytes) and grow the
// in-memory record slice without bound — the 1M-record guard alone admits
// dozens of GiB of RDATA before tripping. 512 MiB comfortably fits the
// largest real-world zones (.nz AXFR ≈ 140 MiB) while bounding worst-case
// memory to a known ceiling.
const maxTransferBytes = 512 << 20

// AXFRRequest represents an AXFR request
// Wire format: Question section with QTYPE=AXFR, QCLASS=IN
type AXFRRequest struct {
	ZoneName string
	ClientIP net.IP
}

// AXFRResponse represents an AXFR response
// Wire format: Sequence of resource records:
//  1. SOA record (start)
//  2. All zone records in canonical order
//  3. SOA record (end)
type AXFRResponse struct {
	ZoneName  string
	Records   []*protocol.ResourceRecord
	SOASerial uint32
}

// AXFRServer handles AXFR requests
// RFC 5936 - DNS Zone Transfer Protocol
// AXFR must use TCP (RFC 5936 Section 4.1)
type AXFRServer struct {
	zones       map[string]*zone.Zone // zone name -> zone
	zonesMu     *sync.RWMutex         // protects zones map (can be shared externally)
	keyStore    *KeyStore             // TSIG keys for authentication
	allowList   []net.IPNet           // Allowed client networks
	requireTSIG bool                  // Always require TSIG, even with allow list
	logger      *util.Logger          // Logger for diagnostics
}

// AXFRServerOption configures the AXFR server
type AXFRServerOption func(*AXFRServer)

// WithKeyStore sets the TSIG key store
func WithKeyStore(ks *KeyStore) AXFRServerOption {
	return func(s *AXFRServer) {
		s.keyStore = ks
	}
}

// WithAllowList sets allowed client networks
func WithAllowList(networks []string) AXFRServerOption {
	return func(s *AXFRServer) {
		for _, cidr := range networks {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				if s.logger != nil {
					s.logger.Warnf("AXFR: invalid CIDR in allowlist: %s: %v", cidr, err)
				}
				continue
			}
			s.allowList = append(s.allowList, *network)
		}
	}
}

// WithRequireTSIG enforces TSIG authentication for all AXFR requests,
// even when an IP allow list is configured. This provides defense in depth
// against unauthorized zone transfers from compromised hosts on the same network.
func WithRequireTSIG() AXFRServerOption {
	return func(s *AXFRServer) {
		s.requireTSIG = true
	}
}

// WithLogger sets a logger for the AXFR server.
// Should be applied before WithAllowList to log invalid CIDRs.
func WithLogger(logger *util.Logger) AXFRServerOption {
	return func(s *AXFRServer) {
		s.logger = logger
	}
}

// NewAXFRServer creates a new AXFR server
func NewAXFRServer(zones map[string]*zone.Zone, opts ...AXFRServerOption) *AXFRServer {
	if zones == nil {
		zones = make(map[string]*zone.Zone)
	}
	s := &AXFRServer{
		zones:     zones,
		zonesMu:   &sync.RWMutex{},
		keyStore:  NewKeyStore(),
		allowList: nil, // empty means deny all until explicitly configured
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithZonesMu sets an external mutex to protect the zones map.
// Use this when multiple components share the same zones map.
func WithZonesMu(mu *sync.RWMutex) AXFRServerOption {
	return func(s *AXFRServer) {
		if mu == nil {
			return
		}
		s.zonesMu = mu
	}
}

// SetZonesMu sets an external mutex to protect the zones map.
// Use this when multiple components share the same zones map.
func (s *AXFRServer) SetZonesMu(mu *sync.RWMutex) {
	if mu == nil {
		return
	}
	s.zonesMu = mu
}

// AddZone adds a zone to the server
func (s *AXFRServer) AddZone(z *zone.Zone) {
	if z == nil {
		return
	}
	s.zonesMu.Lock()
	s.zones[strings.ToLower(z.Origin)] = z
	s.zonesMu.Unlock()
}

// RemoveZone removes a zone from the server
func (s *AXFRServer) RemoveZone(zoneName string) {
	s.zonesMu.Lock()
	delete(s.zones, strings.ToLower(zoneName))
	s.zonesMu.Unlock()
}

// IsAllowed checks if a client IP is allowed to request AXFR
func (s *AXFRServer) IsAllowed(clientIP net.IP) bool {
	if len(s.allowList) == 0 {
		return false // Deny by default — require explicit allow-list configuration
	}
	for _, network := range s.allowList {
		if network.Contains(clientIP) {
			return true
		}
	}
	return false
}

// HandleAXFR handles an AXFR request message
// Returns the AXFR response records and the TSIG key used to verify the request (if any).
// Callers should use the returned key to sign response messages per RFC 2845.
func (s *AXFRServer) HandleAXFR(req *protocol.Message, clientIP net.IP) ([]*protocol.ResourceRecord, *TSIGKey, error) {
	if s == nil {
		return nil, nil, fmt.Errorf("AXFR server is nil")
	}

	// Check if client is allowed by IP
	if !s.IsAllowed(clientIP) {
		return nil, nil, fmt.Errorf("client %s not authorized for AXFR", clientIP)
	}

	// Validate request
	if req == nil {
		return nil, nil, fmt.Errorf("AXFR request is nil")
	}
	if len(req.Questions) != 1 {
		return nil, nil, fmt.Errorf("AXFR requires exactly one question")
	}

	question := req.Questions[0]
	if question == nil || question.Name == nil {
		return nil, nil, fmt.Errorf("AXFR question is invalid")
	}
	if question.QType != protocol.TypeAXFR {
		return nil, nil, fmt.Errorf("invalid query type for AXFR: %d", question.QType)
	}

	zoneName := question.Name.String()

	// Get the zone
	s.zonesMu.RLock()
	z, ok := s.zones[strings.ToLower(zoneName)]
	s.zonesMu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("zone %s not found", zoneName)
	}

	// Verify TSIG — TSIG is required when:
	// - requireTSIG is set (explicit enforcement regardless of other config)
	// - No allow list is configured (secure by default: require TSIG for external access)
	// - keyStore has keys configured
	// This ensures zone transfers are protected even without IP-based ACLs.
	hasAllowList := len(s.allowList) > 0
	var tsigKey *TSIGKey

	if s.requireTSIG || (s.keyStore != nil && s.keyStore.HasKeys()) {
		// TSIG required — authenticate
		if !hasTSIG(req) {
			return nil, nil, fmt.Errorf("TSIG authentication required for AXFR")
		}
		keyName, err := getTSIGKeyName(req)
		if err != nil {
			return nil, nil, fmt.Errorf("getting TSIG key name: %w", err)
		}

		key, ok := s.keyStore.GetKey(keyName)
		if !ok {
			return nil, nil, fmt.Errorf("TSIG key not found: %s", keyName)
		}

		// SECURITY (CWE-290): Verify client IP is in the key's AllowedCIDRs
		if err := s.keyStore.ValidateKeySource(keyName, clientIP); err != nil {
			return nil, nil, fmt.Errorf("TSIG client IP check failed: %w", err)
		}

		if err := VerifyMessage(req, key, nil); err != nil {
			return nil, nil, fmt.Errorf("TSIG verification failed: %w", err)
		}
		tsigKey = key
	} else if hasTSIG(req) {
		// TSIG was provided but we have no keys to verify it — reject
		return nil, nil, fmt.Errorf("TSIG key not found")
	} else if !hasAllowList {
		// No TSIG keys AND no allow list configured — deny by default (secure by default)
		return nil, nil, fmt.Errorf("TSIG authentication required for AXFR when no IP allow list is configured")
	}

	// Generate AXFR response
	records, err := s.generateAXFRRecords(z)
	if err != nil {
		return nil, nil, fmt.Errorf("generating AXFR records: %w", err)
	}

	return records, tsigKey, nil
}

// generateAXFRRecords generates the AXFR response records for a zone
// Per RFC 5936: SOA + all records (sorted) + SOA
func (s *AXFRServer) generateAXFRRecords(z *zone.Zone) ([]*protocol.ResourceRecord, error) {
	if z == nil {
		return nil, fmt.Errorf("zone is nil")
	}
	if z.SOA == nil {
		return nil, fmt.Errorf("zone has no SOA record")
	}

	origin, err := protocol.ParseName(z.Origin)
	if err != nil {
		return nil, fmt.Errorf("parsing zone origin: %w", err)
	}

	// Create SOA record (used at start and end)
	soaRR, err := s.createSOARR(z.SOA, origin)
	if err != nil {
		return nil, fmt.Errorf("creating SOA record: %w", err)
	}

	// Collect all zone records. The apex SOA is emitted separately as the
	// first and last record of the AXFR stream (RFC 5936 §2.2), so it must be
	// skipped here — the parser stores the apex SOA in both z.SOA and
	// z.Records[apex], and re-emitting it mid-stream makes RFC-compliant
	// secondaries treat the second SOA as end-of-transfer and discard every
	// record after it, truncating the zone to just the apex records.
	var zoneRecords []*protocol.ResourceRecord
	z.RLock()
	for name, zoneRecordsList := range z.Records {
		for _, rec := range zoneRecordsList {
			if protocol.RecordTypeFromText(rec.Type) == protocol.TypeSOA {
				continue
			}
			rr, err := s.zoneRecordToRR(name, rec)
			if err != nil {
				util.Warnf("axfr: skipping record %s/%s: %v", name, rec.Type, err)
				continue
			}
			zoneRecords = append(zoneRecords, rr)
		}
	}
	z.RUnlock()

	// Sort zone records canonically (RFC 4034 Section 6.1)
	// Note: We sort only zone records, not the SOA, because AXFR format
	// requires SOA to be first and last
	canonicalSort(zoneRecords)

	// Build final response: SOA + sorted zone records + SOA
	var records []*protocol.ResourceRecord
	records = append(records, soaRR)

	// Add ZONEMD record if present (RFC 8976)
	if z.ZONEMD != nil {
		var zonemdSerial uint32
		if z.SOA != nil {
			zonemdSerial = z.SOA.Serial
		}
		zonemdRR, err := s.createZONEMDRR(z.ZONEMD, origin, zonemdSerial)
		if err != nil {
			util.Warnf("axfr: failed to create ZONEMD record: %v", err)
		} else {
			records = append(records, zonemdRR)
		}
	}

	records = append(records, zoneRecords...)
	records = append(records, soaRR)

	return records, nil
}

// createSOARR creates a ResourceRecord from SOARecord
func (s *AXFRServer) createSOARR(soa *zone.SOARecord, origin *protocol.Name) (*protocol.ResourceRecord, error) {
	mname, err := protocol.ParseName(soa.MName)
	if err != nil {
		return nil, err
	}

	rname, err := protocol.ParseName(soa.RName)
	if err != nil {
		return nil, err
	}

	soaData := &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  soa.Serial,
		Refresh: soa.Refresh,
		Retry:   soa.Retry,
		Expire:  soa.Expire,
		Minimum: soa.Minimum,
	}

	return &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   soa.TTL,
		Data:  soaData,
	}, nil
}

// createZONEMDRR creates a ResourceRecord from ZONEMD
// RFC 8976 - Message Digests for DNS Zones
func (s *AXFRServer) createZONEMDRR(zonemd *zone.ZONEMD, origin *protocol.Name, soaSerial uint32) (*protocol.ResourceRecord, error) {
	// ZONEMD RData format:
	// Serial (4 bytes) | Scheme (1 byte) | Hash Algorithm (1 byte) | Digest
	// RFC 8976 §2.2 requires the ZONEMD Serial field to equal the zone's SOA
	// serial; a mismatch makes every RFC-8976 validator reject the digest.
	zonemdData := &protocol.RDataZONEMD{
		Serial:    soaSerial,
		Scheme:    1, // Simple ZONEMD scheme per RFC 8976
		Algorithm: zonemd.Algorithm,
		Digest:    zonemd.Hash,
	}

	return &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeZONEMD,
		Class: protocol.ClassIN,
		TTL:   0, // ZONEMD should have TTL 0 per RFC 8976
		Data:  zonemdData,
	}, nil
}

// zoneRecordToRR converts a zone.Record to protocol.ResourceRecord
func (s *AXFRServer) zoneRecordToRR(name string, rec zone.Record) (*protocol.ResourceRecord, error) {
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

// parseRData parses presentation-format RData via the shared protocol-package
// text parser, which understands the full set of record types (TLSA, SVCB,
// NAPTR, DS, DNSKEY, ...). Unparseable rdata is an error so call sites skip
// the record instead of shipping presentation bytes as wire data.
func parseRData(rrtype uint16, rdataStr string) (protocol.RData, error) {
	typeName := protocol.TypeString(rrtype)
	rdata := protocol.ParseRDataText(typeName, rdataStr)
	if rdata == nil {
		return nil, fmt.Errorf("unparseable rdata for type %s: %q", typeName, rdataStr)
	}
	return rdata, nil
}

// hasTSIG checks if a message has a TSIG record
func hasTSIG(msg *protocol.Message) bool {
	for _, rr := range msg.Additionals {
		if rr != nil && rr.Type == protocol.TypeTSIG {
			return true
		}
	}
	return false
}

// getTSIGKeyName extracts the TSIG key name from a message
func getTSIGKeyName(msg *protocol.Message) (string, error) {
	for _, rr := range msg.Additionals {
		if rr != nil && rr.Type == protocol.TypeTSIG {
			return rr.Name.String(), nil
		}
	}
	return "", fmt.Errorf("no TSIG record found")
}

// canonicalSort sorts records in canonical order (RFC 4034 Section 6.1)
func canonicalSort(records []*protocol.ResourceRecord) {
	sort.Slice(records, func(i, j int) bool {
		// Compare owner names (canonical comparison)
		nameI := canonicalName(records[i].Name.String())
		nameJ := canonicalName(records[j].Name.String())
		if nameI != nameJ {
			return nameI < nameJ
		}

		// Compare types
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}

		// For same name and type, we could compare RData but it's complex
		// For AXFR, this level of sorting is usually sufficient
		return false
	})
}

// canonicalName returns the canonical form of a domain name
// All lowercase, with trailing dot
func canonicalName(name string) string {
	return strings.ToLower(name)
}

// AXFRClient represents an AXFR client
// Can request zone transfers from remote servers
type AXFRClient struct {
	server   string        // Server address (host:port)
	keyStore *KeyStore     // TSIG keys for authentication
	timeout  time.Duration // Connection timeout
}

// AXFROption configures the AXFR client
type AXFROption func(*AXFRClient)

// WithAXFRTimeout sets the connection timeout
func WithAXFRTimeout(timeout time.Duration) AXFROption {
	return func(c *AXFRClient) {
		c.timeout = timeout
	}
}

// WithAXFRKeyStore sets the TSIG key store
func WithAXFRKeyStore(ks *KeyStore) AXFROption {
	return func(c *AXFRClient) {
		c.keyStore = ks
	}
}

// NewAXFRClient creates a new AXFR client
func NewAXFRClient(server string, opts ...AXFROption) *AXFRClient {
	c := &AXFRClient{
		server:   server,
		keyStore: NewKeyStore(),
		timeout:  30 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Transfer requests a zone transfer from the server
// Returns the received resource records
func (c *AXFRClient) Transfer(zoneName string, key *TSIGKey) ([]*protocol.ResourceRecord, error) {
	// Build AXFR request message
	req, err := c.buildAXFRRequest(zoneName, key)
	if err != nil {
		return nil, fmt.Errorf("building AXFR request: %w", err)
	}

	// Connect to server via TCP
	conn, err := net.DialTimeout("tcp", c.server, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %w", err)
	}
	defer conn.Close()

	// Send request
	if err := c.sendMessage(conn, req); err != nil {
		return nil, fmt.Errorf("sending AXFR request: %w", err)
	}

	// Receive response records
	records, err := c.receiveAXFRResponse(conn, req.Header.ID, key)
	if err != nil {
		return nil, fmt.Errorf("receiving AXFR response: %w", err)
	}

	return records, nil
}

// buildAXFRRequest builds an AXFR request message
func (c *AXFRClient) buildAXFRRequest(zoneName string, key *TSIGKey) (*protocol.Message, error) {
	name, err := protocol.ParseName(zoneName)
	if err != nil {
		return nil, err
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      generateMessageID(),
			Flags:   protocol.Flags{}, // No flags for AXFR query
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeAXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Add TSIG if key provided
	if key != nil {
		tsigRR, err := SignMessage(msg, key, 300)
		if err != nil {
			return nil, fmt.Errorf("signing message: %w", err)
		}
		msg.Additionals = append(msg.Additionals, tsigRR)
	}

	return msg, nil
}

// sendMessage sends a DNS message over TCP
func (c *AXFRClient) sendMessage(conn net.Conn, msg *protocol.Message) error {
	// Pack message into buffer with 2-byte length prefix at the start
	buf := make([]byte, 2+65535)
	n, err := msg.Pack(buf[2:])
	if err != nil {
		return err
	}

	if n > 65535 {
		return fmt.Errorf("message too large for TCP: %d bytes", n)
	}

	// Write length prefix + message fully; TCP may accept only a prefix.
	buf[0] = byte(n >> 8)
	buf[1] = byte(n)
	err = util.WriteFull(conn, buf[:2+n])
	return err
}

// receiveAXFRResponse receives AXFR response records over TCP
func (c *AXFRClient) receiveAXFRResponse(conn net.Conn, expectedTXID uint16, key *TSIGKey) ([]*protocol.ResourceRecord, error) {
	var records []*protocol.ResourceRecord
	var soaCount int
	var totalBytes int
	previousMAC := []byte{}

	for {
		// Set read timeout
		if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return nil, fmt.Errorf("setting read deadline: %w", err)
		}

		// Read 2-byte length prefix
		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			if soaCount >= 2 {
				// We got a complete transfer
				break
			}
			return nil, fmt.Errorf("reading message length: %w", err)
		}

		msgLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
		if msgLen == 0 || msgLen > 65535 {
			return nil, fmt.Errorf("invalid message length: %d", msgLen)
		}

		totalBytes += msgLen
		if totalBytes > maxTransferBytes {
			return nil, fmt.Errorf("AXFR response exceeds aggregate byte cap (%d bytes received)", totalBytes)
		}

		// Read message
		msgBuf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			return nil, fmt.Errorf("reading message: %w", err)
		}

		// Parse message
		msg, err := protocol.UnpackMessage(msgBuf)
		if err != nil {
			return nil, fmt.Errorf("unpacking message: %w", err)
		}
		defer msg.Release()

		// Verify the response transaction ID matches the request.
		// This prevents a hostile or misbehaving master from injecting
		// spoofed DNS messages into the TCP stream (CWE-290 / CWE-347).
		if msg.Header.ID != expectedTXID {
			return nil, fmt.Errorf("AXFR response TXID mismatch: got %d, want %d", msg.Header.ID, expectedTXID)
		}

		// Check for error response
		if msg.Header.Flags.RCODE != protocol.RcodeSuccess {
			return nil, fmt.Errorf("AXFR failed with rcode: %d", msg.Header.Flags.RCODE)
		}

		// Verify TSIG if present
		if key != nil && hasTSIG(msg) {
			if err := VerifyMessage(msg, key, previousMAC); err != nil {
				return nil, fmt.Errorf("TSIG verification failed: %w", err)
			}
			// Extract MAC for next message verification
			mac, err := extractMAC(msg)
			if err != nil {
				return nil, fmt.Errorf("failed to extract TSIG MAC: %w", err)
			}
			previousMAC = mac
		}

		// Process answer records
		for _, rr := range msg.Answers {
			records = append(records, rr)

			if rr.Type == protocol.TypeSOA {
				soaCount++
			}
		}

		// Check if transfer is complete (second SOA)
		if soaCount >= 2 {
			break
		}

		// Safety check: prevent infinite loop
		if len(records) > 1000000 {
			return nil, fmt.Errorf("AXFR response too large")
		}
	}

	return records, nil
}

// extractMAC extracts the TSIG MAC from a message for multi-message verification
func extractMAC(msg *protocol.Message) ([]byte, error) {
	for _, rr := range msg.Additionals {
		if rr.Type == protocol.TypeTSIG {
			if rdata, ok := rr.Data.(*RDataTSIG); ok {
				ts, _, err := UnpackTSIGRecord(rdata.Raw, 0)
				if err != nil {
					return nil, fmt.Errorf("failed to parse TSIG record for MAC extraction: %w", err)
				}
				if ts != nil {
					return ts.MAC, nil
				}
			}
		}
	}
	return nil, nil
}

// generateMessageID generates a random message ID
func generateMessageID() uint16 {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return uint16(time.Now().UnixNano() & 0xFFFF)
	}
	return uint16(b[0])<<8 | uint16(b[1])
}
