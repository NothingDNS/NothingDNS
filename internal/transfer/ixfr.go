package transfer

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// IXFRRequest represents an IXFR request
// Wire format: Question section with QTYPE=IXFR, QCLASS=IN
// Plus an SOA record in the Authority section with client's current serial
type IXFRRequest struct {
	ZoneName     string
	ClientIP     net.IP
	ClientSerial uint32 // Client's current SOA serial
}

// IXFRResponse represents an IXFR response
// Wire format: Difference sequences per RFC 1995:
//  1. If server serial <= client serial: single SOA (no changes)
//  2. If server has history: sequences of changes
//  3. If no history: full AXFR format
type IXFRResponse struct {
	ZoneName  string
	Records   []*protocol.ResourceRecord
	IsAXFR    bool   // True if fell back to full AXFR
	OldSerial uint32 // Client's original serial
	NewSerial uint32 // Server's current serial
}

// IXFRJournalEntry represents a single change to the zone
type IXFRJournalEntry struct {
	Serial    uint32 // SOA serial after this change
	Added     []zone.RecordChange
	Deleted   []zone.RecordChange
	Timestamp time.Time
}

// IXFRServer handles IXFR requests
// RFC 1995 - Incremental Zone Transfer in DNS
type IXFRServer struct {
	axfrServer     *AXFRServer // For AXFR fallback
	zones          map[string]*zone.Zone
	journals       map[string][]*IXFRJournalEntry // zone name -> journal entries (in-memory cache)
	journalsMu     sync.RWMutex                   // Protects journals map
	journalStore   JournalStore                   // Optional persistent storage
	maxJournalSize int                            // Maximum entries per zone
}

// NewIXFRServer creates a new IXFR server
func NewIXFRServer(axfrServer *AXFRServer) *IXFRServer {
	if axfrServer == nil {
		axfrServer = NewAXFRServer(nil)
	}
	return &IXFRServer{
		axfrServer:     axfrServer,
		zones:          axfrServer.zones,
		journals:       make(map[string][]*IXFRJournalEntry),
		maxJournalSize: 100, // Default: keep last 100 changes
	}
}

// SetJournalStore sets the persistent journal store.
// If a store is set, journal entries are persisted to disk.
// If nil, only in-memory storage is used.
func (s *IXFRServer) SetJournalStore(store JournalStore) {
	s.journalStore = store
}

// SetMaxJournalSize sets the maximum number of journal entries per zone
func (s *IXFRServer) SetMaxJournalSize(size int) {
	if s == nil || size <= 0 {
		return
	}
	s.journalsMu.Lock()
	s.maxJournalSize = size
	s.journalsMu.Unlock()
}

// RecordChange records a zone change for IXFR
// Called whenever a zone is modified
func (s *IXFRServer) RecordChange(zoneName string, oldSerial, newSerial uint32, added, deleted []zone.RecordChange) {
	if s == nil {
		return
	}
	zoneName = strings.ToLower(zoneName)

	entry := &IXFRJournalEntry{
		Serial:    newSerial,
		Added:     added,
		Deleted:   deleted,
		Timestamp: time.Now(),
	}

	s.journalsMu.Lock()
	if s.journals == nil {
		s.journals = make(map[string][]*IXFRJournalEntry)
	}
	if s.maxJournalSize <= 0 {
		s.maxJournalSize = 100
	}
	s.journals[zoneName] = append(s.journals[zoneName], entry)

	// Trim journal if too large
	if len(s.journals[zoneName]) > s.maxJournalSize {
		s.journals[zoneName] = s.journals[zoneName][len(s.journals[zoneName])-s.maxJournalSize:]
	}
	s.journalsMu.Unlock()

	// Persist to journal store if configured
	if s.journalStore != nil {
		if err := s.journalStore.SaveEntry(zoneName, entry); err != nil {
			util.Warnf("ixfr: failed to persist journal entry: %v", err)
		}
	}
}

// HandleIXFR handles an IXFR request message
// Returns the IXFR response records
func (s *IXFRServer) HandleIXFR(req *protocol.Message, clientIP net.IP) ([]*protocol.ResourceRecord, error) {
	if s == nil || s.axfrServer == nil {
		return nil, fmt.Errorf("IXFR server is nil")
	}

	// Check if client is allowed (delegate to AXFR server)
	if !s.axfrServer.IsAllowed(clientIP) {
		return nil, fmt.Errorf("client %s not authorized for IXFR", clientIP)
	}

	// Validate request
	if req == nil {
		return nil, fmt.Errorf("IXFR request is nil")
	}
	if len(req.Questions) != 1 {
		return nil, fmt.Errorf("IXFR requires exactly one question")
	}

	question := req.Questions[0]
	if question == nil || question.Name == nil {
		return nil, fmt.Errorf("IXFR question is invalid")
	}
	if question.QType != protocol.TypeIXFR {
		return nil, fmt.Errorf("invalid query type for IXFR: %d", question.QType)
	}

	zoneName := question.Name.String()

	// Get the zone
	s.axfrServer.zonesMu.RLock()
	z, ok := s.zones[strings.ToLower(zoneName)]
	s.axfrServer.zonesMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("zone %s not found", zoneName)
	}

	if z == nil {
		return nil, fmt.Errorf("zone is nil")
	}
	if z.SOA == nil {
		return nil, fmt.Errorf("zone has no SOA record")
	}

	// Verify TSIG — if keyStore has keys, TSIG is required
	if s.axfrServer.keyStore != nil && s.axfrServer.keyStore.HasKeys() {
		if !hasTSIG(req) {
			return nil, fmt.Errorf("TSIG authentication required for IXFR")
		}
		keyName, err := getTSIGKeyName(req)
		if err != nil {
			return nil, fmt.Errorf("getting TSIG key name: %w", err)
		}

		key, ok := s.axfrServer.keyStore.GetKey(keyName)
		if !ok {
			return nil, fmt.Errorf("TSIG key not found: %s", keyName)
		}

		if err := s.axfrServer.keyStore.ValidateKeySource(keyName, clientIP); err != nil {
			return nil, fmt.Errorf("TSIG client IP check failed: %w", err)
		}

		if err := VerifyMessage(req, key, nil); err != nil {
			return nil, fmt.Errorf("TSIG verification failed: %w", err)
		}
	} else if hasTSIG(req) {
		// TSIG was provided but we have no keys to verify it — reject
		return nil, fmt.Errorf("TSIG key not found")
	}

	// Extract client serial from Authority section (SOA record)
	clientSerial := s.extractClientSerial(req)
	serverSerial := z.SOA.Serial

	// If client is up to date, return single SOA
	// Use RFC 1982 serial arithmetic for wrap-safe comparison
	if !serialIsNewer(serverSerial, clientSerial) {
		return s.generateSingleSOA(z)
	}

	// Try to generate incremental changes
	records, err := s.generateIncrementalIXFR(z, clientSerial)
	if err != nil {
		// Fall back to AXFR
		return s.axfrServer.generateAXFRRecords(z)
	}

	return records, nil
}

// extractClientSerial extracts the client's SOA serial from the IXFR request
// Per RFC 1995, client includes an SOA record in the Authority section
func (s *IXFRServer) extractClientSerial(req *protocol.Message) uint32 {
	if req == nil {
		return 0
	}
	for _, rr := range req.Authorities {
		if rr == nil {
			continue
		}
		if rr.Type == protocol.TypeSOA {
			if soaData, ok := rr.Data.(*protocol.RDataSOA); ok {
				return soaData.Serial
			}
		}
	}
	return 0
}

// generateSingleSOA generates a response with just the SOA record
// Used when client is already up to date
func (s *IXFRServer) generateSingleSOA(z *zone.Zone) ([]*protocol.ResourceRecord, error) {
	origin, err := protocol.ParseName(z.Origin)
	if err != nil {
		return nil, fmt.Errorf("parsing zone origin: %w", err)
	}

	soaRR, err := s.axfrServer.createSOARR(z.SOA, origin)
	if err != nil {
		return nil, fmt.Errorf("creating SOA record: %w", err)
	}

	return []*protocol.ResourceRecord{soaRR}, nil
}

// generateIncrementalIXFR generates incremental changes between client and server serials
func (s *IXFRServer) generateIncrementalIXFR(z *zone.Zone, clientSerial uint32) ([]*protocol.ResourceRecord, error) {
	zoneName := strings.ToLower(z.Origin)

	s.journalsMu.RLock()
	journal := s.journals[zoneName]
	s.journalsMu.RUnlock()

	if len(journal) == 0 && s.journalStore != nil {
		// Try loading from persistent journal store
		entries, err := s.journalStore.LoadEntries(zoneName)
		if err != nil {
			util.Warnf("ixfr: failed to load journal from store: %v", err)
		} else if len(entries) > 0 {
			s.journalsMu.Lock()
			s.journals[zoneName] = entries
			journal = entries
			s.journalsMu.Unlock()
		}
	}

	if len(journal) == 0 {
		return nil, ErrNoJournal
	}

	// Find the starting point in the journal. Use RFC 1982 serial-number
	// comparison rather than plain unsigned '>' so journal lookup behaves
	// correctly across the 2^32 serial wraparound.
	startIdx := -1
	for i, entry := range journal {
		if entry == nil {
			return nil, fmt.Errorf("journal entry %d is nil", i)
		}
		if serialIsNewer(entry.Serial, clientSerial) {
			startIdx = i
			break
		}
	}

	if startIdx == -1 {
		return nil, fmt.Errorf("client serial %d not in journal range", clientSerial)
	}

	// Check if we have all changes from client serial to current
	// The journal entry at startIdx-1 should have serial <= clientSerial
	if startIdx > 0 && journal[startIdx-1].Serial != clientSerial {
		// We don't have the exact starting point
		return nil, fmt.Errorf("journal doesn't cover client serial %d", clientSerial)
	}

	origin, err := protocol.ParseName(z.Origin)
	if err != nil {
		return nil, fmt.Errorf("parsing zone origin: %w", err)
	}

	var records []*protocol.ResourceRecord

	// Add initial SOA with server serial
	soaRR, err := s.axfrServer.createSOARR(z.SOA, origin)
	if err != nil {
		return nil, err
	}
	records = append(records, soaRR)

	// Process each journal entry. Per RFC 1995 §4 the IXFR diff body is a
	// sequence of (old-SOA, deleted-RRs, new-SOA, added-RRs) blocks. The
	// "old-SOA" carries the serial of the version BEFORE this diff, and the
	// "new-SOA" carries the serial AFTER the diff. The first diff's old-SOA
	// uses clientSerial; subsequent diffs use the previous journal entry's
	// serial as their old-SOA value.
	for i := startIdx; i < len(journal); i++ {
		entry := journal[i]
		if entry == nil {
			return nil, fmt.Errorf("journal entry %d is nil", i)
		}

		var prevSerial uint32
		if i == startIdx {
			prevSerial = clientSerial
		} else {
			prevSerial = journal[i-1].Serial
		}

		// Old SOA — opens this diff block.
		prevSOA := s.createSOAWithSerial(z.SOA, origin, prevSerial)
		records = append(records, prevSOA)

		// Add deleted records
		for _, del := range entry.Deleted {
			rr, err := s.changeToRR(del)
			if err != nil {
				util.Warnf("ixfr: skipping deleted record %s/%d: %v", del.Name, del.Type, err)
				continue
			}
			records = append(records, rr)
		}

		// New SOA — closes this diff block with the post-update serial.
		newSOA := s.createSOAWithSerial(z.SOA, origin, entry.Serial)
		records = append(records, newSOA)

		// Add added records
		for _, add := range entry.Added {
			rr, err := s.changeToRR(add)
			if err != nil {
				util.Warnf("ixfr: skipping added record %s/%d: %v", add.Name, add.Type, err)
				continue
			}
			records = append(records, rr)
		}
	}

	// Add final SOA
	records = append(records, soaRR)

	return records, nil
}

// createSOAWithSerial creates an SOA record with a specific serial number
func (s *IXFRServer) createSOAWithSerial(soa *zone.SOARecord, origin *protocol.Name, serial uint32) *protocol.ResourceRecord {
	mname, merr := protocol.ParseName(soa.MName)
	if merr != nil {
		mname = protocol.NewName([]string{}, true)
	}
	rname, rerr := protocol.ParseName(soa.RName)
	if rerr != nil {
		rname = protocol.NewName([]string{}, true)
	}

	soaData := &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  serial,
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
	}
}

// changeToRR converts a RecordChange to a ResourceRecord
func (s *IXFRServer) changeToRR(change zone.RecordChange) (*protocol.ResourceRecord, error) {
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

// IXFRClient represents an IXFR client
type IXFRClient struct {
	server   string        // Server address (host:port)
	keyStore *KeyStore     // TSIG keys for authentication
	timeout  time.Duration // Connection timeout
}

// IXFROption configures the IXFR client
type IXFROption func(*IXFRClient)

// WithIXFRTimeout sets the connection timeout
func WithIXFRTimeout(timeout time.Duration) IXFROption {
	return func(c *IXFRClient) {
		c.timeout = timeout
	}
}

// WithIXFRKeyStore sets the TSIG key store
func WithIXFRKeyStore(ks *KeyStore) IXFROption {
	return func(c *IXFRClient) {
		c.keyStore = ks
	}
}

// NewIXFRClient creates a new IXFR client
func NewIXFRClient(server string, opts ...IXFROption) *IXFRClient {
	c := &IXFRClient{
		server:   server,
		keyStore: NewKeyStore(),
		timeout:  30 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Transfer requests an incremental zone transfer from the server
// currentSerial is the client's current SOA serial
func (c *IXFRClient) Transfer(zoneName string, currentSerial uint32, key *TSIGKey) ([]*protocol.ResourceRecord, error) {
	// Build IXFR request message
	req, err := c.buildIXFRRequest(zoneName, currentSerial, key)
	if err != nil {
		return nil, fmt.Errorf("building IXFR request: %w", err)
	}

	// Connect to server via TCP
	conn, err := net.DialTimeout("tcp", c.server, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %w", err)
	}
	defer conn.Close()

	// Send request
	if err := c.sendMessage(conn, req); err != nil {
		return nil, fmt.Errorf("sending IXFR request: %w", err)
	}

	// Receive response records
	records, err := c.receiveIXFRResponse(conn, key)
	if err != nil {
		return nil, fmt.Errorf("receiving IXFR response: %w", err)
	}

	return records, nil
}

// buildIXFRRequest builds an IXFR request message
func (c *IXFRClient) buildIXFRRequest(zoneName string, currentSerial uint32, key *TSIGKey) (*protocol.Message, error) {
	name, err := protocol.ParseName(zoneName)
	if err != nil {
		return nil, err
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      generateMessageID(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeIXFR,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Add SOA record to Authority section with current serial
	origin, err2 := protocol.ParseName(zoneName)
	if err2 != nil {
		return nil, fmt.Errorf("parsing zone name for SOA: %w", err2)
	}
	mname, merr := protocol.ParseName("ns1." + zoneName)
	if merr != nil {
		return nil, fmt.Errorf("parsing mname for SOA: %w", merr)
	}
	rname, rerr := protocol.ParseName("admin." + zoneName)
	if rerr != nil {
		return nil, fmt.Errorf("parsing rname for SOA: %w", rerr)
	}

	soaData := &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  currentSerial,
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data:  soaData,
	}

	msg.Authorities = append(msg.Authorities, soaRR)
	msg.Header.NSCount = 1

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
func (c *IXFRClient) sendMessage(conn net.Conn, msg *protocol.Message) error {
	buf := make([]byte, 2+65535)
	n, err := msg.Pack(buf[2:])
	if err != nil {
		return err
	}

	buf[0] = byte(n >> 8)
	buf[1] = byte(n)
	err = util.WriteFull(conn, buf[:2+n])
	return err
}

// receiveIXFRResponse receives IXFR response records over TCP
func (c *IXFRClient) receiveIXFRResponse(conn net.Conn, key *TSIGKey) ([]*protocol.ResourceRecord, error) {
	var records []*protocol.ResourceRecord
	var soaCount int
	var totalBytes int
	previousMAC := []byte{}

	for {
		if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return nil, fmt.Errorf("setting read deadline: %w", err)
		}

		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			if soaCount >= 2 {
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
			return nil, fmt.Errorf("IXFR response exceeds aggregate byte cap (%d bytes received)", totalBytes)
		}

		msgBuf := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgBuf); err != nil {
			return nil, fmt.Errorf("reading message: %w", err)
		}

		msg, err := protocol.UnpackMessage(msgBuf)
		if err != nil {
			return nil, fmt.Errorf("unpacking message: %w", err)
		}

		if msg.Header.Flags.RCODE != protocol.RcodeSuccess {
			return nil, fmt.Errorf("IXFR failed with rcode: %d", msg.Header.Flags.RCODE)
		}

		// Verify TSIG if present
		if key != nil && hasTSIG(msg) {
			if err := VerifyMessage(msg, key, previousMAC); err != nil {
				return nil, fmt.Errorf("TSIG verification failed: %w", err)
			}
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

		// Check if transfer is complete
		// For IXFR, we need to detect the end differently
		// The final SOA should match the server's current serial
		if len(msg.Answers) == 1 && msg.Answers[0].Type == protocol.TypeSOA {
			// Single SOA response means no changes or end of transfer
			if soaCount >= 2 {
				break
			}
		}

		// Safety check
		if len(records) > 1000000 {
			return nil, fmt.Errorf("IXFR response too large")
		}
	}

	return records, nil
}

// ParseIXFRResponse parses an IXFR response and extracts changes
func (c *IXFRClient) ParseIXFRResponse(records []*protocol.ResourceRecord) (*IXFRResponse, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	resp := &IXFRResponse{
		Records: records,
	}

	// Check if this is a single SOA (no changes)
	if len(records) == 1 && records[0].Type == protocol.TypeSOA {
		if soa, ok := records[0].Data.(*protocol.RDataSOA); ok {
			resp.NewSerial = soa.Serial
			resp.OldSerial = soa.Serial
			return resp, nil
		}
	}

	// Check if this looks like AXFR (SOA at start and end, rest in between)
	// vs IXFR (multiple SOA records interleaved with changes)
	if len(records) >= 2 {
		firstSOA, firstOK := records[0].Data.(*protocol.RDataSOA)
		lastSOA, lastOK := records[len(records)-1].Data.(*protocol.RDataSOA)

		if firstOK && lastOK && firstSOA.Serial == lastSOA.Serial {
			// Count SOA records - AXFR has exactly 2, IXFR has more
			soaCount := 0
			for _, rr := range records {
				if _, ok := rr.Data.(*protocol.RDataSOA); ok {
					soaCount++
				}
			}
			if soaCount == 2 {
				// AXFR: SOA + data records + SOA
				resp.IsAXFR = true
				resp.NewSerial = firstSOA.Serial
				return resp, nil
			}
			// IXFR format: SOA + SOA(old) + changes + SOA(new) + changes + SOA
			resp.NewSerial = firstSOA.Serial
			return resp, nil
		}
	}

	// Extract serials from IXFR format
	// Format: SOA(server) + [SOA(prev) + deletions + SOA(new) + additions]... + SOA(server)
	if len(records) >= 3 {
		var firstSOASerial uint32
		if firstSOA, ok := records[0].Data.(*protocol.RDataSOA); ok {
			firstSOASerial = firstSOA.Serial
			resp.NewSerial = firstSOA.Serial
		}
		if lastSOA, ok := records[len(records)-1].Data.(*protocol.RDataSOA); ok {
			if lastSOA.Serial != firstSOASerial {
				resp.IsAXFR = true
			}
		}
	}

	return resp, nil
}
