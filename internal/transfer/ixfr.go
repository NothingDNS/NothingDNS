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
	// OldSerial is the SOA serial BEFORE this change. It is the entry's
	// lower bound: a client at this serial is covered by the entry, a client
	// at anything older is not. generateIncrementalIXFR needs it to decide
	// whether the oldest retained entry is the client's next version (a delta
	// is correct) or a much later one (a delta would corrupt the secondary).
	// 0 is a legitimate serial, so a journal restored from the store — which
	// does not persist this field — degrades to "unknown" and safely falls
	// back to a full AXFR rather than serving a wrong delta.
	OldSerial uint32 // SOA serial before this change
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
		OldSerial: oldSerial,
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
	records, _, err := s.HandleIXFRWithKey(req, clientIP)
	return records, err
}

// HandleIXFRWithKey is HandleIXFR that also returns the TSIG key that
// authenticated the request (nil for an unsigned request). Callers must sign
// the response stream with it (RFC 8945 §5.3.1, F313).
func (s *IXFRServer) HandleIXFRWithKey(req *protocol.Message, clientIP net.IP) ([]*protocol.ResourceRecord, *TSIGKey, error) {
	if s == nil || s.axfrServer == nil {
		return nil, nil, fmt.Errorf("IXFR server is nil")
	}

	// Check if client is allowed (delegate to AXFR server)
	if !s.axfrServer.IsAllowed(clientIP) {
		return nil, nil, fmt.Errorf("client %s not authorized for IXFR", clientIP)
	}

	// Validate request
	if req == nil {
		return nil, nil, fmt.Errorf("IXFR request is nil")
	}
	if len(req.Questions) != 1 {
		return nil, nil, fmt.Errorf("IXFR requires exactly one question")
	}

	question := req.Questions[0]
	if question == nil || question.Name == nil {
		return nil, nil, fmt.Errorf("IXFR question is invalid")
	}
	if question.QType != protocol.TypeIXFR {
		return nil, nil, fmt.Errorf("invalid query type for IXFR: %d", question.QType)
	}

	zoneName := question.Name.String()

	// Get the zone
	s.axfrServer.zonesMu.RLock()
	z, ok := s.zones[strings.ToLower(zoneName)]
	s.axfrServer.zonesMu.RUnlock()
	if !ok {
		return nil, nil, fmt.Errorf("zone %s not found", zoneName)
	}

	if z == nil {
		return nil, nil, fmt.Errorf("zone is nil")
	}
	z.RLock()
	hasSOA := z.SOA != nil
	z.RUnlock()
	if !hasSOA {
		return nil, nil, fmt.Errorf("zone has no SOA record")
	}

	// Verify TSIG — if keyStore has keys, TSIG is required
	var tsigKey *TSIGKey
	if s.axfrServer.keyStore != nil && s.axfrServer.keyStore.HasKeys() {
		if !hasTSIG(req) {
			return nil, nil, fmt.Errorf("TSIG authentication required for IXFR")
		}
		keyName, err := getTSIGKeyName(req)
		if err != nil {
			return nil, nil, fmt.Errorf("getting TSIG key name: %w", err)
		}

		key, ok := s.axfrServer.keyStore.GetKey(keyName)
		if !ok {
			return nil, nil, fmt.Errorf("TSIG key not found: %s", keyName)
		}

		if err := s.axfrServer.keyStore.ValidateKeySource(keyName, clientIP); err != nil {
			return nil, nil, fmt.Errorf("TSIG client IP check failed: %w", err)
		}

		if err := VerifyMessage(req, key, nil); err != nil {
			return nil, nil, fmt.Errorf("TSIG verification failed: %w", err)
		}
		tsigKey = key
	} else if hasTSIG(req) {
		// TSIG was provided but we have no keys to verify it — reject
		return nil, nil, fmt.Errorf("TSIG key not found")
	}

	// One zone read lock covers the serial decision and the generated
	// answer, so a concurrent update can neither be half-seen nor make the
	// answer's SOA disagree with the serial it was chosen for (F413).
	z.RLock()
	defer z.RUnlock()
	if z.SOA == nil {
		return nil, nil, fmt.Errorf("zone has no SOA record")
	}

	// Extract client serial from Authority section (SOA record)
	clientSerial := s.extractClientSerial(req)
	serverSerial := z.SOA.Serial

	// If client is up to date (server == client), return single SOA.
	// RFC 1982 serial arithmetic: serialIsNewer(server, client) is true
	// only when the server has strictly newer data. Its negation covers
	// two cases that must NOT be conflated:
	//   1. server == client          → client is up-to-date, send single SOA.
	//   2. client is newer than server → server is BEHIND the client (real-world
	//      condition: secondary misconfiguration, stale zone, client clock
	//      skew). Sending a single SOA here would falsely tell the client
	//      it's up-to-date, causing the stale zone to persist silently.
	//      Fall back to AXFR so the client gets a consistent snapshot.
	if serverSerial == clientSerial {
		records, err := s.generateSingleSOA(z)
		return records, tsigKey, err
	}
	if serialIsNewer(clientSerial, serverSerial) {
		// Server is behind the client: refuse the IXFR delta (we can't
		// produce a correct forward-difference) and force a full AXFR.
		records, err := s.axfrServer.generateAXFRRecordsLocked(z)
		return records, tsigKey, err
	}

	// Try to generate incremental changes
	records, err := s.generateIncrementalIXFR(z, clientSerial)
	if err != nil {
		// Fall back to AXFR
		records, err = s.axfrServer.generateAXFRRecordsLocked(z)
		return records, tsigKey, err
	}

	return records, tsigKey, nil
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
// Used when client is already up to date. The caller holds z's read lock.
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

// generateIncrementalIXFR generates incremental changes between client and
// server serials. The caller holds z's read lock (it reads z.SOA).
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

	// Check if we have all changes from client serial to current.
	//
	// The journal covers the client's serial only when the entry immediately
	// before the first newer entry starts exactly at the client serial:
	//
	//   startIdx > 0  -> the preceding entry's post-change Serial must equal
	//                   clientSerial.
	//   startIdx == 0 -> the client is at (or before) the oldest retained
	//                   entry, whose PRE-change OldSerial bounds it. A client
	//                   older than that is not covered: the journal was trimmed
	//                   at maxJournalSize (RecordChange) or never spanned that
	//                   far, so the changes between the client and journal[0]
	//                   are gone. Building a delta from journal[0] would apply
	//                   the wrong diff onto the wrong base version and silently
	//                   corrupt the secondary.
	//
	// In the uncovered case we return an error so HandleIXFR falls back to a
	// full AXFR (RFC 1995 §4 / RFC 5936 §4.2) — the only correct answer.
	uncovered := false
	switch {
	case startIdx > 0:
		uncovered = journal[startIdx-1].Serial != clientSerial
	default:
		uncovered = journal[0].OldSerial != clientSerial
	}
	if uncovered {
		return nil, fmt.Errorf("journal doesn't cover client serial %d", clientSerial)
	}
	// The delta must end at the serial the response is framed with. A zone
	// change that was not journalled (API record edit, zone-file reload)
	// leaves the journal tail behind z.SOA.Serial; serving the shorter delta
	// under the current SOA marks the secondary current while it lacks those
	// changes, so fall back to AXFR (F225).
	if tail := journal[len(journal)-1]; tail.Serial != z.SOA.Serial {
		return nil, fmt.Errorf("journal ends at serial %d, zone is at %d", tail.Serial, z.SOA.Serial)
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

	// Receive response records. With a key, the response stream is bound to
	// this request's TSIG MAC (RFC 8945 §4.3.3, F314).
	var requestMAC []byte
	if key != nil {
		if requestMAC, err = TSIGRequestMAC(req); err != nil {
			return nil, fmt.Errorf("reading IXFR request MAC: %w", err)
		}
	}
	records, err := c.receiveIXFRResponseForRequest(conn, req.Header.ID, key, currentSerial, requestMAC)
	if err != nil {
		return nil, fmt.Errorf("receiving IXFR response: %w", err)
	}
	// A master is authoritative only for the requested zone (F217).
	if err := checkTransferInZone(req.Questions[0].Name, records); err != nil {
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

// maxUnsignedTSIGMessages is the RFC 8945 §5.3.1 bound on consecutive
// unsigned messages in a TSIG-signed multi-message transfer.
const maxUnsignedTSIGMessages = 99

// ixfrStreamTracker follows the RFC 1995 §4 record structure of an IXFR
// response so the client knows exactly when the transfer is complete,
// independently of how the master split the records into TCP messages (F198,
// F199):
//
//	SOA(new)                              up-to-date (new not newer than client)
//	SOA(new) RRs... SOA                   AXFR-style full zone
//	SOA(new) [SOA(old) dels SOA(x) adds]... SOA(new)   incremental
type ixfrStreamTracker struct {
	clientSerial uint32
	newSerial    uint32
	n            int
	incremental  bool
	inAdds       bool // incremental: currently in an additions section
	done         bool
}

// feed consumes one answer RR and reports whether it completed the transfer.
func (t *ixfrStreamTracker) feed(rr *protocol.ResourceRecord) error {
	idx := t.n
	t.n++
	var soa *protocol.RDataSOA
	if rr != nil && rr.Type == protocol.TypeSOA {
		soa, _ = rr.Data.(*protocol.RDataSOA)
		if soa == nil {
			return fmt.Errorf("IXFR response contains a malformed SOA record")
		}
	}
	switch {
	case idx == 0:
		if soa == nil {
			return fmt.Errorf("IXFR response does not begin with an SOA record")
		}
		t.newSerial = soa.Serial
		// RFC 1995 §2/§4: a server with nothing newer answers with its SOA
		// alone.
		if !serialIsNewer(soa.Serial, t.clientSerial) {
			t.done = true
		}
	case idx == 1:
		if soa == nil {
			return nil // AXFR-style full transfer
		}
		if soa.Serial == t.newSerial {
			t.done = true // AXFR-style transfer of an SOA-only zone
			return nil
		}
		t.incremental = true // first diff block's old SOA opens deletions
	case soa == nil:
		return nil
	case !t.incremental:
		t.done = true // AXFR-style closing SOA
	case !t.inAdds:
		t.inAdds = true // diff block's new SOA opens additions
	case soa.Serial == t.newSerial:
		t.done = true // closing SOA
	default:
		t.inAdds = false // next diff block's old SOA
	}
	return nil
}

// receiveIXFRResponse receives IXFR response records over TCP. clientSerial is
// the serial sent in the request; it distinguishes the single-SOA up-to-date
// answer from the opening SOA of a transfer.
func (c *IXFRClient) receiveIXFRResponse(conn net.Conn, expectedTXID uint16, key *TSIGKey, clientSerial uint32) ([]*protocol.ResourceRecord, error) {
	return c.receiveIXFRResponseForRequest(conn, expectedTXID, key, clientSerial, nil)
}

// receiveIXFRResponseForRequest is receiveIXFRResponse for a request whose
// TSIG MAC is requestMAC: with a key, the stream is verified as one
// RFC 8945 §5.3.1 TSIG chain starting from it (F314).
func (c *IXFRClient) receiveIXFRResponseForRequest(conn net.Conn, expectedTXID uint16, key *TSIGKey, clientSerial uint32, requestMAC []byte) ([]*protocol.ResourceRecord, error) {
	var records []*protocol.ResourceRecord
	var totalBytes int
	tracker := &ixfrStreamTracker{clientSerial: clientSerial}
	tsigChain := newTSIGStreamVerifier(key, requestMAC)
	firstMessage := true
	unsigned := 0

	for {
		if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return nil, fmt.Errorf("setting read deadline: %w", err)
		}

		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			// F199: a stream that ends before its closing SOA is truncated,
			// never a complete transfer.
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

		// The message is intentionally NOT released: its records are
		// appended to the returned slice below, and Release() would zero
		// them (Type/TTL reset, Name/RData nil'd) before the caller reads
		// them. Unreleased pooled messages are reclaimed by the garbage
		// collector — the documented safe fallback in the protocol pool
		// contract.
		msg, err := protocol.UnpackMessage(msgBuf)
		if err != nil {
			return nil, fmt.Errorf("unpacking IXFR message: %w", err)
		}

		// Verify the response transaction ID matches the request.
		// This prevents a hostile or misbehaving master from injecting
		// spoofed DNS messages into the TCP stream (CWE-290 / CWE-347).
		if msg.Header.ID != expectedTXID {
			return nil, fmt.Errorf("IXFR response TXID mismatch: got %d, want %d", msg.Header.ID, expectedTXID)
		}

		if msg.Header.Flags.RCODE != protocol.RcodeSuccess {
			return nil, fmt.Errorf("IXFR failed with rcode: %d", msg.Header.Flags.RCODE)
		}

		// F197: a keyed transfer requires TSIG on the first message, on the
		// last message, and on at least every 100th message in between
		// (RFC 8945 §5.3.1).
		if key != nil {
			if hasTSIG(msg) {
				unsigned = 0
			} else {
				if firstMessage {
					return nil, fmt.Errorf("IXFR first response is missing TSIG")
				}
				unsigned++
				if unsigned > maxUnsignedTSIGMessages {
					return nil, fmt.Errorf("IXFR response has more than %d consecutive unsigned messages", maxUnsignedTSIGMessages)
				}
			}
			// F314: signed messages are verified against the request MAC /
			// previous MAC; unsigned ones are digested into the next one.
			if err := tsigChain.verify(msg); err != nil {
				return nil, fmt.Errorf("TSIG verification failed: %w", err)
			}
		}
		firstMessage = false

		// Process answer records
		for _, rr := range msg.Answers {
			if tracker.done {
				return nil, fmt.Errorf("IXFR response has records after its final SOA")
			}
			if err := tracker.feed(rr); err != nil {
				return nil, err
			}
			records = append(records, rr)
		}

		if tracker.done {
			if key != nil && !hasTSIG(msg) {
				return nil, fmt.Errorf("IXFR final response is missing TSIG")
			}
			break
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
