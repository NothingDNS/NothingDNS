package transfer

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// UpdateOperation represents a single update operation
type UpdateOperation struct {
	Name       string
	Type       uint16
	TTL        uint32
	RData      string
	Operation  UpdateOpType
}

// UpdateOpType represents the type of update operation
type UpdateOpType int

const (
	// UpdateOpAdd adds a new record
	UpdateOpAdd UpdateOpType = iota
	// UpdateOpDelete deletes records (by name/type or name/type/RData)
	UpdateOpDelete
	// UpdateOpDeleteRRSet deletes all records of a specific type
	UpdateOpDeleteRRSet
	// UpdateOpDeleteName deletes all records at a name
	UpdateOpDeleteName
)

// UpdatePrerequisite represents a prerequisite condition
type UpdatePrerequisite struct {
	Name      string
	Type      uint16
	Class     uint16 // ClassANY or ClassNONE for special checks
	RData     string
	Condition PreconditionType
}

// PreconditionType represents the type of precondition check
type PreconditionType int

const (
	// PrecondExists checks if an RRset exists (value independent)
	PrecondExists PreconditionType = iota
	// PrecondExistsValue checks if an RR exists (value dependent)
	PrecondExistsValue
	// PrecondNotExists checks if an RRset does not exist
	PrecondNotExists
	// PrecondNameInUse checks if a name is in use
	PrecondNameInUse
	// PrecondNameNotInUse checks if a name is not in use
	PrecondNameNotInUse
)

// UpdateRequest represents a Dynamic DNS update request
type UpdateRequest struct {
	ZoneName       string
	ClientIP       net.IP
	Prerequisites  []UpdatePrerequisite
	Updates        []UpdateOperation
	TSIGKeyName    string
}

// UpdateResponse represents the result of an update request
type UpdateResponse struct {
	Success bool
	RCode   uint8
	Message string
}

// DynamicDNSHandler handles Dynamic DNS UPDATE requests
// RFC 2136 - Dynamic Updates in the Domain Name System
type DynamicDNSHandler struct {
	zones      map[string]*zone.Zone
	zonesMu    *sync.RWMutex
	keyStore   *KeyStore
	acl        map[string][]*net.IPNet // zone -> allowed networks
	aclMu      sync.RWMutex
	updateChan chan *UpdateRequest
	closed     bool
	closeMu    sync.Once
}

// NewDynamicDNSHandler creates a new Dynamic DNS handler
func NewDynamicDNSHandler(zones map[string]*zone.Zone) *DynamicDNSHandler {
	return &DynamicDNSHandler{
		zones:      zones,
		zonesMu:    &sync.RWMutex{},
		keyStore:   NewKeyStore(),
		acl:        make(map[string][]*net.IPNet),
		updateChan: make(chan *UpdateRequest, 100),
	}
}

// SetZonesMu sets an external mutex to protect the zones map.
// Use this when multiple components share the same zones map.
func (h *DynamicDNSHandler) SetZonesMu(mu *sync.RWMutex) {
	h.zonesMu = mu
}

// Close shuts down the handler, closing the update channel.
func (h *DynamicDNSHandler) Close() {
	h.closeMu.Do(func() {
		h.closed = true
		close(h.updateChan)
	})
}

// SetKeyStore sets the TSIG key store for authentication
func (h *DynamicDNSHandler) SetKeyStore(ks *KeyStore) {
	h.keyStore = ks
}

// AddACL adds an allowed network for a zone
func (h *DynamicDNSHandler) AddACL(zoneName string, network *net.IPNet) {
	zoneName = strings.ToLower(zoneName)
	h.aclMu.Lock()
	h.acl[zoneName] = append(h.acl[zoneName], network)
	h.aclMu.Unlock()
}

// IsAllowed checks if a client IP is allowed to update a zone
func (h *DynamicDNSHandler) IsAllowed(zoneName string, clientIP net.IP) bool {
	zoneName = strings.ToLower(zoneName)
	h.aclMu.RLock()
	networks, ok := h.acl[zoneName]
	h.aclMu.RUnlock()
	if !ok || len(networks) == 0 {
		// No ACL means allow all (but TSIG still required)
		return true
	}

	for _, network := range networks {
		if network.Contains(clientIP) {
			return true
		}
	}
	return false
}

// GetUpdateChannel returns the channel that receives update events
func (h *DynamicDNSHandler) GetUpdateChannel() <-chan *UpdateRequest {
	return h.updateChan
}

// HandleUpdate processes a Dynamic DNS UPDATE request
func (h *DynamicDNSHandler) HandleUpdate(req *protocol.Message, clientIP net.IP) (*protocol.Message, error) {
	// Verify this is an UPDATE request
	if req.Header.Flags.Opcode != protocol.OpcodeUpdate {
		return nil, fmt.Errorf("not an UPDATE request")
	}

	// Must have exactly one zone section
	if len(req.Questions) != 1 {
		return h.createUpdateResponse(req, protocol.RcodeFormatError), nil
	}

	zoneQuestion := req.Questions[0]
	zoneName := strings.ToLower(zoneQuestion.Name.String())

	// Get the zone
	h.zonesMu.RLock()
	z, ok := h.zones[zoneName]
	h.zonesMu.RUnlock()
	if !ok {
		return h.createUpdateResponse(req, protocol.RcodeNotZone), nil
	}

	// Check if client is allowed by ACL
	if !h.IsAllowed(zoneName, clientIP) {
		return h.createUpdateResponse(req, protocol.RcodeRefused), nil
	}

	// Verify TSIG if present (required for security)
	if h.keyStore != nil && hasTSIG(req) {
		keyName, err := getTSIGKeyName(req)
		if err != nil {
			return h.createUpdateResponse(req, protocol.RcodeFormatError), nil
		}

		key, ok := h.keyStore.GetKey(keyName)
		if !ok {
			return h.createUpdateResponse(req, protocol.RcodeNotAuth), nil
		}

		if err := VerifyMessage(req, key, nil); err != nil {
			return h.createUpdateResponse(req, protocol.RcodeNotAuth), nil
		}
	} else {
		// TSIG required for Dynamic DNS
		return h.createUpdateResponse(req, protocol.RcodeRefused), nil
	}

	// Check prerequisites
	if err := h.checkPrerequisites(z, req.Answers); err != nil {
		return h.createUpdateResponse(req, protocol.RcodeNXRRSet), nil
	}

	// Parse and apply updates
	updates, err := h.parseUpdates(req.Authorities)
	if err != nil {
		return h.createUpdateResponse(req, protocol.RcodeFormatError), nil
	}

	// Send update request to channel for processing
	updateReq := &UpdateRequest{
		ZoneName:      zoneName,
		ClientIP:      clientIP,
		Prerequisites: h.parsePrerequisites(req.Answers),
		Updates:       updates,
	}

	// Get TSIG key name if present
	if h.keyStore != nil && hasTSIG(req) {
		if keyName, err := getTSIGKeyName(req); err == nil {
			updateReq.TSIGKeyName = keyName
		}
	}

	select {
	case h.updateChan <- updateReq:
	default:
		return h.createUpdateResponse(req, protocol.RcodeRefused), nil
	}

	// Return success response
	return h.createUpdateResponse(req, protocol.RcodeSuccess), nil
}

// checkPrerequisites verifies all prerequisites are met
func (h *DynamicDNSHandler) checkPrerequisites(z *zone.Zone, prereqs []*protocol.ResourceRecord) error {
	for _, rr := range prereqs {
		name := strings.ToLower(rr.Name.String())

		switch rr.Class {
		case protocol.ClassANY:
			// YXDOMAIN or YXRRSET - name or RRset must exist
			if rr.Type == protocol.TypeANY {
				// YXDOMAIN - any records at name
				if !zoneNameExists(z, name) {
					return fmt.Errorf("name does not exist: %s", name)
				}
			} else {
				// YXRRSET - specific type must exist
				if !zoneTypeExists(z, name, rr.Type) {
					return fmt.Errorf("RRset does not exist: %s %d", name, rr.Type)
				}
			}
		case protocol.ClassNONE:
			// NXDOMAIN or NXRRSET - name or RRset must not exist
			if rr.Type == protocol.TypeANY {
				// NXDOMAIN - no records at name
				if zoneNameExists(z, name) {
					return fmt.Errorf("name exists: %s", name)
				}
			} else {
				// NXRRSET - specific type must not exist
				if zoneTypeExists(z, name, rr.Type) {
					return fmt.Errorf("RRset exists: %s %d", name, rr.Type)
				}
			}
		default:
			// Value-dependent prerequisite (RR must exist with this value)
			if !zoneRecordExists(z, name, rr.Type, rr.Data.String()) {
				return fmt.Errorf("record does not exist: %s %d", name, rr.Type)
			}
		}
	}
	return nil
}

// parsePrerequisites extracts prerequisites from resource records
func (h *DynamicDNSHandler) parsePrerequisites(prereqs []*protocol.ResourceRecord) []UpdatePrerequisite {
	var result []UpdatePrerequisite
	for _, rr := range prereqs {
		name := strings.ToLower(rr.Name.String())

		var condition PreconditionType
		switch rr.Class {
		case protocol.ClassANY:
			if rr.Type == protocol.TypeANY {
				condition = PrecondNameInUse
			} else {
				condition = PrecondExists
			}
		case protocol.ClassNONE:
			if rr.Type == protocol.TypeANY {
				condition = PrecondNameNotInUse
			} else {
				condition = PrecondNotExists
			}
		default:
			condition = PrecondExistsValue
		}

		result = append(result, UpdatePrerequisite{
			Name:      name,
			Type:      rr.Type,
			Class:     rr.Class,
			Condition: condition,
		})
	}
	return result
}

// parseUpdates extracts update operations from resource records
func (h *DynamicDNSHandler) parseUpdates(updates []*protocol.ResourceRecord) ([]UpdateOperation, error) {
	var result []UpdateOperation
	for _, rr := range updates {
		name := strings.ToLower(rr.Name.String())

		var op UpdateOpType
		var rdata string

		// Determine operation based on Class and TTL
		switch rr.Class {
		case protocol.ClassNONE:
			// Deletion
			if rr.Type == protocol.TypeANY {
				op = UpdateOpDeleteName
			} else {
				op = UpdateOpDeleteRRSet
			}
		case protocol.ClassANY:
			// Delete specific RR (value dependent)
			op = UpdateOpDelete
			rdata = rr.Data.String()
		default:
			// Addition
			op = UpdateOpAdd
			rdata = rr.Data.String()
		}

		result = append(result, UpdateOperation{
			Name:      name,
			Type:      rr.Type,
			TTL:       rr.TTL,
			RData:     rdata,
			Operation: op,
		})
	}
	return result, nil
}

// createUpdateResponse creates an UPDATE response message
func (h *DynamicDNSHandler) createUpdateResponse(req *protocol.Message, rcode uint8) *protocol.Message {
	return &protocol.Message{
		Header: protocol.Header{
			ID:      req.Header.ID,
			QDCount: req.Header.QDCount,
			Flags:   protocol.NewResponseFlags(rcode),
		},
		Questions: req.Questions,
	}
}

// IsUpdateRequest checks if a message is a Dynamic DNS UPDATE request
func IsUpdateRequest(msg *protocol.Message) bool {
	return msg.Header.Flags.Opcode == protocol.OpcodeUpdate && !msg.Header.Flags.QR
}

// IsUpdateResponse checks if a message is an UPDATE response
func IsUpdateResponse(msg *protocol.Message) bool {
	return msg.Header.Flags.Opcode == protocol.OpcodeUpdate && msg.Header.Flags.QR
}

// ApplyUpdate applies an update to a zone
func ApplyUpdate(z *zone.Zone, update *UpdateRequest) error {
	z.Lock()
	defer z.Unlock()

	// Check prerequisites again before applying
	for _, precond := range update.Prerequisites {
		if err := checkPrerequisiteOnZone(z, precond); err != nil {
			return err
		}
	}

	// Apply each update operation
	for _, op := range update.Updates {
		if err := applyOperationToZone(z, op); err != nil {
			return err
		}
	}

	// Bump SOA serial after successful mutation (RFC 2136 §3.7)
	zone.IncrementSerial(z)

	return nil
}

// checkPrerequisiteOnZone checks a single prerequisite
func checkPrerequisiteOnZone(z *zone.Zone, precond UpdatePrerequisite) error {
	switch precond.Condition {
	case PrecondExists:
		if !zoneTypeExists(z, precond.Name, precond.Type) {
			return fmt.Errorf("prerequisite failed: RRset does not exist")
		}
	case PrecondNotExists:
		if zoneTypeExists(z, precond.Name, precond.Type) {
			return fmt.Errorf("prerequisite failed: RRset exists")
		}
	case PrecondNameInUse:
		if !zoneNameExists(z, precond.Name) {
			return fmt.Errorf("prerequisite failed: name not in use")
		}
	case PrecondNameNotInUse:
		if zoneNameExists(z, precond.Name) {
			return fmt.Errorf("prerequisite failed: name in use")
		}
	case PrecondExistsValue:
		if precond.RData != "" {
			if !zoneRecordExists(z, precond.Name, precond.Type, precond.RData) {
				return fmt.Errorf("prerequisite failed: specific RR does not exist")
			}
		} else if !zoneTypeExists(z, precond.Name, precond.Type) {
			// When RData is empty, fall back to type-existence check
			return fmt.Errorf("prerequisite failed: RRset does not exist")
		}
	}
	return nil
}

// applyOperationToZone applies a single update operation
func applyOperationToZone(z *zone.Zone, op UpdateOperation) error {
	switch op.Operation {
	case UpdateOpAdd:
		record := zone.Record{
			Name:  op.Name,
			Type:  protocol.TypeString(op.Type),
			TTL:   op.TTL,
			RData: op.RData,
		}
		z.Records[op.Name] = append(z.Records[op.Name], record)

	case UpdateOpDelete:
		// Delete specific record (name + type + rdata)
		zoneDeleteRecord(z, op.Name, op.Type, op.RData)

	case UpdateOpDeleteRRSet:
		// Delete all records of type at name
		zoneDeleteRRSet(z, op.Name, op.Type)

	case UpdateOpDeleteName:
		// Delete all records at name
		zoneDeleteName(z, op.Name)
	}

	return nil
}

// Helper functions for zone operations

// zoneNameExists checks if any records exist at the given name
func zoneNameExists(z *zone.Zone, name string) bool {
	// Normalize name
	if !strings.HasSuffix(name, ".") {
		name = name + "." + z.Origin
	}
	records, ok := z.Records[name]
	return ok && len(records) > 0
}

// zoneTypeExists checks if any records of the given type exist at the name
func zoneTypeExists(z *zone.Zone, name string, rrType uint16) bool {
	// Normalize name
	if !strings.HasSuffix(name, ".") {
		name = name + "." + z.Origin
	}
	records, ok := z.Records[name]
	if !ok {
		return false
	}
	typeStr := protocol.TypeString(rrType)
	for _, r := range records {
		if r.Type == typeStr {
			return true
		}
	}
	return false
}

// zoneRecordExists checks if a specific record exists
func zoneRecordExists(z *zone.Zone, name string, rrType uint16, rdata string) bool {
	// Normalize name
	if !strings.HasSuffix(name, ".") {
		name = name + "." + z.Origin
	}
	records, ok := z.Records[name]
	if !ok {
		return false
	}
	typeStr := protocol.TypeString(rrType)
	for _, r := range records {
		if r.Type == typeStr && strings.EqualFold(r.RData, rdata) {
			return true
		}
	}
	return false
}

// zoneDeleteRecord deletes a specific record
func zoneDeleteRecord(z *zone.Zone, name string, rrType uint16, rdata string) {
	// Normalize name
	if !strings.HasSuffix(name, ".") {
		name = name + "." + z.Origin
	}
	records, ok := z.Records[name]
	if !ok {
		return
	}

	typeStr := protocol.TypeString(rrType)
	var newRecords []zone.Record
	for _, r := range records {
		if !(r.Type == typeStr && strings.EqualFold(r.RData, rdata)) {
			newRecords = append(newRecords, r)
		}
	}
	z.Records[name] = newRecords
}

// zoneDeleteRRSet deletes all records of a specific type at a name
func zoneDeleteRRSet(z *zone.Zone, name string, rrType uint16) {
	// Normalize name
	if !strings.HasSuffix(name, ".") {
		name = name + "." + z.Origin
	}
	records, ok := z.Records[name]
	if !ok {
		return
	}

	typeStr := protocol.TypeString(rrType)
	var newRecords []zone.Record
	for _, r := range records {
		if r.Type != typeStr {
			newRecords = append(newRecords, r)
		}
	}
	z.Records[name] = newRecords
}

// zoneDeleteName deletes all records at a name
func zoneDeleteName(z *zone.Zone, name string) {
	// Normalize name
	if !strings.HasSuffix(name, ".") {
		name = name + "." + z.Origin
	}
	delete(z.Records, name)
}
