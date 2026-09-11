package transfer

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// UpdateOperation represents a single update operation
type UpdateOperation struct {
	Name      string
	Type      uint16
	TTL       uint32
	RData     string
	Operation UpdateOpType
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
	ZoneName      string
	ClientIP      net.IP
	Prerequisites []UpdatePrerequisite
	Updates       []UpdateOperation
	TSIGKeyName   string

	// OldSerial and NewSerial are the zone's SOA serial before and after
	// the update was applied. HandleUpdate fills them in so channel
	// consumers can journal the change without re-applying the update.
	OldSerial uint32
	NewSerial uint32
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
	// closeMu ensures Close runs once; the closed signal IS the channel
	// being closed (range/recv stops). No separate bool needed.
	closeMu sync.Once
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
	if req == nil {
		return nil, fmt.Errorf("nil UPDATE request")
	}

	// Verify this is an UPDATE request
	if req.Header.Flags.Opcode != protocol.OpcodeUpdate {
		return nil, fmt.Errorf("not an UPDATE request")
	}

	// Must have exactly one zone section
	if len(req.Questions) != 1 || req.Questions[0] == nil || req.Questions[0].Name == nil {
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

		if err := h.keyStore.ValidateKeySource(keyName, clientIP); err != nil {
			return h.createUpdateResponse(req, protocol.RcodeNotAuth), nil
		}

		if err := VerifyMessage(req, key, nil); err != nil {
			return h.createUpdateResponse(req, protocol.RcodeNotAuth), nil
		}
	} else {
		// TSIG required for Dynamic DNS
		return h.createUpdateResponse(req, protocol.RcodeRefused), nil
	}

	// Parse the wire RRs into typed update + prerequisite structs.
	// Prerequisite *checking* happens later, inside ApplyUpdate, under
	// z.Lock() — see M-6. The earlier unlocked check at this site
	// raced concurrent updates AND read z.Records without z.RLock().
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
	if err := validateUpdateWithinZone(z, updateReq); err != nil {
		return h.createUpdateResponse(req, protocol.RcodeNotZone), nil
	}

	// Get TSIG key name if present
	if h.keyStore != nil && hasTSIG(req) {
		if keyName, err := getTSIGKeyName(req); err == nil {
			updateReq.TSIGKeyName = keyName
		}
	}

	// SECURITY (V-06 fix + M-6): Apply update synchronously to prevent
	// TOCTOU race. ApplyUpdate now also re-checks prerequisites under
	// the same z.Lock() that gates the mutating operations, so two
	// concurrent UPDATEs with mutually-exclusive prereqs can't both
	// pass. Prereq failures return ErrPrereqFailed → NXRRSET RCODE;
	// any other error → ServFail.
	h.zonesMu.Lock()
	z.RLock()
	if z.SOA != nil {
		updateReq.OldSerial = z.SOA.Serial
	}
	z.RUnlock()
	err = ApplyUpdate(z, updateReq)
	if err == nil {
		z.RLock()
		if z.SOA != nil {
			updateReq.NewSerial = z.SOA.Serial
		}
		z.RUnlock()
	}
	h.zonesMu.Unlock()
	if err != nil {
		if errors.Is(err, ErrPrereqFailed) {
			return h.createUpdateResponse(req, protocol.RcodeNXRRSet), nil
		}
		if errors.Is(err, ErrNotZone) {
			return h.createUpdateResponse(req, protocol.RcodeNotZone), nil
		}
		return h.createUpdateResponse(req, protocol.RcodeServerFailure), nil
	}

	// Notify update channel for post-apply side effects (IXFR journal,
	// audit, persistence). The update is ALREADY applied above — consumers
	// must never call ApplyUpdate again (non-blocking send).
	select {
	case h.updateChan <- updateReq:
	default:
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
		var rdata string
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
			if rr.Data != nil {
				rdata = rr.Data.String()
			}
		}

		result = append(result, UpdatePrerequisite{
			Name:      name,
			Type:      rr.Type,
			Class:     rr.Class,
			RData:     rdata,
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
		case protocol.ClassANY:
			// Delete all RRsets at a name or one RRset (RFC 2136 §2.5.2, §2.5.3)
			if rr.Type == protocol.TypeANY {
				op = UpdateOpDeleteName
			} else {
				op = UpdateOpDeleteRRSet
			}
		case protocol.ClassNONE:
			// Delete a specific RR (RFC 2136 §2.5.4)
			op = UpdateOpDelete
			if rr.Data != nil {
				rdata = rr.Data.String()
			}
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
	if req == nil {
		resp := &protocol.Message{}
		resp.Header.Flags = protocol.NewResponseFlags(rcode)
		return resp
	}
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
	if msg == nil {
		return false
	}
	return msg.Header.Flags.Opcode == protocol.OpcodeUpdate && !msg.Header.Flags.QR
}

// IsUpdateResponse checks if a message is an UPDATE response
func IsUpdateResponse(msg *protocol.Message) bool {
	if msg == nil {
		return false
	}
	return msg.Header.Flags.Opcode == protocol.OpcodeUpdate && msg.Header.Flags.QR
}

// ErrPrereqFailed is returned by ApplyUpdate when an RFC 2136
// prerequisite does not hold against the current zone state. The
// handler maps it to the appropriate NXRRSet/YXRRSet/NXDomain/
// YXDomain RCODE rather than the generic ServFail it returns for
// other errors.
var ErrPrereqFailed = errors.New("ddns: prerequisite failed")

// ErrNotZone is returned when an UPDATE prerequisite or operation owner is
// outside the target zone. RFC 2136 requires the handler to answer NOTZONE.
var ErrNotZone = errors.New("ddns: name outside zone")

// ApplyUpdate applies an update to a zone. The prerequisite check and
// the mutating operations run under a single z.Lock() acquisition so
// concurrent UPDATEs with mutually-exclusive prerequisites can't both
// pass — fixing the TOCTOU window the handler used to leave open by
// doing an extra unlocked prereq check before calling here (M-6).
func ApplyUpdate(z *zone.Zone, update *UpdateRequest) error {
	if z == nil {
		return fmt.Errorf("ddns: nil zone")
	}
	if update == nil {
		return fmt.Errorf("ddns: nil update request")
	}

	z.Lock()
	defer z.Unlock()

	if err := validateUpdateWithinZone(z, update); err != nil {
		return err
	}

	// Check prerequisites under the same lock that protects the apply
	// loop below. Any failure here is reported as ErrPrereqFailed so
	// the handler can return the RFC 2136 prereq RCODE; bare error
	// wrapping is fine because errors.Is unwraps fmt.Errorf chains.
	for _, precond := range update.Prerequisites {
		if err := checkPrerequisiteOnZone(z, precond); err != nil {
			return fmt.Errorf("%w: %w", ErrPrereqFailed, err)
		}
	}

	// RFC 2136 §3.4.2 requires the update to be atomic: all operations
	// apply or none do. Validate every add up front so a mid-sequence
	// failure (malformed RDATA) cannot leave prior operations applied
	// while the serial bump is skipped — the zone would hold an
	// unjournaled in-memory-only change that vanishes on restart and
	// stays invisible to secondaries. Delete operations cannot fail
	// here, so adds are the only pre-pass needed.
	for _, op := range update.Updates {
		if op.Operation == UpdateOpAdd {
			if err := zone.ValidateRecordData(normalizeZoneOwner(op.Name, z.Origin), op.RData); err != nil {
				return err
			}
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

func validateUpdateWithinZone(z *zone.Zone, update *UpdateRequest) error {
	if z == nil {
		return fmt.Errorf("ddns: nil zone")
	}
	if update == nil {
		return fmt.Errorf("ddns: nil update request")
	}

	for _, precond := range update.Prerequisites {
		if !nameWithinZone(precond.Name, z.Origin) {
			return fmt.Errorf("%w: %s", ErrNotZone, precond.Name)
		}
	}
	for _, op := range update.Updates {
		if !nameWithinZone(op.Name, z.Origin) {
			return fmt.Errorf("%w: %s", ErrNotZone, op.Name)
		}
	}
	return nil
}

func nameWithinZone(name, origin string) bool {
	name = strings.ToLower(name)
	origin = strings.ToLower(origin)
	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}
	if !strings.HasSuffix(name, ".") {
		return true
	}
	return name == origin || strings.HasSuffix(name, "."+origin)
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
		name := normalizeZoneOwner(op.Name, z.Origin)
		if err := zone.ValidateRecordData(name, op.RData); err != nil {
			return err
		}
		return applyAddToZone(z, name, op)

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

// applyAddToZone implements the RFC 2136 §3.4.2.2 Add semantics. The
// previous implementation appended unconditionally, which duplicated
// identical RRs on replayed UPDATEs, allowed CNAME to coexist with other
// data, and stacked multiple SOA records at the apex.
//
// Rules applied (caller holds z.Lock()):
//   - Owner has a CNAME and the add is not a CNAME → silently ignored.
//   - Add is a CNAME and owner has non-CNAME data → silently ignored.
//   - Add is a CNAME over an existing CNAME → replaces it (singleton RRset).
//   - Add is an SOA: ignored unless at the apex with an RFC 1982-newer
//     serial, in which case it replaces the existing SOA.
//   - Identical name+type+rdata already present → TTL updated in place,
//     no duplicate appended.
func applyAddToZone(z *zone.Zone, name string, op UpdateOperation) error {
	typeStr := protocol.TypeString(op.Type)
	existing := z.Records[name]

	if typeStr == "CNAME" {
		for i, r := range existing {
			if r.Type == "CNAME" {
				// Singleton RRset: replace in place.
				existing[i].TTL = op.TTL
				existing[i].RData = op.RData
				return nil
			}
		}
		if len(existing) > 0 {
			return nil // non-CNAME data exists at owner: ignore
		}
	} else {
		for _, r := range existing {
			if r.Type == "CNAME" {
				return nil // owner is an alias: ignore non-CNAME adds
			}
		}
	}

	if typeStr == "SOA" {
		apex := strings.ToLower(z.Origin)
		if !strings.HasSuffix(apex, ".") {
			apex += "."
		}
		if name != apex {
			return nil // SOA outside the apex: ignore
		}
		newSOA := zone.ParseSOAFromRData(op.RData)
		if newSOA == nil {
			return fmt.Errorf("ddns: malformed SOA rdata")
		}
		if z.SOA != nil && !zone.SerialIsNewer(newSOA.Serial, z.SOA.Serial) {
			return nil // not newer (RFC 1982): ignore
		}
		newSOA.Name = name
		newSOA.TTL = op.TTL
		z.SOA = newSOA
		for i, r := range existing {
			if r.Type == "SOA" {
				existing[i].TTL = op.TTL
				existing[i].RData = op.RData
				return nil
			}
		}
		z.Records[name] = append(existing, zone.Record{
			Name: name, Type: typeStr, TTL: op.TTL, RData: op.RData,
		})
		return nil
	}

	// Duplicate suppression: identical RDATA updates the TTL only.
	for i, r := range existing {
		if r.Type == typeStr && r.RData == op.RData {
			existing[i].TTL = op.TTL
			return nil
		}
	}

	z.Records[name] = append(existing, zone.Record{
		Name:  name,
		Type:  typeStr,
		TTL:   op.TTL,
		RData: op.RData,
	})
	return nil
}

// Helper functions for zone operations

func normalizeZoneOwner(name, origin string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	origin = strings.ToLower(strings.TrimSpace(origin))
	if !strings.HasSuffix(name, ".") {
		name = name + "." + origin
	}
	return name
}

// zoneNameExists checks if any records exist at the given name
func zoneNameExists(z *zone.Zone, name string) bool {
	// Normalize name
	name = normalizeZoneOwner(name, z.Origin)
	records, ok := z.Records[name]
	return ok && len(records) > 0
}

// zoneTypeExists checks if any records of the given type exist at the name
func zoneTypeExists(z *zone.Zone, name string, rrType uint16) bool {
	// Normalize name
	name = normalizeZoneOwner(name, z.Origin)
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
	name = normalizeZoneOwner(name, z.Origin)
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
	name = normalizeZoneOwner(name, z.Origin)
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
	// Remove the map key entirely when no records remain, matching the
	// behavior of zone.Manager.DeleteRecord. Leaving an empty slice
	// behind accumulates empty-name entries that the rest of the code
	// has to defensively len()-check; they also leak into AXFR/IXFR
	// enumerations and zone export.
	if len(newRecords) == 0 {
		delete(z.Records, name)
	} else {
		z.Records[name] = newRecords
	}
}

// zoneDeleteRRSet deletes all records of a specific type at a name
func zoneDeleteRRSet(z *zone.Zone, name string, rrType uint16) {
	// Normalize name
	name = normalizeZoneOwner(name, z.Origin)
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
	if len(newRecords) == 0 {
		delete(z.Records, name)
	} else {
		z.Records[name] = newRecords
	}
}

// zoneDeleteName deletes all records at a name
func zoneDeleteName(z *zone.Zone, name string) {
	// Normalize name
	name = normalizeZoneOwner(name, z.Origin)
	delete(z.Records, name)
}
