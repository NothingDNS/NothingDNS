package dnssec

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Signer provides zone signing capabilities.
type Signer struct {
	zone   string
	keys   map[uint16]*SigningKey // keytag -> key
	mu     sync.RWMutex
	config SignerConfig
}

// SigningKey holds a key pair for signing.
type SigningKey struct {
	PrivateKey *PrivateKey
	DNSKEY     *protocol.RDataDNSKEY
	KeyTag     uint16
	IsKSK      bool // Key Signing Key
	IsZSK      bool // Zone Signing Key

	// RFC 7583 key rollover state and timing
	State  KeyState   // Current lifecycle state (default: Active)
	Timing *KeyTiming // Scheduled timing for state transitions (nil = always active)
}

func cloneSigningKey(key *SigningKey) *SigningKey {
	if key == nil {
		return nil
	}
	clone := *key
	if key.PrivateKey != nil {
		privateKey := *key.PrivateKey
		clone.PrivateKey = &privateKey
	}
	if key.DNSKEY != nil {
		if dnskey, ok := key.DNSKEY.Copy().(*protocol.RDataDNSKEY); ok {
			clone.DNSKEY = dnskey
		}
	}
	if key.Timing != nil {
		timing := *key.Timing
		clone.Timing = &timing
	}
	return &clone
}

// SignerConfig holds signing parameters.
type SignerConfig struct {
	NSEC3Enabled      bool
	NSEC3Algorithm    uint8
	NSEC3Iterations   uint16
	NSEC3Salt         []byte
	NSEC3OptOut       bool // RFC 5155 Section 6 - opt-out for unsigned delegations
	SignatureValidity time.Duration
	InceptionOffset   time.Duration
}

// DefaultSignerConfig returns recommended signing settings.
func DefaultSignerConfig() SignerConfig {
	return SignerConfig{
		NSEC3Enabled:      false,
		NSEC3Algorithm:    1, // SHA-1 (only defined algorithm)
		NSEC3Iterations:   0,
		NSEC3Salt:         nil,
		SignatureValidity: 30 * 24 * time.Hour, // 30 days
		InceptionOffset:   1 * time.Hour,       // 1 hour in the past
	}
}

// NewSigner creates a zone signer.
func NewSigner(zone string, config SignerConfig) *Signer {
	return &Signer{
		zone:   canonicalZone(zone),
		keys:   make(map[uint16]*SigningKey),
		config: config,
	}
}

// AddKey adds a signing key (KSK or ZSK).
func (s *Signer) AddKey(key *SigningKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.KeyTag] = key
}

// RemoveKey removes a signing key.
func (s *Signer) RemoveKey(keyTag uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, keyTag)
}

// GetKeys returns all signing keys.
func (s *Signer) GetKeys() []*SigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*SigningKey, 0, len(s.keys))
	for _, key := range s.keys {
		result = append(result, cloneSigningKey(key))
	}
	return result
}

// GetKSKs returns all Key Signing Keys.
func (s *Signer) GetKSKs() []*SigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*SigningKey
	for _, key := range s.keys {
		if key.IsKSK {
			result = append(result, cloneSigningKey(key))
		}
	}
	return result
}

// GetZSKs returns all Zone Signing Keys.
func (s *Signer) GetZSKs() []*SigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*SigningKey
	for _, key := range s.keys {
		if key.IsZSK {
			result = append(result, cloneSigningKey(key))
		}
	}
	return result
}

// GetActiveKSKs returns KSKs that are in the Active state.
// Keys without timing metadata are considered always active.
func (s *Signer) GetActiveKSKs() []*SigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*SigningKey
	for _, key := range s.keys {
		if key.IsKSK && isActive(key) {
			result = append(result, cloneSigningKey(key))
		}
	}
	return result
}

// GetActiveZSKs returns ZSKs that are in the Active state.
// Keys without timing metadata are considered always active.
func (s *Signer) GetActiveZSKs() []*SigningKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*SigningKey
	for _, key := range s.keys {
		if key.IsZSK && isActive(key) {
			result = append(result, cloneSigningKey(key))
		}
	}
	return result
}

// isActive returns true if a key is in Active state or has no timing
// (legacy keys without rollover metadata are always active).
func isActive(key *SigningKey) bool {
	if key.Timing == nil {
		return true // No timing = always active (backward compatible)
	}
	return key.State == KeyStateActive
}

// SetKeyState updates the state of a key identified by its key tag.
func (s *Signer) SetKeyState(keyTag uint16, state KeyState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, ok := s.keys[keyTag]; ok {
		key.State = state
	}
}

// SetKeyTiming updates the timing metadata of a key identified by its key tag.
func (s *Signer) SetKeyTiming(keyTag uint16, timing *KeyTiming) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key, ok := s.keys[keyTag]; ok {
		key.Timing = timing
	}
}

// GenerateKeyPair generates a new key pair for the zone.
func (s *Signer) GenerateKeyPair(algorithm uint8, isKSK bool) (*SigningKey, error) {
	const maxKeyTagAttempts = 16

	for attempt := 0; attempt < maxKeyTagAttempts; attempt++ {
		key, err := s.generateKeyPairOnce(algorithm, isKSK)
		if err != nil {
			return nil, err
		}
		if key.KeyTag != 0 {
			s.AddKey(key)
			return key, nil
		}
	}

	return nil, fmt.Errorf("generated DNSSEC key tag was zero after %d attempts", maxKeyTagAttempts)
}

func (s *Signer) generateKeyPairOnce(algorithm uint8, isKSK bool) (*SigningKey, error) {
	priv, pub, err := GenerateKeyPair(algorithm, isKSK)
	if err != nil {
		return nil, err
	}

	// Create DNSKEY record
	flags := uint16(0x0100) // Zone Key bit
	if isKSK {
		flags |= protocol.DNSKEYFlagSEP // Secure Entry Point bit
	}

	publicKey, err := PackDNSKEYPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("packing public key: %w", err)
	}

	dnskey := &protocol.RDataDNSKEY{
		Flags:     flags,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: publicKey,
	}

	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)

	signingKey := &SigningKey{
		PrivateKey: priv,
		DNSKEY:     dnskey,
		KeyTag:     keyTag,
		IsKSK:      isKSK,
		IsZSK:      !isKSK,
	}

	return signingKey, nil
}

// SignZone signs all records in a zone.
// Returns the signed zone records including RRSIGs and NSEC/NSEC3 records.
func (s *Signer) SignZone(records []*protocol.ResourceRecord) ([]*protocol.ResourceRecord, error) {
	s.mu.RLock()
	if len(s.keys) == 0 {
		s.mu.RUnlock()
		return nil, fmt.Errorf("no signing keys available")
	}

	// Snapshot keys while holding the lock
	keys := make(map[uint16]*SigningKey, len(s.keys))
	for k, v := range s.keys {
		keys[k] = v
	}
	s.mu.RUnlock()

	// Separate DNSKEY records and other records
	var dnskeyRRs []*protocol.ResourceRecord
	var otherRRs []*protocol.ResourceRecord

	for _, rr := range records {
		if rr.Type == protocol.TypeDNSKEY {
			dnskeyRRs = append(dnskeyRRs, rr)
		} else {
			otherRRs = append(otherRRs, rr)
		}
	}

	// Generate DNSKEY records from our keys if not present
	if len(dnskeyRRs) == 0 {
		for _, key := range keys {
			name, err := protocol.ParseName(s.zone)
			if err != nil {
				return nil, fmt.Errorf("parsing zone name %q: %w", s.zone, err)
			}
			dnskeyRR := &protocol.ResourceRecord{
				Name:  name,
				Type:  protocol.TypeDNSKEY,
				Class: protocol.ClassIN,
				TTL:   86400,
				Data:  key.DNSKEY,
			}
			dnskeyRRs = append(dnskeyRRs, dnskeyRR)
		}
	}

	// Calculate signature validity
	now := time.Now()
	inception := signerUnixTime(now.Add(-s.config.InceptionOffset))
	expiration := signerUnixTime(now.Add(s.config.SignatureValidity))

	// Sign DNSKEY RRSet with active KSKs only.
	//
	// During a KSK rollover (RFC 7583) keys move through Pre-Published →
	// Ready → Active → Retired states. ONLY keys in the Active state
	// should be used to produce signatures: a Pre-Published key's
	// DNSKEY may already be in the zone, but resolvers haven't yet
	// established a chain of trust through it (parent DS not updated),
	// and a Retired key should not produce new signatures.
	//
	// The previous code called GetKSKs() (all KSKs regardless of
	// state), so any zone using the rollover scheduler would sign with
	// not-yet-trusted or post-rollover keys — validators would see
	// RRSIGs covered by a key they cannot verify and treat the zone
	// as Bogus. GetActiveKSKs() filters by state, with the same
	// "no timing = always active" backward-compat behaviour for zones
	// that don't use the rollover scheduler.
	ksks := s.GetActiveKSKs()
	if len(ksks) == 0 {
		return nil, fmt.Errorf("no active KSK available for signing DNSKEY")
	}

	var signedRecords []*protocol.ResourceRecord
	signedRecords = append(signedRecords, dnskeyRRs...)

	for _, ksk := range ksks {
		rrsig, err := s.SignRRSet(dnskeyRRs, ksk, inception, expiration)
		if err != nil {
			return nil, fmt.Errorf("signing DNSKEY: %w", err)
		}
		signedRecords = append(signedRecords, rrsig)
	}

	// Group other records by RRSet (name + type)
	groups := groupRecordsByRRSet(otherRRs)

	// Sign each RRSet with active ZSKs only — same rollover-state
	// rationale as KSKs above. A Pre-Published ZSK that isn't yet
	// active should not produce signatures (validators won't see its
	// DNSKEY as a valid signer until it transitions to Active).
	zsks := s.GetActiveZSKs()
	if len(zsks) == 0 {
		// Use active KSK as fallback (small zones often deploy a
		// single combined-signing key with both KSK+ZSK roles).
		zsks = ksks
	}

	for _, rrSet := range groups {
		// Add the records
		signedRecords = append(signedRecords, rrSet...)

		// Sign with all ZSKs
		for _, zsk := range zsks {
			rrsig, err := s.SignRRSet(rrSet, zsk, inception, expiration)
			if err != nil {
				return nil, fmt.Errorf("signing RRSet: %w", err)
			}
			signedRecords = append(signedRecords, rrsig)
		}
	}

	// Generate denial of existence records
	var denialRecords []*protocol.ResourceRecord
	if s.config.NSEC3Enabled {
		denialRecords = s.generateNSEC3(signedRecords)
	} else {
		denialRecords = s.generateNSEC(signedRecords)
	}

	// Sign denial records
	nsecGroups := groupRecordsByRRSet(denialRecords)
	for _, nsecSet := range nsecGroups {
		signedRecords = append(signedRecords, nsecSet...)

		for _, zsk := range zsks {
			rrsig, err := s.SignRRSet(nsecSet, zsk, inception, expiration)
			if err != nil {
				return nil, fmt.Errorf("signing NSEC: %w", err)
			}
			signedRecords = append(signedRecords, rrsig)
		}
	}

	return signedRecords, nil
}

// SignRRSet creates an RRSIG record for an RRSet.
func (s *Signer) SignRRSet(rrSet []*protocol.ResourceRecord, key *SigningKey, inception, expiration uint32) (*protocol.ResourceRecord, error) {
	ownerName, rrtype, ttl, err := validateRRSetForSigning(rrSet)
	if err != nil {
		return nil, err
	}
	if err := validateSigningKey(key); err != nil {
		return nil, err
	}

	// Sort records canonically
	sorted := make([]*protocol.ResourceRecord, len(rrSet))
	copy(sorted, rrSet)
	canonicalSort(sorted)

	// Count labels
	labelCount := len(splitLabels(ownerName))
	if labelCount > 0xff {
		return nil, fmt.Errorf("owner name has too many labels for RRSIG: %d (max 255)", labelCount)
	}
	labels := uint8(labelCount)

	// Create RRSIG record
	signerName, err := protocol.ParseName(s.zone)
	if err != nil {
		return nil, fmt.Errorf("parsing zone name %q: %w", s.zone, err)
	}

	rrsig := &protocol.RDataRRSIG{
		TypeCovered: rrtype,
		Algorithm:   key.DNSKEY.Algorithm,
		Labels:      labels,
		OriginalTTL: ttl,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      key.KeyTag,
		SignerName:  signerName,
		Signature:   nil, // Will be filled after signing
	}

	// Create canonical data to sign
	signedData, err := s.createSignedData(sorted, rrsig)
	if err != nil {
		return nil, fmt.Errorf("creating signed data: %w", err)
	}

	// Sign the data
	signature, err := SignData(key.DNSKEY.Algorithm, key.PrivateKey, signedData)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	rrsig.Signature = signature

	// Create the RRSIG resource record
	owner, ownerErr := protocol.ParseName(ownerName)
	if ownerErr != nil {
		return nil, fmt.Errorf("parsing owner name %q: %w", ownerName, ownerErr)
	}
	rrsigRR := &protocol.ResourceRecord{
		Name:  owner,
		Type:  protocol.TypeRRSIG,
		Class: protocol.ClassIN,
		TTL:   ttl,
		Data:  rrsig,
	}

	return rrsigRR, nil
}

func validateRRSetForSigning(rrSet []*protocol.ResourceRecord) (string, uint16, uint32, error) {
	if len(rrSet) == 0 {
		return "", 0, 0, fmt.Errorf("cannot sign empty RRSet")
	}

	first := rrSet[0]
	if first == nil {
		return "", 0, 0, fmt.Errorf("nil RR in RRSet")
	}
	if first.Name == nil {
		return "", 0, 0, fmt.Errorf("nil RR owner name")
	}
	if first.Data == nil {
		return "", 0, 0, fmt.Errorf("nil RDATA for %s type %d", first.Name.String(), first.Type)
	}

	ownerName := first.Name.String()
	rrtype := first.Type
	class := first.Class
	ttl := first.TTL
	for i, rr := range rrSet[1:] {
		index := i + 1
		if rr == nil {
			return "", 0, 0, fmt.Errorf("nil RR in RRSet")
		}
		if rr.Name == nil {
			return "", 0, 0, fmt.Errorf("nil RR owner name")
		}
		if rr.Data == nil {
			return "", 0, 0, fmt.Errorf("nil RDATA for %s type %d", rr.Name.String(), rr.Type)
		}
		if rr.Name.String() != ownerName || rr.Type != rrtype || rr.Class != class {
			return "", 0, 0, fmt.Errorf("record %d does not belong to RRSet %s type %d class %d", index, ownerName, rrtype, class)
		}
	}

	return ownerName, rrtype, ttl, nil
}

func validateSigningKey(key *SigningKey) error {
	if key == nil {
		return fmt.Errorf("nil signing key")
	}
	if key.DNSKEY == nil {
		return fmt.Errorf("nil DNSKEY in signing key")
	}
	if key.PrivateKey == nil {
		return fmt.Errorf("nil private key in signing key")
	}
	return nil
}

func signerUnixTime(t time.Time) uint32 {
	sec := t.Unix()
	if sec <= 0 {
		return 0
	}
	if sec > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(sec)
}

// createSignedData creates the canonical data that was signed.
func (s *Signer) createSignedData(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG) ([]byte, error) {
	if rrsig == nil {
		return nil, fmt.Errorf("nil RRSIG")
	}
	if rrsig.SignerName == nil {
		return nil, fmt.Errorf("nil RRSIG signer name")
	}

	// Build the RRSIG RDATA portion (without signature)
	// TypeCovered | Algorithm | Labels | OriginalTTL | Expiration | Inception | KeyTag | SignerName

	var data []byte

	// Type Covered (2 bytes)
	data = append(data, byte(rrsig.TypeCovered>>8), byte(rrsig.TypeCovered))

	// Algorithm (1 byte)
	data = append(data, rrsig.Algorithm)

	// Labels (1 byte)
	data = append(data, rrsig.Labels)

	// Original TTL (4 bytes)
	data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
		byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))

	// Expiration (4 bytes)
	data = append(data, byte(rrsig.Expiration>>24), byte(rrsig.Expiration>>16),
		byte(rrsig.Expiration>>8), byte(rrsig.Expiration))

	// Inception (4 bytes)
	data = append(data, byte(rrsig.Inception>>24), byte(rrsig.Inception>>16),
		byte(rrsig.Inception>>8), byte(rrsig.Inception))

	// Key Tag (2 bytes)
	data = append(data, byte(rrsig.KeyTag>>8), byte(rrsig.KeyTag))

	// Signer Name (wire format)
	signerData := rrsig.SignerName.CanonicalWire()
	data = append(data, signerData...)

	// Add canonical owner name for each RR in the set
	for _, rr := range rrSet {
		if rr == nil {
			return nil, fmt.Errorf("nil RR in RRSet")
		}
		if rr.Name == nil {
			return nil, fmt.Errorf("nil RR owner name")
		}
		if rr.Data == nil {
			return nil, fmt.Errorf("nil RDATA for %s type %d", rr.Name.String(), rr.Type)
		}

		ownerData := rr.Name.CanonicalWire()
		data = append(data, ownerData...)

		// Type (2 bytes)
		data = append(data, byte(rr.Type>>8), byte(rr.Type))

		// Class (2 bytes)
		data = append(data, byte(rr.Class>>8), byte(rr.Class))

		// TTL (4 bytes) - use original TTL from RRSIG
		data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
			byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))

		// RData length (2 bytes) and RData
		rdataLen := rr.Data.Len()
		if rdataLen > 0xffff {
			return nil, fmt.Errorf("RDATA for %s type %d too large: %d bytes (max 65535)", rr.Name.String(), rr.Type, rdataLen)
		}
		buf := make([]byte, rdataLen)
		n, err := rr.Data.Pack(buf, 0)
		if err != nil {
			return nil, fmt.Errorf("packing RDATA for %s type %d: %w", rr.Name.String(), rr.Type, err)
		}
		rdata := buf[:n]
		if len(rdata) > 0xffff {
			return nil, fmt.Errorf("RDATA for %s type %d too large: %d bytes (max 65535)", rr.Name.String(), rr.Type, len(rdata))
		}
		data = append(data, byte(len(rdata)>>8), byte(len(rdata)))
		data = append(data, rdata...)
	}

	return data, nil
}

// generateNSEC creates NSEC records for the zone.
func (s *Signer) generateNSEC(records []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	// Collect unique owner names and their types
	nameTypes := make(map[string]map[uint16]bool)

	for _, rr := range records {
		name := rr.Name.String()
		if nameTypes[name] == nil {
			nameTypes[name] = make(map[uint16]bool)
		}
		nameTypes[name][rr.Type] = true
	}

	// Get sorted list of names
	var names []string
	for name := range nameTypes {
		names = append(names, name)
	}
	sort.Strings(names)

	// Create NSEC chain
	var nsecRecords []*protocol.ResourceRecord

	for i, name := range names {
		// Next name in chain (wraps around)
		nextIndex := (i + 1) % len(names)
		nextName := names[nextIndex]

		// Collect types for this name
		var types []uint16
		for t := range nameTypes[name] {
			types = append(types, t)
		}

		// Add NSEC type
		types = append(types, protocol.TypeNSEC)
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

		// Create NSEC record
		owner, ownerErr := protocol.ParseName(name)
		if ownerErr != nil {
			continue
		}
		next, nextErr := protocol.ParseName(nextName)
		if nextErr != nil {
			continue
		}

		nsec := &protocol.RDataNSEC{
			NextDomain: next,
			TypeBitMap: types,
		}

		nsecRR := &protocol.ResourceRecord{
			Name:  owner,
			Type:  protocol.TypeNSEC,
			Class: protocol.ClassIN,
			TTL:   86400, // Standard TTL for NSEC
			Data:  nsec,
		}

		nsecRecords = append(nsecRecords, nsecRR)
	}

	return nsecRecords
}

// generateNSEC3 creates NSEC3 records for the zone.
// When NSEC3OptOut is enabled, delegation points without secure records
// use the opt-out flag per RFC 5155 Section 6.
func (s *Signer) generateNSEC3(records []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	// Collect unique owner names and their record types
	type nameInfo struct {
		original string
		hasNS    bool // delegation point (or apex) — has NS records
		hasSOA   bool // zone apex — never opt-out
		hasDS    bool // signed delegation — never opt-out
		hasOther bool // other records requiring authenticated denial
	}
	nameInfos := make(map[string]*nameInfo)

	for _, rr := range records {
		name := rr.Name.String()
		if nameInfos[name] == nil {
			nameInfos[name] = &nameInfo{original: name}
		}
		ni := nameInfos[name]

		switch rr.Type {
		case protocol.TypeNS:
			ni.hasNS = true
		case protocol.TypeSOA:
			ni.hasSOA = true
		case protocol.TypeDS:
			ni.hasDS = true
		case protocol.TypeNSEC3, protocol.TypeRRSIG:
			// Neither NSEC3 nor RRSIG indicates a secure delegation.
			// NSEC3 records live at hashed owner names, and RRSIGs cover
			// every RRset in a signed zone — including the delegation NS
			// RRset that the parent always signs. Counting RRSIG would
			// mark every delegation "secure" and opt-out would never
			// engage for unsigned children (RFC 5155 §6.1.1).
		default:
			// Any other record type means this is a secure delegation
			ni.hasOther = true
		}
	}

	// Calculate NSEC3 hashes for all names
	type hashedName struct {
		original  string
		hashed    string
		hashBytes []byte
		isOptOut  bool
	}

	var hashes []hashedName
	for name, ni := range nameInfos {
		// Determine if this name should use opt-out.
		// Opt-out applies to UNSIGNED delegations only (RFC 5155 §6.1.1):
		// delegation points (has NS) that are not the zone apex (no SOA)
		// and carry no DS record. The apex must never be opt-out, and a
		// delegation with a DS record proves a signed child — neither may
		// be skipped in the denial chain.
		isOptOut := s.config.NSEC3OptOut && ni.hasNS && !ni.hasSOA && !ni.hasDS && !ni.hasOther

		hash, err := NSEC3Hash(name, s.config.NSEC3Algorithm, s.config.NSEC3Iterations, s.config.NSEC3Salt)
		if err != nil {
			continue
		}
		hashes = append(hashes, hashedName{
			original:  name,
			hashed:    protocol.Base32Encode(hash),
			hashBytes: hash,
			isOptOut:  isOptOut,
		})
	}

	// Sort by hash
	sort.Slice(hashes, func(i, j int) bool {
		return hashes[i].hashed < hashes[j].hashed
	})

	// Create NSEC3 records
	var nsec3Records []*protocol.ResourceRecord

	for i, hn := range hashes {
		// Next hash in chain (wraps around)
		nextIndex := (i + 1) % len(hashes)
		nextHash := hashes[nextIndex].hashBytes

		// Get types for the original name
		var types []uint16

		if hn.isOptOut {
			// Opt-out: empty bitmap, proves no secure records in this range
			// The opt-out flag indicates there may be unsigned delegations
			types = nil
		} else {
			// Full proof: list all record types at this name. RRSIG is
			// present at the original owner name and stays in the bitmap;
			// the NSEC3 type MUST NOT be listed here — RFC 5155 §3.2.1:
			// "the NSEC3 type itself will never be present in the Type
			// Bit Maps" (NSEC3 records live at hashed owner names, not at
			// the original name).
			for _, rr := range records {
				if rr.Name.String() == hn.original {
					types = append(types, rr.Type)
				}
			}
			sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
		}

		// Set flags: bit 0 = opt-out
		flags := uint8(0)
		if hn.isOptOut {
			flags = protocol.NSEC3FlagOptOut
		}

		// Create NSEC3 record
		nsec3 := &protocol.RDataNSEC3{
			HashAlgorithm: s.config.NSEC3Algorithm,
			Flags:         flags,
			Iterations:    s.config.NSEC3Iterations,
			Salt:          s.config.NSEC3Salt,
			HashLength:    uint8(len(nextHash)),
			NextHashed:    nextHash,
			TypeBitMap:    types,
		}

		// Owner name is <hash>.<zone>
		ownerName := hn.hashed + "." + s.zone
		owner, ownerErr := protocol.ParseName(ownerName)
		if ownerErr != nil {
			continue
		}

		nsec3RR := &protocol.ResourceRecord{
			Name:  owner,
			Type:  protocol.TypeNSEC3,
			Class: protocol.ClassIN,
			TTL:   86400,
			Data:  nsec3,
		}

		nsec3Records = append(nsec3Records, nsec3RR)
	}

	return nsec3Records
}

// CreateDS creates a DS record for a DNSKEY.
func CreateDS(zone string, dnskey *protocol.RDataDNSKEY, digestType uint8) (*TrustAnchor, error) {
	return DSFromDNSKEY(zone, dnskey, digestType)
}
