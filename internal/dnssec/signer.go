package dnssec

import (
	"fmt"
	"sort"
	"strings"
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
	return s.generateKeyPairWithState(algorithm, isKSK, KeyStateCreated, nil)
}

// generateKeyPairWithState generates a key and adds it to the signer with its
// rollover state and timing already set, so no reader ever observes it with
// Timing == nil — which isActive treats as "always active" (F242).
func (s *Signer) generateKeyPairWithState(algorithm uint8, isKSK bool, state KeyState, timing *KeyTiming) (*SigningKey, error) {
	const maxKeyTagAttempts = 16

	for attempt := 0; attempt < maxKeyTagAttempts; attempt++ {
		key, err := s.generateKeyPairOnce(algorithm, isKSK)
		if err != nil {
			return nil, err
		}
		if key.KeyTag != 0 {
			key.State = state
			key.Timing = timing
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

// DNSKEYRRSet returns the zone's DNSKEY RRset, one record per loaded key.
//
// SignZone already synthesised these when signing a whole zone, but nothing
// published them on the query path: a zone signed from configured keys served
// RRSIGs whose keys no resolver could fetch, so every validator saw the zone
// as Bogus. Serving the RRset is what makes a signed zone validatable.
//
// Every loaded key is published, including Pre-Published and Retired ones —
// that is the point of pre-publication during a rollover (RFC 7583); only
// *signing* is restricted to active keys.
func (s *Signer) DNSKEYRRSet(ttl uint32) ([]*protocol.ResourceRecord, error) {
	name, err := protocol.ParseName(s.zone)
	if err != nil {
		return nil, fmt.Errorf("parsing zone name %q: %w", s.zone, err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	rrs := make([]*protocol.ResourceRecord, 0, len(s.keys))
	for _, key := range s.keys {
		if key == nil || key.DNSKEY == nil {
			continue
		}
		rrs = append(rrs, &protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeDNSKEY,
			Class: protocol.ClassIN,
			TTL:   ttl,
			Data:  key.DNSKEY,
		})
	}
	return rrs, nil
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

	// Delegation points and the names below them (F459, RFC 4035 §2.2): the
	// parent is authoritative only for the DS RRset at a cut. The delegation
	// NS RRset and glue are published unsigned, otherwise a validator accepts
	// the parent's copy of child data — e.g. glue for a name inside an
	// unsigned child zone validated as Secure.
	cuts := s.zoneCuts(otherRRs)

	for _, rrSet := range groups {
		// Add the records
		signedRecords = append(signedRecords, rrSet...)

		if !s.authoritativeRRSet(rrSet[0].Name.String(), rrSet[0].Type, cuts) {
			continue
		}

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
	// Only authoritative data enters the chain (RFC 4035 §2.3, RFC 5155
	// §7.1): no glue owners below a cut, and a cut's bitmap shows only the
	// NS, DS and RRSIG types it really has.
	var chainRecords []*protocol.ResourceRecord
	for _, rr := range signedRecords {
		name := rr.Name.String()
		if rr.Type == protocol.TypeNS || rr.Type == protocol.TypeRRSIG || s.authoritativeRRSet(name, rr.Type, cuts) {
			if !belowZoneCut(name, cuts) {
				chainRecords = append(chainRecords, rr)
			}
		}
	}

	var denialRecords []*protocol.ResourceRecord
	if s.config.NSEC3Enabled {
		denialRecords = s.generateNSEC3(chainRecords)
	} else {
		denialRecords = s.generateNSEC(chainRecords)
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

// zoneCuts returns the delegation points among records: owners other than
// the zone apex that carry an NS RRset.
func (s *Signer) zoneCuts(records []*protocol.ResourceRecord) []string {
	seen := make(map[string]bool)
	var cuts []string
	for _, rr := range records {
		if rr == nil || rr.Name == nil || rr.Type != protocol.TypeNS {
			continue
		}
		name := strings.ToLower(rr.Name.String())
		if sameDNSName(name, s.zone) || seen[name] {
			continue
		}
		seen[name] = true
		cuts = append(cuts, name)
	}
	return cuts
}

// belowZoneCut reports whether name lies strictly below one of cuts (glue or
// occluded data the parent is not authoritative for).
func belowZoneCut(name string, cuts []string) bool {
	for _, cut := range cuts {
		if !sameDNSName(name, cut) && inBailiwick(name, cut) {
			return true
		}
	}
	return false
}

// authoritativeRRSet reports whether the zone is authoritative for (and so
// signs) the RRset owner/rrtype: everything except data below a cut and,
// at a cut, everything but the DS RRset (RFC 4035 §2.2).
func (s *Signer) authoritativeRRSet(owner string, rrtype uint16, cuts []string) bool {
	if belowZoneCut(owner, cuts) {
		return false
	}
	for _, cut := range cuts {
		if sameDNSName(owner, cut) {
			return rrtype == protocol.TypeDS
		}
	}
	return true
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

	// Count labels. RFC 4034 §3.1.3: the Labels field does not count the
	// leftmost label when it is a wildcard, because a validator reconstructs a
	// wildcard-expanded owner as "*." plus the rightmost Labels labels of the
	// queried name (RFC 4035 §5.3.2). Counting the wildcard label emitted
	// Labels=3 for `*.example.com.`, so a validator rebuilt the owner as
	// "*.foo.example.com." — not the name that was signed — and every
	// wildcard-expanded answer from this signer was Bogus.
	labelCount := len(splitLabels(ownerName))
	if strings.HasPrefix(ownerName, "*.") {
		labelCount--
	}
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
// emptyNonTerminals returns the names in this zone that exist only as empty
// non-terminals: names with descendants but no records of their own.
//
// The denial chain must cover them. RFC 4035 §3.1.3.1 proves a NODATA answer
// with a denial record AT the queried name, and this server answers NODATA for
// an empty non-terminal rather than NXDOMAIN (Zone.NodeExists, used by
// cmd/nothingdns/authoritative.go); RFC 5155 §8.5 needs the NSEC3 whose owner
// hash matches the QNAME. A chain built only from the owner names present in
// the record list leaves every empty non-terminal unprovable, so a validating
// resolver rejects the negative answer it is served.
//
// Names are returned in the presentation form of the owner they were derived
// from, matching how the chain generators key their maps.
func (s *Signer) emptyNonTerminals(records []*protocol.ResourceRecord) []string {
	apex := strings.ToLower(s.zone)
	seen := make(map[string]struct{})
	var out []string

	for _, rr := range records {
		if rr == nil || rr.Name == nil {
			continue
		}
		name := rr.Name.String()
		for {
			idx := strings.IndexByte(name, '.')
			if idx < 0 || idx+1 >= len(name) {
				break
			}
			name = name[idx+1:]
			if strings.EqualFold(name, apex) || !strings.HasSuffix(strings.ToLower(name), "."+apex) {
				break
			}
			if _, dup := seen[name]; dup {
				// The rest of this chain was walked already.
				break
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}
	return out
}

// denialTTL returns the TTL for the zone's NSEC/NSEC3 records: the lesser of
// the apex SOA's MINIMUM field and the SOA's own TTL (RFC 9077 §3, updating
// RFC 4034 §4 and RFC 5155 §3). A fixed 86400 let resolvers doing aggressive
// NSEC caching (RFC 8198) deny newly added names for a day (F248). Without an
// apex SOA in records the historical 86400 is kept.
func (s *Signer) denialTTL(records []*protocol.ResourceRecord) uint32 {
	for _, rr := range records {
		if rr == nil || rr.Name == nil || rr.Type != protocol.TypeSOA || !sameDNSName(rr.Name.String(), s.zone) {
			continue
		}
		if soa, ok := rr.Data.(*protocol.RDataSOA); ok {
			if soa.Minimum < rr.TTL {
				return soa.Minimum
			}
			return rr.TTL
		}
	}
	return 86400
}

func (s *Signer) generateNSEC(records []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	// Collect unique owner names and their types. Empty non-terminals own no
	// records, so they are seeded separately — a NODATA answer for one of them
	// needs an NSEC at the name itself.
	nameTypes := make(map[string]map[uint16]bool)

	for _, name := range s.emptyNonTerminals(records) {
		nameTypes[name] = make(map[uint16]bool)
	}

	for _, rr := range records {
		name := rr.Name.String()
		if nameTypes[name] == nil {
			nameTypes[name] = make(map[uint16]bool)
		}
		nameTypes[name][rr.Type] = true
	}

	// Get sorted list of names — in RFC 4034 §6.1 canonical order
	// (rightmost label first, labels as case-folded octet strings), the same
	// order the validator's nameInRange uses (F77). Neither presentation
	// sort.Strings nor a whole-wire-name byte compare produces it.
	names := make([]string, 0, len(nameTypes))
	for name := range nameTypes {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return canonicalNameCompare(names[i], names[j]) < 0
	})

	// Create NSEC chain
	var nsecRecords []*protocol.ResourceRecord
	ttl := s.denialTTL(records)

	for i, name := range names {
		// Next name in chain (wraps around)
		nextIndex := (i + 1) % len(names)
		nextName := names[nextIndex]

		// Collect types for this name
		var types []uint16
		for t := range nameTypes[name] {
			types = append(types, t)
		}

		// Add NSEC type, and RRSIG: the NSEC RRset itself is signed, so the
		// owner always has an RRSIG — also at an unsigned delegation, whose
		// NS RRset is not signed (F459, RFC 4035 §2.3).
		if !nameTypes[name][protocol.TypeRRSIG] {
			types = append(types, protocol.TypeRRSIG)
		}
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
			TTL:   ttl,
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

	// Empty non-terminals own no records, so seed them explicitly: a NODATA
	// answer for one of them needs the NSEC3 whose owner hash matches its name
	// (RFC 5155 §8.5), and without an entry here the chain omits it entirely.
	for _, name := range s.emptyNonTerminals(records) {
		nameInfos[name] = &nameInfo{original: name}
	}

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
			// NSEC3 records live at hashed owner names, and at a cut an
			// RRSIG covers only the DS RRset (SignZone no longer signs the
			// delegation NS, F459) or comes from a caller passing an
			// already-signed zone. Counting RRSIG would mark such
			// delegations "secure" and opt-out would never engage for
			// unsigned children (RFC 5155 §6.1.1).
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
	ttl := s.denialTTL(records)

	for i, hn := range hashes {
		// Next hash in chain (wraps around)
		nextIndex := (i + 1) % len(hashes)
		nextHash := hashes[nextIndex].hashBytes

		// List all record types at this name. RRSIG is present at the
		// original owner name and stays in the bitmap; the NSEC3 type MUST
		// NOT be listed here — RFC 5155 §3.2.1: "the NSEC3 type itself will
		// never be present in the Type Bit Maps" (NSEC3 records live at
		// hashed owner names, not at the original name).
		//
		// An Opt-Out unsigned delegation keeps its real bitmap too (F247):
		// RFC 5155 §8.9 accepts a matching NSEC3 as proof of an insecure
		// delegation only with NS set and DS/SOA clear. An empty bitmap
		// claimed "exists, not a zone cut", so validators treated the
		// unsigned child as Bogus.
		var types []uint16
		for _, rr := range records {
			if rr.Name.String() == hn.original {
				types = append(types, rr.Type)
			}
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

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
			TTL:   ttl,
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
