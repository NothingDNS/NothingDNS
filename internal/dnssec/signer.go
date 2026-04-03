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
}

// SignerConfig holds signing parameters.
type SignerConfig struct {
	NSEC3Enabled        bool
	NSEC3Algorithm      uint8
	NSEC3Iterations     uint16
	NSEC3Salt           []byte
	SignatureValidity   time.Duration
	InceptionOffset     time.Duration
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
		result = append(result, key)
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
			result = append(result, key)
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
			result = append(result, key)
		}
	}
	return result
}

// GenerateKeyPair generates a new key pair for the zone.
func (s *Signer) GenerateKeyPair(algorithm uint8, isKSK bool) (*SigningKey, error) {
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

	s.AddKey(signingKey)
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
	inception := uint32(now.Add(-s.config.InceptionOffset).Unix())
	expiration := uint32(now.Add(s.config.SignatureValidity).Unix())

	// Sign DNSKEY RRSet with KSK
	ksks := s.GetKSKs()
	if len(ksks) == 0 {
		return nil, fmt.Errorf("no KSK available for signing DNSKEY")
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

	// Sign each RRSet with ZSK
	zsks := s.GetZSKs()
	if len(zsks) == 0 {
		// Use KSK as fallback
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
	if len(rrSet) == 0 {
		return nil, fmt.Errorf("cannot sign empty RRSet")
	}

	// Sort records canonically
	sorted := make([]*protocol.ResourceRecord, len(rrSet))
	copy(sorted, rrSet)
	canonicalSort(sorted)

	// Get owner name and type from first record
	ownerName := sorted[0].Name.String()
	rrtype := sorted[0].Type
	ttl := sorted[0].TTL

	// Count labels
	labels := uint8(len(splitLabels(ownerName)))

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

// createSignedData creates the canonical data that was signed.
func (s *Signer) createSignedData(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG) ([]byte, error) {
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
	signerData := protocol.CanonicalWireName(rrsig.SignerName.String())
	data = append(data, signerData...)

	// Add canonical owner name for each RR in the set
	for _, rr := range rrSet {
		ownerData := protocol.CanonicalWireName(rr.Name.String())
		data = append(data, ownerData...)

		// Type (2 bytes)
		data = append(data, byte(rr.Type>>8), byte(rr.Type))

		// Class (2 bytes)
		data = append(data, byte(rr.Class>>8), byte(rr.Class))

		// TTL (4 bytes) - use original TTL from RRSIG
		data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
			byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))

		// RData length (2 bytes) and RData
		buf := make([]byte, rr.Data.Len())
		n, err := rr.Data.Pack(buf, 0)
		if err != nil {
			return nil, fmt.Errorf("packing RDATA for %s type %d: %w", rr.Name.String(), rr.Type, err)
		}
		rdata := buf[:n]
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
func (s *Signer) generateNSEC3(records []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	// Collect unique owner names
	uniqueNames := make(map[string]bool)
	for _, rr := range records {
		uniqueNames[rr.Name.String()] = true
	}

	// Calculate NSEC3 hashes for all names
	type hashedName struct {
		original string
		hashed   string
		hashBytes []byte
	}

	var hashes []hashedName
	for name := range uniqueNames {
		hash, err := NSEC3Hash(name, s.config.NSEC3Algorithm, s.config.NSEC3Iterations, s.config.NSEC3Salt)
		if err != nil {
			continue
		}
		hashes = append(hashes, hashedName{
			original: name,
			hashed:   protocol.Base32Encode(hash),
			hashBytes: hash,
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
		for _, rr := range records {
			if rr.Name.String() == hn.original {
				types = append(types, rr.Type)
			}
		}
		types = append(types, protocol.TypeNSEC3)
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

		// Create NSEC3 record
		nsec3 := &protocol.RDataNSEC3{
			HashAlgorithm: s.config.NSEC3Algorithm,
			Flags:         0,
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

