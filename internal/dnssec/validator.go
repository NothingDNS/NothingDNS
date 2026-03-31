package dnssec

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ValidationResult represents the outcome of DNSSEC validation.
type ValidationResult int

const (
	// ValidationSecure indicates the response passed DNSSEC validation.
	ValidationSecure ValidationResult = iota
	// ValidationInsecure indicates the zone is not signed or no DNSSEC info available.
	ValidationInsecure
	// ValidationBogus indicates DNSSEC validation failed (bad signature, expired, etc).
	ValidationBogus
	// ValidationIndeterminate indicates the validator couldn't determine the status.
	ValidationIndeterminate
)

func (r ValidationResult) String() string {
	switch r {
	case ValidationSecure:
		return "SECURE"
	case ValidationInsecure:
		return "INSECURE"
	case ValidationBogus:
		return "BOGUS"
	case ValidationIndeterminate:
		return "INDETERMINATE"
	default:
		return "UNKNOWN"
	}
}

// Resolver interface for fetching DNS records during validation.
type Resolver interface {
	// Query sends a DNS query and returns the response.
	Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error)
}

// ValidatorConfig holds validation settings.
type ValidatorConfig struct {
	// Enabled enables DNSSEC validation.
	Enabled bool

	// RequireDNSSEC fails validation if DNSSEC info unavailable.
	RequireDNSSEC bool

	// IgnoreTime ignores signature timestamps (for testing).
	IgnoreTime bool

	// MaxDelegationDepth limits chain validation depth.
	MaxDelegationDepth int

	// ClockSkew allows for time difference between systems.
	ClockSkew time.Duration
}

// DefaultValidatorConfig returns recommended validation settings.
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		Enabled:            true,
		RequireDNSSEC:      false,
		IgnoreTime:         false,
		MaxDelegationDepth: 20,
		ClockSkew:          5 * time.Minute,
	}
}

// Validator performs DNSSEC validation.
type Validator struct {
	config       ValidatorConfig
	trustAnchors *TrustAnchorStore
	resolver     Resolver
}

// NewValidator creates a new DNSSEC validator.
func NewValidator(config ValidatorConfig, anchors *TrustAnchorStore, resolver Resolver) *Validator {
	if anchors == nil {
		anchors = NewTrustAnchorStoreWithBuiltIn()
	}
	if config.MaxDelegationDepth == 0 {
		config.MaxDelegationDepth = 20
	}
	if config.ClockSkew == 0 {
		config.ClockSkew = 5 * time.Minute
	}

	return &Validator{
		config:       config,
		trustAnchors: anchors,
		resolver:     resolver,
	}
}

// ValidateResponse validates a DNS response message.
func (v *Validator) ValidateResponse(ctx context.Context, msg *protocol.Message, queryName string) (ValidationResult, error) {
	if !v.config.Enabled {
		return ValidationInsecure, nil
	}

	if msg == nil {
		return ValidationBogus, fmt.Errorf("nil message")
	}

	// Find closest trust anchor
	anchor, remaining := v.trustAnchors.FindClosestAnchor(queryName)
	if anchor == nil {
		if v.config.RequireDNSSEC {
			return ValidationBogus, fmt.Errorf("no trust anchor found for %s", queryName)
		}
		return ValidationInsecure, nil
	}

	// Build validation chain from anchor to query name
	chain, err := v.buildChain(ctx, anchor, remaining)
	if err != nil {
		return ValidationBogus, fmt.Errorf("building validation chain: %w", err)
	}

	// Validate the answer
	result := v.validateMessage(ctx, msg, queryName, chain)
	return result, nil
}

// chainLink represents one link in the validation chain.
type chainLink struct {
	zone      string
	dnsKeys   []*protocol.ResourceRecord
	dsRecords []*protocol.ResourceRecord
	validated bool
}

// buildChain builds a validation chain from trust anchor to target.
func (v *Validator) buildChain(ctx context.Context, anchor *TrustAnchor, remaining []string) ([]*chainLink, error) {
	chain := []*chainLink{}

	// Start with trust anchor zone
	currentZone := anchor.Zone

	// Fetch DNSKEY for trust anchor zone and validate
	dnsKeys, err := v.fetchDNSKEY(ctx, currentZone)
	if err != nil {
		return nil, fmt.Errorf("fetching DNSKEY for %s: %w", currentZone, err)
	}

	// Validate at least one DNSKEY matches the trust anchor
	if !v.validateTrustAnchor(anchor, dnsKeys) {
		return nil, fmt.Errorf("trust anchor validation failed for %s", currentZone)
	}

	chain = append(chain, &chainLink{
		zone:      currentZone,
		dnsKeys:   dnsKeys,
		dsRecords: nil,
		validated: true,
	})

	// Build chain through remaining labels
	for i := 0; i < len(remaining); i++ {
		childLabels := remaining[i:]
		childZone := joinLabels(childLabels)

		// Check depth limit
		if len(chain) >= v.config.MaxDelegationDepth {
			return nil, fmt.Errorf("max delegation depth exceeded")
		}

		// Fetch DS records for child zone
		dsRecords, err := v.fetchDS(ctx, childZone)
		if err != nil {
			return nil, fmt.Errorf("fetching DS for %s: %w", childZone, err)
		}

		if len(dsRecords) == 0 {
			// Unsigned delegation - chain ends here
			break
		}

		// Fetch DNSKEY for child zone
		childKeys, err := v.fetchDNSKEY(ctx, childZone)
		if err != nil {
			return nil, fmt.Errorf("fetching DNSKEY for %s: %w", childZone, err)
		}

		// Validate DS records against parent keys
		if !v.validateDelegation(chain[len(chain)-1], dsRecords, childKeys) {
			return nil, fmt.Errorf("delegation validation failed for %s", childZone)
		}

		chain = append(chain, &chainLink{
			zone:      childZone,
			dnsKeys:   childKeys,
			dsRecords: dsRecords,
			validated: true,
		})

		currentZone = childZone
	}

	return chain, nil
}

// validateTrustAnchor checks if DNSKEY records match the trust anchor.
func (v *Validator) validateTrustAnchor(anchor *TrustAnchor, dnsKeys []*protocol.ResourceRecord) bool {
	for _, rr := range dnsKeys {
		dnskey, ok := rr.Data.(*protocol.RDataDNSKEY)
		if !ok {
			continue
		}

		keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
		if anchor.KeyTag != keyTag {
			continue
		}
		if anchor.Algorithm != dnskey.Algorithm {
			continue
		}

		// If anchor has digest, verify it matches DS computation
		if len(anchor.Digest) > 0 {
			digest := calculateDSDigestFromDNSKEY(rr.Name.String(), dnskey, anchor.DigestType)
			if bytesEqual(digest, anchor.Digest) {
				return true
			}
		}

		// If anchor has public key, compare directly
		if len(anchor.PublicKey) > 0 && bytesEqual(anchor.PublicKey, dnskey.PublicKey) {
			return true
		}
	}

	return false
}

// validateDelegation validates a delegation using DS/DNSKEY.
func (v *Validator) validateDelegation(parent *chainLink, dsRecords, childKeys []*protocol.ResourceRecord) bool {
	for _, dsRR := range dsRecords {
		ds, ok := dsRR.Data.(*protocol.RDataDS)
		if !ok {
			continue
		}

		for _, keyRR := range childKeys {
			dnskey, ok := keyRR.Data.(*protocol.RDataDNSKEY)
			if !ok {
				continue
			}

			// Check if DNSKEY matches DS
			keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
			if ds.KeyTag != keyTag {
				continue
			}
			if ds.Algorithm != dnskey.Algorithm {
				continue
			}

			// Verify DS digest
			digest := calculateDSDigestFromDNSKEY(keyRR.Name.String(), dnskey, ds.DigestType)
			if bytesEqual(digest, ds.Digest) {
				return true
			}
		}
	}

	return false
}

// validateMessage validates the DNS response message.
func (v *Validator) validateMessage(ctx context.Context, msg *protocol.Message, queryName string, chain []*chainLink) ValidationResult {
	if len(chain) == 0 {
		return ValidationBogus
	}

	// Get the zone that should have signed this response
	zoneLink := chain[len(chain)-1]

	// Group answers by name and type
	answerGroups := groupRecordsByRRSet(msg.Answers)

	// Validate each answer RRSet
	for _, rrSet := range answerGroups {
		if len(rrSet) == 0 {
			continue
		}

		// Find matching RRSIG
		rrsig := v.findRRSIG(msg.Answers, rrSet[0].Name.String(), rrSet[0].Type)
		if rrsig == nil {
			// No signature for this RRSet
			if v.config.RequireDNSSEC {
				return ValidationBogus
			}
			continue
		}

		// Validate the signature
		if !v.validateRRSIG(rrSet, rrsig, zoneLink.dnsKeys) {
			return ValidationBogus
		}
	}

	// Validate negative response if applicable
	if len(msg.Answers) == 0 {
		result := v.validateNegativeResponse(msg, queryName, chain)
		if result == ValidationBogus {
			return ValidationBogus
		}
	}

	return ValidationSecure
}

// findRRSIG finds an RRSIG record for the given name and type.
func (v *Validator) findRRSIG(answers []*protocol.ResourceRecord, name string, rrtype uint16) *protocol.RDataRRSIG {
	for _, rr := range answers {
		if rr.Type != protocol.TypeRRSIG {
			continue
		}
		rrsig, ok := rr.Data.(*protocol.RDataRRSIG)
		if !ok {
			continue
		}
		if rrsig.TypeCovered == rrtype && rr.Name.String() == name {
			return rrsig
		}
	}
	return nil
}

// validateRRSIG validates an RRSIG over an RRSet.
func (v *Validator) validateRRSIG(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG, dnsKeys []*protocol.ResourceRecord) bool {
	// Check signature timestamps
	if !v.config.IgnoreTime {
		now := uint32(time.Now().Unix())
		if rrsig.Expiration < now {
			return false // Signature expired
		}
		if rrsig.Inception > now {
			return false // Signature not yet valid
		}
	}

	// Find matching DNSKEY
	var matchingKey *protocol.RDataDNSKEY
	for _, rr := range dnsKeys {
		dnskey, ok := rr.Data.(*protocol.RDataDNSKEY)
		if !ok {
			continue
		}
		keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
		if keyTag == rrsig.KeyTag && dnskey.Algorithm == rrsig.Algorithm {
			matchingKey = dnskey
			break
		}
	}

	if matchingKey == nil {
		return false
	}

	// Parse the public key
	pubKey, err := ParseDNSKEYPublicKey(matchingKey.Algorithm, matchingKey.PublicKey)
	if err != nil {
		return false
	}

	// Create canonical signed data
	signedData := v.canonicalizeRRSet(rrSet, rrsig)

	// Verify signature
	err = VerifySignature(rrsig, signedData, pubKey)
	return err == nil
}

// canonicalizeRRSet creates the canonical data that was signed.
func (v *Validator) canonicalizeRRSet(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG) []byte {
	// Sort records canonically
	sorted := make([]*protocol.ResourceRecord, len(rrSet))
	copy(sorted, rrSet)
	canonicalSort(sorted)

	// Concatenate all RRs in canonical order
	var result []byte
	for _, rr := range sorted {
		// Create canonical wire format representation
		canonical := v.canonicalizeRR(rr, rrsig.OriginalTTL)
		result = append(result, canonical...)
	}

	return result
}

// canonicalizeRR creates a canonical wire format representation of a record.
// Per RFC 4034 Section 6, canonical form includes:
// - Owner name in lowercase wire format (no compression)
// - Type (2 bytes, big-endian)
// - Class (2 bytes, big-endian)
// - TTL (4 bytes, big-endian) - from RRSIG's OriginalTTL
// - RDATA in canonical form
func (v *Validator) canonicalizeRR(rr *protocol.ResourceRecord, ttl uint32) []byte {
	// Estimate buffer size: max name (255) + type (2) + class (2) + ttl (4) + rdata
	buf := make([]byte, 0, 512)

	// 1. Canonical owner name (lowercase, wire format, no compression)
	// Each label: 1 byte length + label data (lowercase)
	name := rr.Name.String()
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, label := range labels {
		if label == "" {
			continue // Skip empty labels (root)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, toLowerBytes(label)...)
	}
	buf = append(buf, 0) // Root label terminator

	// 2. Type (2 bytes, big-endian)
	typeBytes := make([]byte, 2)
	protocol.PutUint16(typeBytes, rr.Type)
	buf = append(buf, typeBytes...)

	// 3. Class (2 bytes, big-endian)
	classBytes := make([]byte, 2)
	protocol.PutUint16(classBytes, rr.Class)
	buf = append(buf, classBytes...)

	// 4. TTL (4 bytes, big-endian) - use the TTL from RRSIG
	ttlBytes := make([]byte, 4)
	protocol.PutUint32(ttlBytes, ttl)
	buf = append(buf, ttlBytes...)

	// 5. RDATA length (2 bytes, big-endian)
	rdataLen := rr.Data.Len()
	rdatalenBytes := make([]byte, 2)
	protocol.PutUint16(rdatalenBytes, uint16(rdataLen))
	buf = append(buf, rdatalenBytes...)

	// 6. RDATA (packed)
	if rdataLen > 0 {
		rdataBuf := make([]byte, rdataLen)
		n, err := rr.Data.Pack(rdataBuf, 0)
		if err == nil && n > 0 {
			buf = append(buf, rdataBuf[:n]...)
		}
	}

	return buf
}

// toLowerBytes converts a string to lowercase bytes.
func toLowerBytes(s string) []byte {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return result
}

// canonicalSort sorts records in canonical order for signing.
func canonicalSort(rrs []*protocol.ResourceRecord) {
	// Simplified: sort by name then type then RDATA
	// Full implementation per RFC 4034 Section 6.3
	sort.Slice(rrs, func(i, j int) bool {
		// Compare names (canonical = lowercase)
		nameI := toLower(rrs[i].Name.String())
		nameJ := toLower(rrs[j].Name.String())
		if nameI != nameJ {
			return nameI < nameJ
		}

		// Compare types
		if rrs[i].Type != rrs[j].Type {
			return rrs[i].Type < rrs[j].Type
		}

		// Compare RDATA (packed)
		bufI := make([]byte, 65535)
		nI, errI := rrs[i].Data.Pack(bufI, 0)
		if errI != nil {
			return false
		}
		rdataI := bufI[:nI]

		bufJ := make([]byte, 65535)
		nJ, errJ := rrs[j].Data.Pack(bufJ, 0)
		if errJ != nil {
			return true
		}
		rdataJ := bufJ[:nJ]

		return string(rdataI) < string(rdataJ)
	})
}

// validateNegativeResponse validates NSEC/NSEC3 for negative answers.
func (v *Validator) validateNegativeResponse(msg *protocol.Message, queryName string, chain []*chainLink) ValidationResult {
	if len(msg.Questions) == 0 {
		return ValidationBogus
	}
	qtype := msg.Questions[0].QType

	// Check for NSEC records
	for _, rr := range msg.Authorities {
		if rr.Type == protocol.TypeNSEC {
			nsec, ok := rr.Data.(*protocol.RDataNSEC)
			if !ok {
				continue
			}
			if v.validateNSEC(rr.Name.String(), queryName, qtype, nsec) {
				return ValidationSecure
			}
		}
		if rr.Type == protocol.TypeNSEC3 {
			nsec3, ok := rr.Data.(*protocol.RDataNSEC3)
			if !ok {
				continue
			}
			if v.validateNSEC3(rr.Name.String(), queryName, qtype, nsec3, chain) {
				return ValidationSecure
			}
		}
	}

	return ValidationBogus
}

// validateNSEC validates an NSEC record for authenticated denial.
func (v *Validator) validateNSEC(owner, queryName string, qtype uint16, nsec *protocol.RDataNSEC) bool {
	// NSEC proves that the queried name doesn't exist or the type doesn't exist
	// Owner < queryName < NextDomain

	// Check if query name is in the gap
	if !nameInRange(queryName, owner, nsec.NextDomain.String()) {
		return false
	}

	// If it's an exact match, check type bitmap
	if owner == queryName {
		// Type should not be in the bitmap
		if nsec.HasType(qtype) {
			return false
		}
	}

	return true
}

// validateNSEC3 validates an NSEC3 record for authenticated denial.
func (v *Validator) validateNSEC3(owner, queryName string, qtype uint16, nsec3 *protocol.RDataNSEC3, chain []*chainLink) bool {
	// Get NSEC3 parameters from chain
	if len(chain) == 0 {
		return false
	}

	// Hash the query name
	hashedName, err := NSEC3Hash(queryName, nsec3.HashAlgorithm, nsec3.Iterations, nsec3.Salt)
	if err != nil {
		return false
	}

	hashedNameStr := protocol.Base32Encode(hashedName)
	ownerHash := extractNSEC3Hash(owner)

	// Check if hashed query name falls in the range
	if !nameInRange(hashedNameStr, ownerHash, protocol.Base32Encode(nsec3.NextHashed)) {
		return false
	}

	return true
}

// extractNSEC3Hash extracts the hash portion from an NSEC3 owner name.
func extractNSEC3Hash(owner string) string {
	// NSEC3 owner format: <hash>.<zone>
	// Extract just the hash part
	labels := splitLabels(owner)
	if len(labels) == 0 {
		return ""
	}
	return labels[0]
}

// nameInRange checks if a name falls between owner and next (in canonical order).
// It handles both the normal case and NSEC wrap-around where the last record
// in the zone has a next domain name that is lexicographically before the owner,
// meaning the range covers names from owner to the end of the zone AND from the
// beginning of the zone up to next.
func nameInRange(name, owner, next string) bool {
	if owner < next {
		// Normal case: name must be strictly between owner and next
		return name > owner && name < next
	}
	if owner > next {
		// Wrap-around case: name is in range if it is after owner OR before next
		return name > owner || name < next
	}
	// owner == next: single NSEC covering entire zone; any name except owner is in range
	return name != owner
}

// groupRecordsByRRSet groups records by name and type.
func groupRecordsByRRSet(records []*protocol.ResourceRecord) map[string][]*protocol.ResourceRecord {
	groups := make(map[string][]*protocol.ResourceRecord)
	for _, rr := range records {
		if rr.Type == protocol.TypeRRSIG {
			continue // Don't include RRSIGs in RRSet
		}
		key := rr.Name.String() + "|" + strconv.Itoa(int(rr.Type))
		groups[key] = append(groups[key], rr)
	}
	return groups
}

// fetchDNSKEY fetches DNSKEY records for a zone.
func (v *Validator) fetchDNSKEY(ctx context.Context, zone string) ([]*protocol.ResourceRecord, error) {
	if v.resolver == nil {
		return nil, fmt.Errorf("no resolver configured")
	}

	msg, err := v.resolver.Query(ctx, zone, protocol.TypeDNSKEY)
	if err != nil {
		return nil, err
	}

	var keys []*protocol.ResourceRecord
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeDNSKEY {
			keys = append(keys, rr)
		}
	}

	return keys, nil
}

// fetchDS fetches DS records for a delegation.
func (v *Validator) fetchDS(ctx context.Context, zone string) ([]*protocol.ResourceRecord, error) {
	if v.resolver == nil {
		return nil, fmt.Errorf("no resolver configured")
	}

	msg, err := v.resolver.Query(ctx, zone, protocol.TypeDS)
	if err != nil {
		return nil, err
	}

	var dsRecords []*protocol.ResourceRecord
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeDS {
			dsRecords = append(dsRecords, rr)
		}
	}

	return dsRecords, nil
}

// calculateDSDigestFromDNSKEY computes the DS digest for a DNSKEY.
// Per RFC 4034 Section 5:
//   digest = hash(canonical_owner_name | DNSKEY_RDATA)
// Where DNSKEY_RDATA = flags | protocol | algorithm | public_key
func calculateDSDigestFromDNSKEY(zone string, dnskey *protocol.RDataDNSKEY, digestType uint8) []byte {
	// Create the data to be hashed: canonical owner name + DNSKEY RDATA
	var data []byte

	// 1. Canonical owner name (lowercase, wire format)
	name := zone
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" {
			continue
		}
		data = append(data, byte(len(label)))
		data = append(data, toLowerBytes(label)...)
	}
	data = append(data, 0) // Root label terminator

	// 2. DNSKEY RDATA: flags (2) | protocol (1) | algorithm (1) | public_key
	flagsBytes := make([]byte, 2)
	protocol.PutUint16(flagsBytes, dnskey.Flags)
	data = append(data, flagsBytes...)
	data = append(data, dnskey.Protocol)
	data = append(data, dnskey.Algorithm)
	data = append(data, dnskey.PublicKey...)

	// Hash the data based on digest type
	switch digestType {
	case 1: // SHA-1 (NOT RECOMMENDED but supported for compatibility)
		h := sha1.New()
		h.Write(data)
		return h.Sum(nil)
	case 2: // SHA-256 (MUST implement per RFC 8624)
		h := sha256.New()
		h.Write(data)
		return h.Sum(nil)
	case 4: // SHA-384 (MAY implement per RFC 8624)
		h := sha512.New384()
		h.Write(data)
		return h.Sum(nil)
	default:
		return nil
	}
}

// HasSignature checks if a message contains DNSSEC signatures.
func HasSignature(msg *protocol.Message) bool {
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeRRSIG {
			return true
		}
	}
	for _, rr := range msg.Authorities {
		if rr.Type == protocol.TypeRRSIG || rr.Type == protocol.TypeNSEC || rr.Type == protocol.TypeNSEC3 {
			return true
		}
	}
	return false
}

// ExtractRRSIGs extracts RRSIG records for a specific type.
func ExtractRRSIGs(msg *protocol.Message, rrtype uint16) []*protocol.RDataRRSIG {
	var rrsigs []*protocol.RDataRRSIG
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeRRSIG {
			if rrsig, ok := rr.Data.(*protocol.RDataRRSIG); ok && rrsig.TypeCovered == rrtype {
				rrsigs = append(rrsigs, rrsig)
			}
		}
	}
	return rrsigs
}
