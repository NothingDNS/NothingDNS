package dnssec

import (
	"crypto/sha1" // #nosec G505 - Required for legacy DS digest support
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"hash"
	"os"
	"sync"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// TrustAnchor represents a DNSSEC trust anchor.
// Trust anchors are the starting points for DNSSEC validation chains.
type TrustAnchor struct {
	Zone       string
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     []byte
	PublicKey  []byte // For DNSKEY-based anchors
	ValidFrom  time.Time
	ValidUntil *time.Time // nil if no expiration
}

// IsValid checks if the trust anchor is currently valid.
func (ta *TrustAnchor) IsValid() bool {
	now := time.Now()
	if now.Before(ta.ValidFrom) {
		return false
	}
	if ta.ValidUntil != nil && now.After(*ta.ValidUntil) {
		return false
	}
	return true
}

// MatchesDS checks if a DS record matches this trust anchor.
func (ta *TrustAnchor) MatchesDS(ds *protocol.RDataDS) bool {
	return ta.KeyTag == ds.KeyTag &&
		ta.Algorithm == ds.Algorithm &&
		ta.DigestType == ds.DigestType &&
		bytesEqual(ta.Digest, ds.Digest)
}

// MatchesDNSKEY checks if a DNSKEY record matches this trust anchor.
func (ta *TrustAnchor) MatchesDNSKEY(dnskey *protocol.RDataDNSKEY) bool {
	if ta.PublicKey == nil {
		return false
	}
	tag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
	return ta.KeyTag == tag &&
		ta.Algorithm == dnskey.Algorithm &&
		bytesEqual(ta.PublicKey, dnskey.PublicKey)
}

// TrustAnchorStore manages a collection of trust anchors.
type TrustAnchorStore struct {
	mu      sync.RWMutex
	anchors map[string][]*TrustAnchor // zone -> anchors
}

// NewTrustAnchorStore creates a new trust anchor store.
func NewTrustAnchorStore() *TrustAnchorStore {
	return &TrustAnchorStore{
		anchors: make(map[string][]*TrustAnchor),
	}
}

// NewTrustAnchorStoreWithBuiltIn creates a store with built-in root anchors.
func NewTrustAnchorStoreWithBuiltIn() *TrustAnchorStore {
	store := NewTrustAnchorStore()
	for _, anchor := range BuiltInRootAnchors {
		store.AddAnchor(anchor)
	}
	return store
}

// AddAnchor adds a trust anchor to the store.
func (s *TrustAnchorStore) AddAnchor(anchor *TrustAnchor) {
	s.mu.Lock()
	defer s.mu.Unlock()

	zone := canonicalZone(anchor.Zone)
	s.anchors[zone] = append(s.anchors[zone], anchor)
}

// RemoveAnchor removes a specific trust anchor.
func (s *TrustAnchorStore) RemoveAnchor(zone string, keyTag uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	zone = canonicalZone(zone)
	anchors := s.anchors[zone]
	for i, a := range anchors {
		if a.KeyTag == keyTag {
			s.anchors[zone] = append(anchors[:i], anchors[i+1:]...)
			return
		}
	}
}

// GetAnchorsForZone returns all trust anchors for a zone.
func (s *TrustAnchorStore) GetAnchorsForZone(zone string) []*TrustAnchor {
	s.mu.RLock()
	defer s.mu.RUnlock()

	zone = canonicalZone(zone)
	result := make([]*TrustAnchor, len(s.anchors[zone]))
	copy(result, s.anchors[zone])
	return result
}

// FindClosestAnchor finds the closest trust anchor for a given domain.
// Returns the anchor and the remaining labels to validate.
func (s *TrustAnchorStore) FindClosestAnchor(name string) (*TrustAnchor, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	labels := splitLabels(name)

	// Try from most specific to root
	for i := 0; i < len(labels); i++ {
		zone := joinLabels(labels[i:])
		if anchors, ok := s.anchors[zone]; ok && len(anchors) > 0 {
			// Return the first valid anchor
			for _, anchor := range anchors {
				if anchor.IsValid() {
					return anchor, labels[:i]
				}
			}
		}
	}

	// Try root as last resort
	if anchors, ok := s.anchors["."]; ok && len(anchors) > 0 {
		for _, anchor := range anchors {
			if anchor.IsValid() {
				return anchor, labels
			}
		}
	}

	return nil, labels
}

// LoadFromFile loads trust anchors from an RFC 7958 format XML file.
func (s *TrustAnchorStore) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading trust anchor file: %w", err)
	}

	anchors, err := ParseTrustAnchorXML(data)
	if err != nil {
		return fmt.Errorf("parsing trust anchor XML: %w", err)
	}

	for _, anchor := range anchors {
		s.AddAnchor(anchor)
	}

	return nil
}

// GetAllZones returns all zones that have trust anchors.
func (s *TrustAnchorStore) GetAllZones() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	zones := make([]string, 0, len(s.anchors))
	for zone := range s.anchors {
		zones = append(zones, zone)
	}
	return zones
}

// Clear removes all trust anchors.
func (s *TrustAnchorStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.anchors = make(map[string][]*TrustAnchor)
}

// RFC 7958 XML structures
type trustAnchorXML struct {
	XMLName    xml.Name         `xml:"TrustAnchor"`
	ID         string           `xml:"id,attr"`
	Source     string           `xml:"source,attr"`
	Zone       string           `xml:"Zone"`
	KeyDigests []keyDigestXML   `xml:"KeyDigest"`
}

type keyDigestXML struct {
	ID         string `xml:"id,attr"`
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
}

// ParseTrustAnchorXML parses RFC 7958 format trust anchor XML.
func ParseTrustAnchorXML(data []byte) ([]*TrustAnchor, error) {
	var xmlAnchors trustAnchorXML
	if err := xml.Unmarshal(data, &xmlAnchors); err != nil {
		return nil, fmt.Errorf("unmarshaling XML: %w", err)
	}

	zone := canonicalZone(xmlAnchors.Zone)
	anchors := make([]*TrustAnchor, 0, len(xmlAnchors.KeyDigests))

	for _, kd := range xmlAnchors.KeyDigests {
		digest, err := hex.DecodeString(kd.Digest)
		if err != nil {
			return nil, fmt.Errorf("decoding digest: %w", err)
		}

		validFrom, err := parseXMLTime(kd.ValidFrom)
		if err != nil {
			return nil, fmt.Errorf("parsing validFrom: %w", err)
		}

		var validUntil *time.Time
		if kd.ValidUntil != "" {
			vt, err := parseXMLTime(kd.ValidUntil)
			if err != nil {
				return nil, fmt.Errorf("parsing validUntil: %w", err)
			}
			validUntil = &vt
		}

		anchor := &TrustAnchor{
			Zone:       zone,
			KeyTag:     kd.KeyTag,
			Algorithm:  kd.Algorithm,
			DigestType: kd.DigestType,
			Digest:     digest,
			ValidFrom:  validFrom,
			ValidUntil: validUntil,
		}
		anchors = append(anchors, anchor)
	}

	return anchors, nil
}

// parseXMLTime parses RFC 7958 timestamp format.
func parseXMLTime(s string) (time.Time, error) {
	// Try RFC 7958 format: 2024-01-01T00:00:00+00:00
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Try without timezone: 2024-01-01T00:00:00
	if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unsupported time format: %s", s)
}

// canonicalZone returns the canonical form of a zone name.
func canonicalZone(zone string) string {
	if zone == "" {
		return "."
	}
	// Ensure trailing dot for root reference
	if zone[len(zone)-1] != '.' {
		zone += "."
	}
	// Convert to lowercase
	return toLower(zone)
}

// toLower converts a string to lowercase (ASCII only for DNS).
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

// joinLabels joins DNS labels with dots.
func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return "."
	}
	result := labels[0]
	for i := 1; i < len(labels); i++ {
		result += "." + labels[i]
	}
	return result + "."
}

// splitLabels splits a domain name into labels (TLD first, leaf last).
// The name should be in canonical form (lowercase, with trailing dot).
func splitLabels(name string) []string {
	if name == "." || name == "" {
		return []string{}
	}
	// Remove trailing dot if present
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	// Split by dots - this gives us TLD first
	labels := []string{}
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}

// bytesEqual compares two byte slices for equality using constant-time comparison.
func bytesEqual(a, b []byte) bool {
	// Handle nil cases: nil != empty slice
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(a, b) == 1
}

// BuiltInRootAnchors contains the IANA root trust anchors.
// These are the current IANA root KSKs as of 2024.
var BuiltInRootAnchors = []*TrustAnchor{
	// Root KSK 2024 (KeyTag 20326)
	{
		Zone:       ".",
		KeyTag:     20326,
		Algorithm:  protocol.AlgorithmRSASHA256,
		DigestType: 2, // SHA-256
		Digest: []byte{
			0xE0, 0x6D, 0x44, 0xB8, 0x0B, 0x8F, 0x1D, 0x39,
			0xA9, 0x5C, 0x0B, 0x0D, 0x7C, 0x65, 0xD0, 0x84,
			0x58, 0xE8, 0x80, 0x40, 0x9B, 0xBC, 0x68, 0x34,
			0x57, 0x10, 0x42, 0x37, 0xC7, 0xF8, 0xEC, 0x8D,
		},
		ValidFrom: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		// ValidUntil will be set when this anchor is replaced
	},
	// Root KSK 2017 (KeyTag 19036) - expired but kept for reference
	{
		Zone:       ".",
		KeyTag:     19036,
		Algorithm:  protocol.AlgorithmRSASHA256,
		DigestType: 2, // SHA-256
		Digest: []byte{
			0x49, 0xAC, 0x11, 0xD7, 0xB6, 0xF4, 0x4E, 0x4D,
			0xE4, 0xF4, 0x07, 0x81, 0xE3, 0xD4, 0x68, 0xE9,
			0x4C, 0x06, 0x51, 0x14, 0x7D, 0xB4, 0x74, 0xD4,
			0x15, 0xC0, 0xF5, 0x82, 0x5C, 0xDC, 0x4D, 0xCC,
		},
		ValidFrom: time.Date(2017, 2, 2, 0, 0, 0, 0, time.UTC),
		ValidUntil: func() *time.Time {
			t := time.Date(2024, 1, 11, 0, 0, 0, 0, time.UTC)
			return &t
		}(),
	},
}

// DSFromDNSKEY creates a DS record from a DNSKEY.
func DSFromDNSKEY(zone string, dnskey *protocol.RDataDNSKEY, digestType uint8) (*TrustAnchor, error) {
	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)

	var digest []byte
	var err error

	switch digestType {
	case 1: // SHA-1 - NOT RECOMMENDED
		digest, err = calculateDSDigestSHA1(zone, dnskey)
	case 2: // SHA-256
		digest, err = calculateDSDigestSHA256(zone, dnskey)
	case 4: // SHA-384
		digest, err = calculateDSDigestSHA384(zone, dnskey)
	default:
		return nil, fmt.Errorf("unsupported digest type: %d", digestType)
	}

	if err != nil {
		return nil, err
	}

	return &TrustAnchor{
		Zone:       canonicalZone(zone),
		KeyTag:     keyTag,
		Algorithm:  dnskey.Algorithm,
		DigestType: digestType,
		Digest:     digest,
		PublicKey:  dnskey.PublicKey,
		ValidFrom:  time.Now(),
	}, nil
}

// calculateDSDigestSHA256 computes SHA-256 digest for DS record.
func calculateDSDigestSHA256(zone string, dnskey *protocol.RDataDNSKEY) ([]byte, error) {
	return calculateDSDigestWithHash(zone, dnskey, sha256.New())
}

// calculateDSDigestSHA1 computes SHA-1 digest for DS record.
func calculateDSDigestSHA1(zone string, dnskey *protocol.RDataDNSKEY) ([]byte, error) {
	return calculateDSDigestWithHash(zone, dnskey, sha1.New())
}

// calculateDSDigestSHA384 computes SHA-384 digest for DS record.
func calculateDSDigestSHA384(zone string, dnskey *protocol.RDataDNSKEY) ([]byte, error) {
	return calculateDSDigestWithHash(zone, dnskey, sha512.New384())
}

// calculateDSDigestWithHash computes DS digest using a hash function.
func calculateDSDigestWithHash(zone string, dnskey *protocol.RDataDNSKEY, h hash.Hash) ([]byte, error) {
	// Wire format of owner name
	ownerWire := protocol.CanonicalWireName(zone)

	// DNSKEY RDATA: flags (2) + protocol (1) + algorithm (1) + public key
	dnskeyRData := make([]byte, 4+len(dnskey.PublicKey))
	dnskeyRData[0] = byte(dnskey.Flags >> 8)
	dnskeyRData[1] = byte(dnskey.Flags)
	dnskeyRData[2] = dnskey.Protocol
	dnskeyRData[3] = dnskey.Algorithm
	copy(dnskeyRData[4:], dnskey.PublicKey)

	// Calculate digest: hash(owner | dnskey_rdata)
	h.Write(ownerWire)
	h.Write(dnskeyRData)

	return h.Sum(nil), nil
}
