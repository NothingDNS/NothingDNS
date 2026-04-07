// Package dnssec provides DNSSEC (DNS Security Extensions) functionality.
// This file implements RFC 8901 - Multi-Signer DNSSEC.
// Multi-Signer DNSSEC allows multiple organizations to operate independent
// signers for a shared zone, enabling DNSSEC deployment without a single
// operator requiring all keys.
package dnssec

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// MultiSignerError represents errors in multi-signer operations.
type MultiSignerError struct {
	Msg string
}

func (e *MultiSignerError) Error() string {
	return fmt.Sprintf("multi-signer: %s", e.Msg)
}

// SignerInfo represents information about a zone signer.
type SignerInfo struct {
	// SignerName is the name of the signer (typically a ZSK identifier)
	SignerName string

	// ZoneName is the zone this signer handles
	ZoneName string

	// KeyTag is the key tag of the signing key
	KeyTag uint16

	// Algorithm is the signing algorithm
	Algorithm uint8

	// IsKSK indicates if this is a Key Signing Key
	IsKSK bool

	// IsActive indicates if this signer is currently active
	IsActive bool

	// AddedTime is when this signer was added to the zone
	AddedTime time.Time
}

// MultiSignerZone represents a zone managed by multiple signers.
type MultiSignerZone struct {
	// ZoneName is the name of the zone
	ZoneName string

	// Signers is the list of active signers
	Signers []*SignerInfo

	// OriginalTTL is the original TTL for records in this zone
	OriginalTTL uint32

	// SignatureValidity is how long signatures remain valid
	SignatureValidity time.Duration
}

// NewMultiSignerZone creates a new multi-signer zone.
func NewMultiSignerZone(zoneName string) *MultiSignerZone {
	return &MultiSignerZone{
		ZoneName:          strings.ToLower(zoneName),
		Signers:          make([]*SignerInfo, 0),
		OriginalTTL:       3600, // 1 hour default
		SignatureValidity: 7 * 24 * time.Hour, // 7 days default
	}
}

// AddSigner adds a signer to the zone.
func (mz *MultiSignerZone) AddSigner(signer *SignerInfo) error {
	// Check for duplicate key tag
	for _, s := range mz.Signers {
		if s.KeyTag == signer.KeyTag && s.Algorithm == signer.Algorithm {
			return &MultiSignerError{Msg: fmt.Sprintf("duplicate signer: keytag %d algorithm %d", s.KeyTag, s.Algorithm)}
		}
	}

	signer.AddedTime = time.Now()
	mz.Signers = append(mz.Signers, signer)
	return nil
}

// RemoveSigner removes a signer by key tag and algorithm.
func (mz *MultiSignerZone) RemoveSigner(keyTag uint16, algorithm uint8) {
	for i, s := range mz.Signers {
		if s.KeyTag == keyTag && s.Algorithm == algorithm {
			mz.Signers = append(mz.Signers[:i], mz.Signers[i+1:]...)
			return
		}
	}
}

// GetActiveSigners returns all active signers.
func (mz *MultiSignerZone) GetActiveSigners() []*SignerInfo {
	var active []*SignerInfo
	for _, s := range mz.Signers {
		if s.IsActive {
			active = append(active, s)
		}
	}
	return active
}

// CDS represents a CDS record for signaling DNSSEC support.
type CDS struct {
	// KeyTag is the key tag of the referenced DNSKEY
	KeyTag uint16

	// Algorithm is the signing algorithm
	Algorithm uint8

	// DigestType is the type of digest (1=SHA-1, 2=SHA-256, 4=SHA-384)
	DigestType uint8

	// Digest is the hash of the referenced DNSKEY
	Digest []byte
}

// CDSFromDNSKEY creates a CDS record from a DNSKEY.
func CDSFromDNSKEY(dnskey *protocol.RDataDNSKEY) (*CDS, error) {
	// Check if this is a KSK (bit 0x0001 in flags)
	if dnskey.Flags&0x0001 == 0 {
		return nil, &MultiSignerError{Msg: "CDS must be derived from a KSK"}
	}

	// Pack the DNSKEY for hashing
	buf := make([]byte, 256) // large enough buffer
	n, err := dnskey.Pack(buf, 0)
	if err != nil {
		return nil, &MultiSignerError{Msg: fmt.Sprintf("packing DNSKEY: %v", err)}
	}
	dnskeyBytes := buf[:n]

	// Compute digest based on digest type
	// For now, we compute SHA-256 digest
	digest := computeDNSKEYDigest(dnskeyBytes, 2) // 2 = SHA-256

	return &CDS{
		KeyTag:     ComputeKeyTag(dnskey.Algorithm, dnskeyBytes),
		Algorithm:  dnskey.Algorithm,
		DigestType: 2, // SHA-256
		Digest:     digest,
	}, nil
}

// computeDNSKEYDigest computes the digest of a DNSKEY record.
func computeDNSKEYDigest(dnskey []byte, digestType uint8) []byte {
	// This is a simplified implementation
	// Actual implementation would use crypto/sha1 or crypto/sha256
	h := sha256.New()
	h.Write(dnskey)
	return h.Sum(nil)[:20]
}

// CDNSKEY represents a CDNSKEY record (RFC 8901).
type CDNSKEY struct {
	// Flags indicates KSK (256) or ZSK (257)
	Flags uint16

	// Protocol must be 3
	Protocol uint8

	// Algorithm is the signing algorithm
	Algorithm uint8
}

// NewCDNSKEYFromDNSKEY creates a CDNSKEY from a DNSKEY.
func NewCDNSKEYFromDNSKEY(dnskey *protocol.RDataDNSKEY) *CDNSKEY {
	flags := uint16(256) // KSK
	if dnskey.Flags&0x0001 == 0 {
		flags = 257 // ZSK
	}

	return &CDNSKEY{
		Flags:    flags,
		Protocol: 3,
		Algorithm: dnskey.Algorithm,
	}
}

// String returns a human-readable representation.
func (s *SignerInfo) String() string {
	keyType := "ZSK"
	if s.IsKSK {
		keyType = "KSK"
	}
	return fmt.Sprintf("Signer{%s %s keytag=%d algo=%d active=%v}",
		s.ZoneName, keyType, s.KeyTag, s.Algorithm, s.IsActive)
}

// SortSigners sorts signers by key tag and algorithm.
func SortSigners(signers []*SignerInfo) {
	sort.Slice(signers, func(i, j int) bool {
		if signers[i].KeyTag != signers[j].KeyTag {
			return signers[i].KeyTag < signers[j].KeyTag
		}
		return signers[i].Algorithm < signers[j].Algorithm
	})
}

// ValidateMultiSignerZone validates a multi-signer zone configuration.
func ValidateMultiSignerZone(mz *MultiSignerZone) error {
	if mz == nil {
		return &MultiSignerError{Msg: "nil zone"}
	}

	if mz.ZoneName == "" {
		return &MultiSignerError{Msg: "missing zone name"}
	}

	if len(mz.Signers) == 0 {
		return &MultiSignerError{Msg: "no signers configured"}
	}

	// Check that at least one signer is active
	hasActive := false
	for _, s := range mz.Signers {
		if s.IsActive {
			hasActive = true
			break
		}
	}
	if !hasActive {
		return &MultiSignerError{Msg: "no active signers"}
	}

	// Check for duplicate signers
	seen := make(map[string]bool)
	for _, s := range mz.Signers {
		key := fmt.Sprintf("%d-%d", s.KeyTag, s.Algorithm)
		if seen[key] {
			return &MultiSignerError{Msg: fmt.Sprintf("duplicate signer keytag=%d algo=%d", s.KeyTag, s.Algorithm)}
		}
		seen[key] = true
	}

	return nil
}

// MultiSignerConfig holds configuration for multi-signer operation.
type MultiSignerConfig struct {
	// ZoneName is the zone being managed
	ZoneName string

	// MinActiveSigners is the minimum number of signers that must be active
	MinActiveSigners int

	// KeyPropagationTime is how long to wait for keys to propagate
	KeyPropagationTime time.Duration

	// SignatureRefreshTime is when to refresh signatures
	SignatureRefreshTime time.Duration
}

// DefaultMultiSignerConfig returns default multi-signer configuration.
func DefaultMultiSignerConfig(zoneName string) *MultiSignerConfig {
	return &MultiSignerConfig{
		ZoneName:            zoneName,
		MinActiveSigners:    1,
		KeyPropagationTime:  5 * time.Minute,
		SignatureRefreshTime: 24 * time.Hour,
	}
}
