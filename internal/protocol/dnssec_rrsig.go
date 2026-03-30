package protocol

import (
	"fmt"
	"strings"
	"time"
)

// RDataRRSIG represents a Resource Record Signature (RRSIG) record (RFC 4034).
// RRSIG records contain cryptographic signatures that authenticate DNS data.
type RDataRRSIG struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OriginalTTL uint32
	Expiration  uint32 // Unix timestamp
	Inception   uint32 // Unix timestamp
	KeyTag      uint16
	SignerName  *Name
	Signature   []byte
}

// Type returns TypeRRSIG.
func (r *RDataRRSIG) Type() uint16 { return TypeRRSIG }

// Pack serializes the RRSIG record to wire format.
func (r *RDataRRSIG) Pack(buf []byte, offset int) (int, error) {
	startOffset := offset

	// Type Covered (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.TypeCovered)
	offset += 2

	// Algorithm (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Algorithm
	offset++

	// Labels (1 byte)
	if offset+1 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	buf[offset] = r.Labels
	offset++

	// Original TTL (4 bytes)
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint32(buf[offset:], r.OriginalTTL)
	offset += 4

	// Expiration (4 bytes) - Unix timestamp
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint32(buf[offset:], r.Expiration)
	offset += 4

	// Inception (4 bytes) - Unix timestamp
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint32(buf[offset:], r.Inception)
	offset += 4

	// Key Tag (2 bytes)
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.KeyTag)
	offset += 2

	// Signer Name
	n, err := PackName(r.SignerName, buf, offset, nil)
	if err != nil {
		return 0, fmt.Errorf("packing signer name: %w", err)
	}
	offset += n

	// Signature
	sigLen := len(r.Signature)
	if offset+sigLen > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Signature)
	offset += sigLen

	return offset - startOffset, nil
}

// Unpack deserializes the RRSIG record from wire format.
func (r *RDataRRSIG) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	startOffset := offset
	endOffset := offset + int(rdlength)

	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Need at least 18 bytes for fixed fields before signer name
	if offset+18 > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Type Covered
	r.TypeCovered = Uint16(buf[offset:])
	offset += 2

	// Algorithm
	r.Algorithm = buf[offset]
	offset++

	// Labels
	r.Labels = buf[offset]
	offset++

	// Original TTL
	r.OriginalTTL = Uint32(buf[offset:])
	offset += 4

	// Expiration
	r.Expiration = Uint32(buf[offset:])
	offset += 4

	// Inception
	r.Inception = Uint32(buf[offset:])
	offset += 4

	// Key Tag
	r.KeyTag = Uint16(buf[offset:])
	offset += 2

	// Signer Name
	signerName, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, fmt.Errorf("unpacking signer name: %w", err)
	}
	r.SignerName = signerName
	offset += n

	// Signature (remaining bytes)
	if offset > endOffset {
		return 0, ErrBufferTooSmall
	}
	sigLen := endOffset - offset
	r.Signature = make([]byte, sigLen)
	copy(r.Signature, buf[offset:endOffset])
	offset = endOffset

	return offset - startOffset, nil
}

// String returns the RRSIG record in presentation format.
func (r *RDataRRSIG) String() string {
	typeStr := TypeString(r.TypeCovered)
	signerStr := "."
	if r.SignerName != nil {
		signerStr = r.SignerName.String()
	}

	return fmt.Sprintf("%s %d %d %d %s %s %d %s %s",
		typeStr,
		r.Algorithm,
		r.Labels,
		r.OriginalTTL,
		formatDNSTime(r.Expiration),
		formatDNSTime(r.Inception),
		r.KeyTag,
		signerStr,
		base64Encode(r.Signature),
	)
}

// Len returns the wire length of the RRSIG record.
func (r *RDataRRSIG) Len() int {
	signerLen := 1
	if r.SignerName != nil {
		signerLen = r.SignerName.WireLength()
	}
	return 18 + signerLen + len(r.Signature)
}

// Copy creates a deep copy of the RRSIG record.
func (r *RDataRRSIG) Copy() RData {
	var signerName *Name
	if r.SignerName != nil {
		signerName = NewName(r.SignerName.Labels, r.SignerName.FQDN)
	}

	sigCopy := make([]byte, len(r.Signature))
	copy(sigCopy, r.Signature)

	return &RDataRRSIG{
		TypeCovered: r.TypeCovered,
		Algorithm:   r.Algorithm,
		Labels:      r.Labels,
		OriginalTTL: r.OriginalTTL,
		Expiration:  r.Expiration,
		Inception:   r.Inception,
		KeyTag:      r.KeyTag,
		SignerName:  signerName,
		Signature:   sigCopy,
	}
}

// IsExpired returns true if the signature has expired.
func (r *RDataRRSIG) IsExpired() bool {
	return time.Now().Unix() > int64(r.Expiration)
}

// IsInceptionValid returns true if the signature inception time has passed.
func (r *RDataRRSIG) IsInceptionValid() bool {
	return time.Now().Unix() >= int64(r.Inception)
}

// ValidityPeriod returns the time range during which the signature is valid.
func (r *RDataRRSIG) ValidityPeriod() (inception, expiration time.Time) {
	return time.Unix(int64(r.Inception), 0), time.Unix(int64(r.Expiration), 0)
}

// formatDNSTime formats a Unix timestamp as YYYYMMDDHHMMSS for presentation.
func formatDNSTime(timestamp uint32) string {
	t := time.Unix(int64(timestamp), 0).UTC()
	return t.Format("20060102150405")
}

// SignerNameString returns the signer name as a string.
func (r *RDataRRSIG) SignerNameString() string {
	if r.SignerName == nil {
		return "."
	}
	return r.SignerName.String()
}

// RRSIGForRRSet returns the canonical wire format data to be signed.
// This is used when creating signatures per RFC 4034 Section 5.
func RRSIGForRRSet(rrsig *RDataRRSIG, rrset []*ResourceRecord) ([]byte, error) {
	if len(rrset) == 0 {
		return nil, fmt.Errorf("empty RRSet")
	}

	var data []byte

	// RRSIG RDATA (without signature):
	// Type Covered | Algorithm | Labels | Original TTL | Expiration | Inception | Key Tag | Signer Name
	data = append(data, byte(rrsig.TypeCovered>>8), byte(rrsig.TypeCovered))
	data = append(data, rrsig.Algorithm)
	data = append(data, rrsig.Labels)
	data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
		byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))
	data = append(data, byte(rrsig.Expiration>>24), byte(rrsig.Expiration>>16),
		byte(rrsig.Expiration>>8), byte(rrsig.Expiration))
	data = append(data, byte(rrsig.Inception>>24), byte(rrsig.Inception>>16),
		byte(rrsig.Inception>>8), byte(rrsig.Inception))
	data = append(data, byte(rrsig.KeyTag>>8), byte(rrsig.KeyTag))
	data = append(data, canonicalWireName(rrsig.SignerName.String())...)

	// RRSet in canonical form (sorted, one RR at a time):
	// Owner Name | Type | Class | TTL | RDLENGTH | RDATA
	for _, rr := range rrset {
		data = append(data, canonicalWireName(rr.Name.String())...)
		data = append(data, byte(rr.Type>>8), byte(rr.Type))
		data = append(data, byte(rr.Class>>8), byte(rr.Class))
		data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
			byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))

		if rr.Data != nil {
			buf := make([]byte, 65535)
			n, err := rr.Data.Pack(buf, 0)
			if err != nil {
				continue
			}
			rdata := buf[:n]
			data = append(data, byte(len(rdata)>>8), byte(len(rdata)))
			data = append(data, rdata...)
		} else {
			data = append(data, 0, 0)
		}
	}

	return data, nil
}

// canonicalWireName converts a DNS name to canonical lowercase wire format.
func canonicalWireName(name string) []byte {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	if name == "" || name == "." {
		return []byte{0}
	}

	var wire []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		wire = append(wire, byte(len(label)))
		wire = append(wire, []byte(label)...)
	}
	wire = append(wire, 0)
	return wire
}
