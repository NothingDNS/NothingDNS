package protocol

import (
	"fmt"
	"time"
)

// RData is the interface that all DNS record type data structures implement.
type RData interface {
	// Type returns the DNS record type code (e.g., TypeA, TypeAAAA).
	Type() uint16

	// Pack serializes the record data to wire format.
	// Returns the number of bytes written.
	Pack(buf []byte, offset int) (int, error)

	// Unpack deserializes record data from wire format.
	// Returns the number of bytes consumed.
	Unpack(buf []byte, offset int, rdlength uint16) (int, error)

	// String returns a human-readable representation of the record data.
	String() string

	// Len returns the length of the record data in wire format.
	Len() int

	// Copy creates a deep copy of the record data.
	Copy() RData
}

// ResourceRecord represents a DNS resource record (RFC 1035 §4.1.3).
type ResourceRecord struct {
	// Name is the domain name to which this resource record pertains.
	Name *Name

	// Type is the type of the resource record (e.g., TypeA, TypeAAAA).
	Type uint16

	// Class is the class of the resource record (usually ClassIN).
	Class uint16

	// TTL is the time interval (in seconds) that the resource record may be cached.
	TTL uint32

	// Data contains the record-type-specific data.
	Data RData
}

// NewResourceRecord creates a new ResourceRecord.
func NewResourceRecord(name string, rrtype, rrclass uint16, ttl uint32, data RData) (*ResourceRecord, error) {
	n, err := ParseName(name)
	if err != nil {
		return nil, err
	}

	return &ResourceRecord{
		Name:  n,
		Type:  rrtype,
		Class: rrclass,
		TTL:   ttl,
		Data:  data,
	}, nil
}

// WireLength returns the length of the resource record in wire format.
func (rr *ResourceRecord) WireLength() int {
	// Name length + Type (2) + Class (2) + TTL (4) + RDLENGTH (2) + RData length
	rdataLen := 0
	if rr.Data != nil {
		rdataLen = rr.Data.Len()
	}
	return rr.Name.WireLength() + 10 + rdataLen
}

// Pack serializes the resource record to wire format.
// Returns the number of bytes written.
func (rr *ResourceRecord) Pack(buf []byte, offset int, compression map[string]int) (int, error) {
	startOffset := offset

	// Pack the name
	n, err := PackName(rr.Name, buf, offset, compression)
	if err != nil {
		return 0, fmt.Errorf("packing name: %w", err)
	}
	offset += n

	// Pack Type
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], rr.Type)
	offset += 2

	// Pack Class
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], rr.Class)
	offset += 2

	// Pack TTL
	if offset+4 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint32(buf[offset:], rr.TTL)
	offset += 4

	// Pack RDLENGTH (placeholder first)
	rdlengthOffset := offset
	if offset+2 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	offset += 2 // Reserve space for RDLENGTH

	// Pack RData
	rdataLen, err := rr.Data.Pack(buf, offset)
	if err != nil {
		return 0, fmt.Errorf("packing rdata: %w", err)
	}
	offset += rdataLen

	// Now write the actual RDLENGTH
	PutUint16(buf[rdlengthOffset:], uint16(rdataLen))

	return offset - startOffset, nil
}

// UnpackResourceRecord deserializes a resource record from wire format.
// Returns the record and the number of bytes consumed.
func UnpackResourceRecord(buf []byte, offset int) (*ResourceRecord, int, error) {
	startOffset := offset

	// Unpack the name
	name, n, err := UnpackName(buf, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("unpacking name: %w", err)
	}
	offset += n

	// Check bounds for fixed fields
	if offset+10 > len(buf) {
		return nil, 0, ErrBufferTooSmall
	}

	// Unpack Type
	rrtype := Uint16(buf[offset:])
	offset += 2

	// Unpack Class
	rrclass := Uint16(buf[offset:])
	offset += 2

	// Unpack TTL
	ttl := Uint32(buf[offset:])
	offset += 4

	// Unpack RDLENGTH
	rdlength := Uint16(buf[offset:])
	offset += 2

	// Check bounds for RDATA
	if offset+int(rdlength) > len(buf) {
		return nil, 0, ErrBufferTooSmall
	}

	// Create appropriate RData based on type
	data := createRData(rrtype)

	// Unpack RData
	if data != nil {
		n, err := data.Unpack(buf, offset, rdlength)
		if err != nil {
			return nil, 0, fmt.Errorf("unpacking rdata: %w", err)
		}
		offset += n
	} else {
		// Unknown type - use raw data
		data = &RDataRaw{
			TypeVal: rrtype,
			Data:    make([]byte, rdlength),
		}
		copy(data.(*RDataRaw).Data, buf[offset:offset+int(rdlength)])
		offset += int(rdlength)
	}

	return &ResourceRecord{
		Name:  name,
		Type:  rrtype,
		Class: rrclass,
		TTL:   ttl,
		Data:  data,
	}, offset - startOffset, nil
}

// RDataRaw is a fallback for unknown record types.
type RDataRaw struct {
	TypeVal uint16
	Data    []byte
}

// Type returns the record type.
func (r *RDataRaw) Type() uint16 { return r.TypeVal }

// Pack serializes the raw data.
func (r *RDataRaw) Pack(buf []byte, offset int) (int, error) {
	if offset+len(r.Data) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Data)
	return len(r.Data), nil
}

// Unpack deserializes raw data.
func (r *RDataRaw) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if offset+int(rdlength) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Data = make([]byte, rdlength)
	copy(r.Data, buf[offset:offset+int(rdlength)])
	return int(rdlength), nil
}

// String returns a hex representation.
func (r *RDataRaw) String() string {
	return fmt.Sprintf("\\# %d %x", len(r.Data), r.Data)
}

// Len returns the length.
func (r *RDataRaw) Len() int { return len(r.Data) }

// Copy creates a copy.
func (r *RDataRaw) Copy() RData {
	dataCopy := make([]byte, len(r.Data))
	copy(dataCopy, r.Data)
	return &RDataRaw{TypeVal: r.TypeVal, Data: dataCopy}
}

// createRData creates an appropriate RData structure for the given type.
// Returns nil for types not yet implemented.
func createRData(rrtype uint16) RData {
	switch rrtype {
	case TypeA:
		return &RDataA{}
	case TypeAAAA:
		return &RDataAAAA{}
	case TypeCNAME:
		return &RDataCNAME{}
	case TypeNS:
		return &RDataNS{}
	case TypePTR:
		return &RDataPTR{}
	case TypeMX:
		return &RDataMX{}
	case TypeTXT:
		return &RDataTXT{}
	case TypeSOA:
		return &RDataSOA{}
	case TypeSRV:
		return &RDataSRV{}
	case TypeCAA:
		return &RDataCAA{}
	case TypeNAPTR:
		return &RDataNAPTR{}
	case TypeSSHFP:
		return &RDataSSHFP{}
	case TypeTLSA:
		return &RDataTLSA{}
	case TypeDS:
		return &RDataDS{}
	case TypeDNSKEY:
		return &RDataDNSKEY{}
	case TypeRRSIG:
		return &RDataRRSIG{}
	case TypeNSEC:
		return &RDataNSEC{}
	case TypeNSEC3:
		return &RDataNSEC3{}
	case TypeNSEC3PARAM:
		return &RDataNSEC3PARAM{}
	case TypeOPT:
		return &RDataOPT{}
	default:
		return nil
	}
}

// String returns a human-readable representation of the resource record.
func (rr *ResourceRecord) String() string {
	classStr := ClassString(rr.Class)
	typeStr := TypeString(rr.Type)

	dataStr := ""
	if rr.Data != nil {
		dataStr = rr.Data.String()
	}

	// Format: name TTL class type data
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s",
		rr.Name.String(),
		rr.TTL,
		classStr,
		typeStr,
		dataStr,
	)
}

// Copy creates a deep copy of the resource record.
func (rr *ResourceRecord) Copy() *ResourceRecord {
	if rr == nil {
		return nil
	}

	var data RData
	if rr.Data != nil {
		data = rr.Data.Copy()
	}

	return &ResourceRecord{
		Name:  NewName(rr.Name.Labels, rr.Name.FQDN),
		Type:  rr.Type,
		Class: rr.Class,
		TTL:   rr.TTL,
		Data:  data,
	}
}

// IsExpired returns true if the record has expired based on the given timestamp.
func (rr *ResourceRecord) IsExpired(cachedAt time.Time) bool {
	return time.Since(cachedAt) > time.Duration(rr.TTL)*time.Second
}

// RemainingTTL returns the remaining TTL in seconds based on when the record was cached.
func (rr *ResourceRecord) RemainingTTL(cachedAt time.Time) uint32 {
	elapsed := time.Since(cachedAt)
	ttl := time.Duration(rr.TTL) * time.Second
	if elapsed >= ttl {
		return 0
	}
	return uint32((ttl - elapsed).Seconds())
}
