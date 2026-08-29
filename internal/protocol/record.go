package protocol

import (
	"fmt"
	"reflect"
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

func isNilRData(data RData) bool {
	if data == nil {
		return true
	}
	v := reflect.ValueOf(data)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
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

	rr := acquireResourceRecord()
	rr.Name = n
	rr.Type = rrtype
	rr.Class = rrclass
	rr.TTL = ttl
	rr.Data = data
	return rr, nil
}

// WireLength returns the length of the resource record in wire format.
func (rr *ResourceRecord) WireLength() int {
	if rr == nil || rr.Name == nil {
		return 0
	}
	// Name length + Type (2) + Class (2) + TTL (4) + RDLENGTH (2) + RData length
	rdataLen := 0
	if !isNilRData(rr.Data) {
		rdataLen = rr.Data.Len()
	}
	return rr.Name.WireLength() + 10 + rdataLen
}

// Pack serializes the resource record to wire format.
// Returns the number of bytes written.
func (rr *ResourceRecord) Pack(buf []byte, offset int, compression map[string]int) (int, error) {
	if rr == nil {
		return 0, fmt.Errorf("nil resource record")
	}
	if rr.Name == nil {
		return 0, fmt.Errorf("nil resource record name")
	}
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
	if isNilRData(rr.Data) {
		return 0, fmt.Errorf("packing rdata: nil RData for record %s type %d", rr.Name, rr.Type)
	}
	rdataLen, err := rr.Data.Pack(buf, offset)
	if err != nil {
		return 0, fmt.Errorf("packing rdata: %w", err)
	}
	if rdataLen > 0xffff {
		return 0, fmt.Errorf("packing rdata: RDATA length %d exceeds 65535 bytes", rdataLen)
	}
	offset += rdataLen

	// Now write the actual RDLENGTH
	PutUint16(buf[rdlengthOffset:], uint16(rdataLen))

	return offset - startOffset, nil
}

// Release returns the ResourceRecord and any pooled children to internal pools.
func (rr *ResourceRecord) Release() {
	if rr == nil {
		return
	}
	if rr.Name != nil {
		rr.Name.Release()
		rr.Name = nil
	}
	if !isNilRData(rr.Data) {
		releaseRData(rr.Data)
		rr.Data = nil
	}
	rr.Type = 0
	rr.Class = 0
	rr.TTL = 0
	resourceRecordPool.Put(rr)
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
		name.Release()
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

	// RFC 2181 §8: "Implementations should treat TTL values received with the
	// most significant bit set as if the entire value received was zero."
	// The TTL is signed on the wire in practice, so 0x80000000 and above are
	// nonsense — but they are nonsense a remote party chooses. Passed through,
	// a TTL of 0xFFFFFFFF tells every downstream cache to hold the record for
	// 136 years, which turns one bad or hostile answer into a permanent one.
	// The OPT pseudo-record is exempt: its "TTL" field is not a TTL at all
	// (RFC 6891 §6.1.3 packs the extended RCODE, EDNS version, DO bit and Z
	// into it), so zeroing it would silently strip the DO bit.
	if rrtype != TypeOPT && ttl&0x80000000 != 0 {
		ttl = 0
	}

	// Unpack RDLENGTH
	rdlength := Uint16(buf[offset:])
	offset += 2

	// Check bounds for RDATA
	if offset+int(rdlength) > len(buf) {
		name.Release()
		return nil, 0, ErrBufferTooSmall
	}

	// Create appropriate RData based on type
	data := createRData(rrtype)

	// Unpack RData
	if data != nil {
		n, err := data.Unpack(buf, offset, rdlength)
		if err != nil {
			name.Release()
			releaseRData(data)
			return nil, 0, fmt.Errorf("unpacking rdata: %w", err)
		}
		if n != int(rdlength) {
			name.Release()
			releaseRData(data)
			return nil, 0, fmt.Errorf("rdata length mismatch: consumed %d bytes, rdlength %d", n, rdlength)
		}
		offset += n
	} else {
		// Unknown type - use raw data
		raw := &RDataRaw{
			TypeVal: rrtype,
			Data:    make([]byte, rdlength),
		}
		copy(raw.Data, buf[offset:offset+int(rdlength)])
		data = raw
		offset += int(rdlength)
	}

	rr := acquireResourceRecord()
	rr.Name = name
	rr.Type = rrtype
	rr.Class = rrclass
	rr.TTL = ttl
	rr.Data = data
	return rr, offset - startOffset, nil
}

// RDataRaw is a fallback for unknown record types.
type RDataRaw struct {
	TypeVal uint16
	Data    []byte
}

// Type returns the record type.
func (r *RDataRaw) Type() uint16 {
	if r == nil {
		return 0
	}

	return r.TypeVal
}

// Pack serializes the raw data.
func (r *RDataRaw) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil raw record")
	}

	if offset+len(r.Data) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	copy(buf[offset:], r.Data)
	return len(r.Data), nil
}

// Unpack deserializes raw data.
func (r *RDataRaw) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil raw record")
	}

	if offset+int(rdlength) > len(buf) {
		return 0, ErrBufferTooSmall
	}
	r.Data = make([]byte, rdlength)
	copy(r.Data, buf[offset:offset+int(rdlength)])
	return int(rdlength), nil
}

// String returns a hex representation.
func (r *RDataRaw) String() string {
	if r == nil {
		return ""
	}

	return fmt.Sprintf("\\# %d %x", len(r.Data), r.Data)
}

// Len returns the length.
func (r *RDataRaw) Len() int {
	if r == nil {
		return 0
	}

	return len(r.Data)
}

// Copy creates a copy.
func (r *RDataRaw) Copy() RData {
	if r == nil {
		return nil
	}

	dataCopy := make([]byte, len(r.Data))
	copy(dataCopy, r.Data)
	return &RDataRaw{TypeVal: r.TypeVal, Data: dataCopy}
}

// createRData creates an appropriate RData structure for the given type.
// Returns nil for types not yet implemented.
func createRData(rrtype uint16) RData {
	if pooled := pooledRData(rrtype); pooled != nil {
		return pooled
	}
	switch rrtype {
	case TypeA:
		return &RDataA{}
	case TypeAAAA:
		return &RDataAAAA{}
	case TypeCNAME:
		return &RDataCNAME{}
	case TypeDNAME:
		return &RDataDNAME{}
	case TypeNS:
		return &RDataNS{}
	case TypePTR:
		return &RDataPTR{}
	case TypeMX:
		return &RDataMX{}
	case TypeTXT:
		return &RDataTXT{}
	case TypeHINFO:
		return &RDataHINFO{}
	case TypeRP:
		return &RDataRP{}
	case TypeAFSDB:
		return &RDataAFSDB{}
	case TypeSIG:
		// SIG uses the same RDATA wire format as RRSIG (RFC 4034 appendix A).
		return &RDataRRSIG{}
	case TypeKEY:
		// KEY uses the same RDATA wire format as DNSKEY.
		return &RDataDNSKEY{}
	case TypeSPF:
		// SPF uses the same <character-string> wire encoding as TXT.
		return &RDataTXT{}
	case TypeLOC:
		return &RDataLOC{}
	case TypeSOA:
		return &RDataSOA{}
	case TypeSRV:
		return &RDataSRV{}
	case TypeKX:
		return &RDataKX{}
	case TypeCERT:
		return &RDataCERT{}
	case TypeCAA:
		return &RDataCAA{}
	case TypeURI:
		return &RDataURI{}
	case TypeNAPTR:
		return &RDataNAPTR{}
	case TypeAPL:
		return &RDataAPL{}
	case TypeSSHFP:
		return &RDataSSHFP{}
	case TypeHIP:
		return &RDataHIP{}
	case TypeIPSECKEY:
		return &RDataIPSECKEY{}
	case TypeTLSA:
		return &RDataTLSA{}
	case TypeDHCID:
		return &RDataDHCID{}
	case TypeDS:
		return &RDataDS{}
	case TypeCDS:
		// CDS uses the same RDATA wire format as DS (RFC 7344).
		return &RDataDS{}
	case TypeDNSKEY:
		return &RDataDNSKEY{}
	case TypeCDNSKEY:
		// CDNSKEY uses the same RDATA wire format as DNSKEY (RFC 7344).
		return &RDataDNSKEY{}
	case TypeTA:
		// TA uses the same RDATA wire format as DS.
		return &RDataDS{}
	case TypeOPENPGPKEY:
		return &RDataOPENPGPKEY{}
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
	case TypeSVCB:
		return &RDataSVCB{}
	case TypeHTTPS:
		return &RDataHTTPS{}
	case TypeZONEMD:
		return &RDataZONEMD{}
	default:
		return nil
	}
}

// String returns a human-readable representation of the resource record.
func (rr *ResourceRecord) String() string {
	if rr == nil {
		return "<nil resource record>"
	}
	classStr := ClassString(rr.Class)
	typeStr := TypeString(rr.Type)
	name := "<nil>"
	if rr.Name != nil {
		name = rr.Name.String()
	}

	dataStr := ""
	if !isNilRData(rr.Data) {
		dataStr = rr.Data.String()
	}

	// Format: name TTL class type data
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s",
		name,
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
	if !isNilRData(rr.Data) {
		data = rr.Data.Copy()
	}
	var name *Name
	if rr.Name != nil {
		name = rr.Name.Copy()
	}

	copyRR := acquireResourceRecord()
	copyRR.Name = name
	copyRR.Type = rr.Type
	copyRR.Class = rr.Class
	copyRR.TTL = rr.TTL
	copyRR.Data = data
	return copyRR
}

// IsExpired returns true if the record has expired based on the given timestamp.
func (rr *ResourceRecord) IsExpired(cachedAt time.Time) bool {
	return rr.isExpiredAt(time.Now(), cachedAt)
}

func (rr *ResourceRecord) isExpiredAt(now, cachedAt time.Time) bool {
	if rr == nil {
		return true
	}
	return !now.Before(cachedAt.Add(time.Duration(rr.TTL) * time.Second))
}

// RemainingTTL returns the remaining TTL in seconds based on when the record was cached.
func (rr *ResourceRecord) RemainingTTL(cachedAt time.Time) uint32 {
	if rr == nil {
		return 0
	}
	elapsed := time.Since(cachedAt)
	if elapsed <= 0 {
		return rr.TTL
	}
	ttl := time.Duration(rr.TTL) * time.Second
	if elapsed >= ttl {
		return 0
	}
	return uint32((ttl - elapsed) / time.Second)
}
