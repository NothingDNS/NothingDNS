// Package protocol provides DNS protocol types for NothingDNS.
//
// Authority/Service record types: SOA, SRV.

package protocol

import (
	"fmt"
)

// RDataSOA represents an SOA record.
type RDataSOA struct {
	MName   *Name  // Primary master name server
	RName   *Name  // Responsible authority's mailbox
	Serial  uint32 // Serial number
	Refresh uint32 // Refresh interval
	Retry   uint32 // Retry interval
	Expire  uint32 // Expire limit
	Minimum uint32 // Minimum TTL
}

// Type returns TypeSOA.
func (r *RDataSOA) Type() uint16 { return TypeSOA }

// Pack serializes the SOA record.
func (r *RDataSOA) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil SOA record")
	}
	startOffset := offset

	// MName
	n, err := PackName(r.MName, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	// RName
	n, err = PackName(r.RName, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	// Check space for fixed fields
	if offset+20 > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Serial, Refresh, Retry, Expire, Minimum (5 x 4 bytes = 20 bytes)
	PutUint32(buf[offset:], r.Serial)
	offset += 4
	PutUint32(buf[offset:], r.Refresh)
	offset += 4
	PutUint32(buf[offset:], r.Retry)
	offset += 4
	PutUint32(buf[offset:], r.Expire)
	offset += 4
	PutUint32(buf[offset:], r.Minimum)
	offset += 4

	return offset - startOffset, nil
}

// Unpack deserializes the SOA record.
//
// Enforces the rdlength boundary so a peer cannot send an SOA whose
// declared RDLENGTH disagrees with the actual MName+RName+fixed
// fields. Without this check, a too-small RDLENGTH would let us
// read 20 fixed bytes from the FOLLOWING resource record's wire
// image as SOA fields, and we'd return n > rdlength to
// UnpackResourceRecord — corrupting every subsequent record's
// offset. Same class as the TXT rdlength-bypass fix.
func (r *RDataSOA) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil SOA record")
	}
	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// MName
	mname, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.MName = mname
	offset += n
	if offset > endOffset {
		mname.Release()
		return 0, fmt.Errorf("SOA MName overflows rdlength")
	}

	// RName
	rname, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.RName = rname
	offset += n
	if offset > endOffset {
		rname.Release()
		return 0, fmt.Errorf("SOA RName overflows rdlength")
	}

	// Check space for fixed fields against the rdlength boundary,
	// not just the overall buffer.
	if offset+20 > endOffset {
		return 0, fmt.Errorf("SOA fixed fields overflow rdlength")
	}

	// Serial, Refresh, Retry, Expire, Minimum
	r.Serial = Uint32(buf[offset:])
	offset += 4
	r.Refresh = Uint32(buf[offset:])
	offset += 4
	r.Retry = Uint32(buf[offset:])
	offset += 4
	r.Expire = Uint32(buf[offset:])
	offset += 4
	r.Minimum = Uint32(buf[offset:])
	offset += 4

	return offset - startOffset, nil
}

// String returns the SOA record data.
func (r *RDataSOA) String() string {
	if r == nil {
		return ""
	}
	mname := "."
	rname := "."
	if r.MName != nil {
		mname = r.MName.String()
	}
	if r.RName != nil {
		rname = r.RName.String()
	}
	return fmt.Sprintf("%s %s %d %d %d %d %d",
		mname, rname, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minimum,
	)
}

// Len returns the wire length.
func (r *RDataSOA) Len() int {
	if r == nil {
		return 0
	}
	mnameLen := 1
	rnameLen := 1
	if r.MName != nil {
		mnameLen = r.MName.WireLength()
	}
	if r.RName != nil {
		rnameLen = r.RName.WireLength()
	}
	return mnameLen + rnameLen + 20
}

// Copy creates a copy.
func (r *RDataSOA) Copy() RData {
	if r == nil {
		return nil
	}
	var mname, rname *Name
	if r.MName != nil {
		mname = r.MName.Copy()
	}
	if r.RName != nil {
		rname = r.RName.Copy()
	}
	copyR := rdataSOAPool.Get().(*RDataSOA)
	copyR.MName = mname
	copyR.RName = rname
	copyR.Serial = r.Serial
	copyR.Refresh = r.Refresh
	copyR.Retry = r.Retry
	copyR.Expire = r.Expire
	copyR.Minimum = r.Minimum
	return copyR
}

// ============================================================================
// SRV Record (Service Locator) - RFC 2782
// ============================================================================

// RDataSRV represents an SRV record.
type RDataSRV struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   *Name
}

// Type returns TypeSRV.
func (r *RDataSRV) Type() uint16 { return TypeSRV }

// Pack serializes the SRV record.
func (r *RDataSRV) Pack(buf []byte, offset int) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil SRV record")
	}
	startOffset := offset

	// Priority, Weight, Port
	if offset+6 > len(buf) {
		return 0, ErrBufferTooSmall
	}
	PutUint16(buf[offset:], r.Priority)
	offset += 2
	PutUint16(buf[offset:], r.Weight)
	offset += 2
	PutUint16(buf[offset:], r.Port)
	offset += 2

	// Target
	n, err := PackName(r.Target, buf, offset, nil)
	if err != nil {
		return 0, err
	}
	offset += n

	return offset - startOffset, nil
}

// Unpack deserializes the SRV record.
//
// Enforces the rdlength boundary so a malicious peer cannot
// declare a too-small RDLENGTH and have us advance past the
// next RR's start while consuming the Target's name + compression
// pointer bytes. Same rdlength-bypass class as the TXT / SOA fixes.
func (r *RDataSRV) Unpack(buf []byte, offset int, rdlength uint16) (int, error) {
	if r == nil {
		return 0, fmt.Errorf("nil SRV record")
	}
	startOffset := offset
	endOffset := offset + int(rdlength)
	if endOffset > len(buf) {
		return 0, ErrBufferTooSmall
	}

	// Priority, Weight, Port
	if offset+6 > endOffset {
		return 0, fmt.Errorf("SRV fixed fields overflow rdlength")
	}
	r.Priority = Uint16(buf[offset:])
	offset += 2
	r.Weight = Uint16(buf[offset:])
	offset += 2
	r.Port = Uint16(buf[offset:])
	offset += 2

	// Target
	target, n, err := UnpackName(buf, offset)
	if err != nil {
		return 0, err
	}
	r.Target = target
	offset += n
	if offset > endOffset {
		target.Release()
		return 0, fmt.Errorf("SRV Target overflows rdlength")
	}

	return offset - startOffset, nil
}

// String returns the SRV record data.
func (r *RDataSRV) String() string {
	if r == nil {
		return ""
	}
	target := "."
	if r.Target != nil {
		target = r.Target.String()
	}
	return fmt.Sprintf("%d %d %d %s", r.Priority, r.Weight, r.Port, target)
}

// Len returns the wire length.
func (r *RDataSRV) Len() int {
	if r == nil {
		return 0
	}
	if r.Target == nil {
		return 7
	}
	return 6 + r.Target.WireLength()
}

// Copy creates a copy.
func (r *RDataSRV) Copy() RData {
	if r == nil {
		return nil
	}
	var target *Name
	if r.Target != nil {
		target = r.Target.Copy()
	}
	copyR := rdataSRVPool.Get().(*RDataSRV)
	copyR.Priority = r.Priority
	copyR.Weight = r.Weight
	copyR.Port = r.Port
	copyR.Target = target
	return copyR
}
