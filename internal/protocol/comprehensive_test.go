package protocol

import (
	"encoding/binary"
	"strings"
	"testing"
)

// TestParseNameWithErrors tests error handling in ParseName
func TestParseNameWithErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		errMatch string
	}{
		{"root domain", ".", ""},
		{"root domain (not FQDN)", "", ""},
		{"label with underscore", "foo_bar.example.com", ""}, // underscore is allowed
		{"wildcard name", "*.example.com", ""},
		{"label too long", strings.Repeat("a", 64) + ".com", "too long"},
		{"invalid character in label", "foo bar.example.com", "invalid"},
		{"label with @", "foo@bar.example.com", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseName(tt.input)
			if tt.errMatch == "" {
				if err != nil {
					t.Errorf("ParseName(%q) unexpected error: %v", tt.input, err)
				}
			} else {
				if err == nil {
					t.Errorf("ParseName(%q) expected error containing %q", tt.input, tt.errMatch)
				} else if !strings.Contains(err.Error(), tt.errMatch) {
					t.Errorf("ParseName(%q) error = %v, want containing %q", tt.input, err, tt.errMatch)
				}
			}
		})
	}
}

// TestNameIsRoot tests Name.IsRoot
func TestNameIsRoot(t *testing.T) {
	n, _ := ParseName(".")
	if !n.IsRoot() {
		t.Error("Root domain should return true for IsRoot()")
	}

	n2, _ := ParseName("example.com.")
	if n2.IsRoot() {
		t.Error("Non-root domain should return false for IsRoot()")
	}
}

// TestNameIsWildcard tests Name.IsWildcard
func TestNameIsWildcard(t *testing.T) {
	n, _ := ParseName("*.example.com.")
	if !n.IsWildcard() {
		t.Error("Wildcard domain should return true for IsWildcard()")
	}

	n2, _ := ParseName("example.com.")
	if n2.IsWildcard() {
		t.Error("Non-wildcard domain should return false for IsWildcard()")
	}
}

// TestNameHasPrefix tests Name.HasPrefix
func TestNameHasPrefix(t *testing.T) {
	n, _ := ParseName("www.example.com.")

	if !n.HasPrefix([]string{"www"}) {
		t.Error("HasPrefix should return true for 'www'")
	}
	if !n.HasPrefix([]string{"www", "example"}) {
		t.Error("HasPrefix should return true for 'www.example'")
	}
	if n.HasPrefix([]string{"mail"}) {
		t.Error("HasPrefix should return false for 'mail'")
	}
	if n.HasPrefix([]string{"www", "example", "com", "org"}) {
		t.Error("HasPrefix should return false when prefix is longer than name")
	}
}

// TestNameHasSuffix tests Name.HasSuffix
func TestNameHasSuffix(t *testing.T) {
	n, _ := ParseName("www.example.com.")

	if !n.HasSuffix([]string{"com"}) {
		t.Error("HasSuffix should return true for 'com'")
	}
	if !n.HasSuffix([]string{"example", "com"}) {
		t.Error("HasSuffix should return true for 'example.com'")
	}
	if n.HasSuffix([]string{"org"}) {
		t.Error("HasSuffix should return false for 'org'")
	}
}

// TestNameEqual tests Name.Equal
func TestNameEqual(t *testing.T) {
	n1, _ := ParseName("www.example.com.")
	n2, _ := ParseName("WWW.EXAMPLE.COM.") // Case insensitive
	n3, _ := ParseName("example.com.")
	n4, _ := ParseName("www.example.com") // Not FQDN

	if !n1.Equal(n2) {
		t.Error("Equal should be case insensitive")
	}
	if n1.Equal(n3) {
		t.Error("Equal should return false for different names")
	}
	if n1.Equal(n4) {
		t.Error("Equal should return false when FQDN differs")
	}
}

// TestNameWireLength tests Name.WireLength
func TestNameWireLength(t *testing.T) {
	n, _ := ParseName("example.com.")
	// 1 + 7 + 1 + 3 + 1 = 13
	if n.WireLength() != 13 {
		t.Errorf("WireLength() = %d, want 13", n.WireLength())
	}

	root, _ := ParseName(".")
	if root.WireLength() != 1 {
		t.Errorf("Root WireLength() = %d, want 1", root.WireLength())
	}
}

// TestPackUnpackNameRoundTrip tests name pack/unpack round-trip
func TestPackUnpackNameRoundTrip(t *testing.T) {
	names := []string{
		".",
		"com.",
		"example.com.",
		"www.example.com.",
		"sub.domain.example.com.",
		"*.example.com.",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			n, err := ParseName(name)
			if err != nil {
				t.Fatalf("ParseName failed: %v", err)
			}

			buf := make([]byte, 256)
			written, err := PackName(n, buf, 0, nil)
			if err != nil {
				t.Fatalf("PackName failed: %v", err)
			}

			unpacked, consumed, err := UnpackName(buf, 0)
			if err != nil {
				t.Fatalf("UnpackName failed: %v", err)
			}
			if consumed != written {
				t.Errorf("Consumed bytes = %d, want %d", consumed, written)
			}
			if !n.Equal(unpacked) {
				t.Errorf("Unpacked name = %q, want %q", unpacked.String(), n.String())
			}
		})
	}
}

// TestPackNameErrors tests PackName error cases
func TestPackNameErrors(t *testing.T) {
	n, _ := ParseName("example.com.")

	// Invalid offset
	buf := make([]byte, 256)
	_, err := PackName(n, buf, -1, nil)
	if err == nil {
		t.Error("PackName should fail with negative offset")
	}

	_, err = PackName(n, buf, 300, nil)
	if err == nil {
		t.Error("PackName should fail with offset beyond buffer")
	}

	// Buffer too small
	buf = make([]byte, 5)
	_, err = PackName(n, buf, 0, nil)
	if err == nil {
		t.Error("PackName should fail with too small buffer")
	}
}

// TestUnpackNameErrors tests UnpackName error cases
func TestUnpackNameErrors(t *testing.T) {
	// Invalid offset
	_, _, err := UnpackName([]byte{0}, -1)
	if err == nil {
		t.Error("UnpackName should fail with negative offset")
	}

	// Empty buffer
	_, _, err = UnpackName([]byte{}, 0)
	if err == nil {
		t.Error("UnpackName should fail with empty buffer")
	}

	// Label too long (> 63 bytes)
	data := []byte{64} // length byte = 64
	for i := 0; i < 64; i++ {
		data = append(data, 'a')
	}
	data = append(data, 0) // terminator
	_, _, err = UnpackName(data, 0)
	if err == nil {
		t.Error("UnpackName should fail with label > 63 bytes")
	}
}

// TestUnpackNameWithPointer tests unpacking names with compression pointers
func TestUnpackNameWithPointer(t *testing.T) {
	// Create a message with compression
	data := []byte{
		// Name: example.com at offset 0
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		// Pointer to offset 0 at offset 13
		0xC0, 0x00,
	}

	name, consumed, err := UnpackName(data, 13)
	if err != nil {
		t.Fatalf("UnpackName with pointer failed: %v", err)
	}
	if consumed != 2 {
		t.Errorf("Consumed = %d, want 2", consumed)
	}
	if name.String() != "example.com." {
		t.Errorf("Name = %q, want 'example.com.'", name.String())
	}
}

// TestUnpackNamePointerTooDeep tests pointer depth limit
func TestUnpackNamePointerTooDeep(t *testing.T) {
	// Create a chain of pointers that exceeds MaxPointerDepth
	data := make([]byte, 100)
	for i := 0; i < MaxPointerDepth+1; i++ {
		data[i*2] = 0xC0
		data[i*2+1] = byte(i*2 + 2)
	}
	// Last one points to root
	data[(MaxPointerDepth+1)*2] = 0x00

	_, _, err := UnpackName(data, 0)
	if err == nil {
		t.Error("UnpackName should fail with pointer too deep")
	}
}

// TestUnpackNameInvalidPointer tests invalid pointer handling
func TestUnpackNameInvalidPointer(t *testing.T) {
	// Pointer to beyond buffer
	data := []byte{0xC0, 0x20} // Pointer to offset 32
	_, _, err := UnpackName(data, 0)
	if err == nil {
		t.Error("UnpackName should fail with pointer beyond buffer")
	}
}

// TestUnpackNamePointerLoop tests pointer loop detection
func TestUnpackNamePointerLoop(t *testing.T) {
	// Pointer that points to itself
	data := []byte{0xC0, 0x00}
	_, _, err := UnpackName(data, 0)
	// This should actually succeed as we have MaxPointerDepth limit
	// but let's verify it handles it
	if err != nil && !strings.Contains(err.Error(), "depth") {
		t.Errorf("Unexpected error: %v", err)
	}
}

// TestWireNameLength tests WireNameLength function
func TestWireNameLength(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		offset  int
		wantLen int
		wantErr bool
	}{
		{"root name", []byte{0x00}, 0, 1, false},
		{"simple name", []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00}, 0, 9, false},
		{"with pointer", []byte{0xC0, 0x00}, 0, 2, false},
		{"invalid offset", []byte{0x00}, -1, 0, true},
		{"label too long", []byte{64, 'a', 'a', 'a'}, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WireNameLength(tt.data, tt.offset)
			if tt.wantErr {
				if err == nil {
					t.Error("WireNameLength should return error")
				}
			} else {
				if err != nil {
					t.Errorf("WireNameLength unexpected error: %v", err)
				}
				if got != tt.wantLen {
					t.Errorf("WireNameLength = %d, want %d", got, tt.wantLen)
				}
			}
		})
	}
}

// TestCompareNames tests CompareNames function
func TestCompareNames(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"example.com.", "example.com.", 0},
		{"a.example.com.", "b.example.com.", -1},
		{"b.example.com.", "a.example.com.", 1},
		{"example.com.", "org.", -1}, // com < org
	}

	for _, tt := range tests {
		a, _ := ParseName(tt.a)
		b, _ := ParseName(tt.b)
		got := CompareNames(a, b)
		if got != tt.want {
			t.Errorf("CompareNames(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestIsSubdomain tests IsSubdomain function
func TestIsSubdomain(t *testing.T) {
	parent, _ := ParseName("example.com.")
	child, _ := ParseName("www.example.com.")
	other, _ := ParseName("other.org.")

	if !IsSubdomain(child, parent) {
		t.Error("www.example.com should be subdomain of example.com")
	}
	if IsSubdomain(parent, child) {
		t.Error("example.com should not be subdomain of www.example.com")
	}
	if IsSubdomain(other, parent) {
		t.Error("other.org should not be subdomain of example.com")
	}
}

// TestBufferFromData tests creating buffer from existing data
func TestBufferFromData(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	b := NewBufferFromData(data)

	if b.Length() != 5 {
		t.Errorf("Length mismatch: got %d, want 5", b.Length())
	}

	if b.Capacity() != 5 {
		t.Errorf("Capacity mismatch: got %d, want 5", b.Capacity())
	}

	v, err := b.ReadUint8()
	if err != nil {
		t.Fatalf("ReadUint8 failed: %v", err)
	}
	if v != 1 {
		t.Errorf("ReadUint8 mismatch: got %d, want 1", v)
	}
}

// TestBufferPool tests buffer pool operations
func TestBufferPool(t *testing.T) {
	b1 := GetBuffer()
	if b1 == nil {
		t.Fatal("GetBuffer returned nil")
	}

	b1.WriteUint8(1)
	b1.WriteUint8(2)

	PutBuffer(b1)

	b2 := GetBuffer()
	if b2 == nil {
		t.Fatal("GetBuffer returned nil after PutBuffer")
	}

	// Buffer should be reset
	if b2.Length() != 0 {
		t.Errorf("Buffer from pool should be reset, got length %d", b2.Length())
	}

	PutBuffer(b2)

	// Test PutBufferSized
	b3 := NewBuffer(10000)   // Large buffer
	PutBufferSized(b3, 5000) // Should be discarded (too large)
}

// TestSlicePool tests slice pool operations
func TestSlicePool(t *testing.T) {
	s1 := GetSlice()
	if s1 == nil {
		t.Fatal("GetSlice returned nil")
	}

	*s1 = append(*s1, 1, 2, 3)

	PutSlice(s1)

	s2 := GetSlice()
	if s2 == nil {
		t.Fatal("GetSlice returned nil after PutSlice")
	}

	// Slice should be reset
	if len(*s2) != 0 {
		t.Errorf("Slice from pool should be reset, got length %d", len(*s2))
	}

	PutSlice(s2)

	// Test PutSliceSized
	s3 := make([]byte, 0, 10000)
	PutSliceSized(&s3, 5000) // Should be discarded (too large)
}

// TestPutUnpackUint16 tests PutUint16 and UnpackUint16 helpers
func TestPutUnpackUint16(t *testing.T) {
	buf := make([]byte, 2)
	PutUint16(buf, 0x1234)
	if Uint16(buf) != 0x1234 {
		t.Errorf("Uint16 mismatch: got %x, want 0x1234", Uint16(buf))
	}

	// Test bit operations
	result := PackUint16(15, 14, 13) // Set bits 15, 14, 13
	if result != 0xE000 {
		t.Errorf("PackUint16 bits mismatch: got %x, want 0xE000", result)
	}

	if !UnpackUint16(result, 15) {
		t.Error("UnpackUint16 bit 15 should be set")
	}
	if !UnpackUint16(result, 14) {
		t.Error("UnpackUint16 bit 14 should be set")
	}
	if !UnpackUint16(result, 13) {
		t.Error("UnpackUint16 bit 13 should be set")
	}
}

// TestValidateMessage tests message validation
func TestValidateMessage(t *testing.T) {
	// Valid message (header only)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Flags
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(header[6:8], 0)      // ANCOUNT
	binary.BigEndian.PutUint16(header[8:10], 0)     // NSCOUNT
	binary.BigEndian.PutUint16(header[10:12], 0)    // ARCOUNT
	if err := ValidateMessage(header); err != nil {
		t.Errorf("ValidateMessage failed for valid header: %v", err)
	}

	// Too short
	if err := ValidateMessage([]byte{1, 2, 3}); err == nil {
		t.Error("ValidateMessage should fail for too short message")
	}
}

// TestUint48 tests 48-bit integer packing/unpacking
func TestUint48(t *testing.T) {
	buf := make([]byte, 6)
	PutUint48(buf, 0x123456789ABC)
	v := Uint48(buf)
	if v != 0x123456789ABC {
		t.Errorf("Uint48 mismatch: got %x, want 0x123456789ABC", v)
	}

	// Bounds: slices shorter than 6 return 0 from Uint48
	short := []byte{0x01, 0x02}
	if got := Uint48(short); got != 0 {
		t.Errorf("Uint48(short slice) = %d, want 0", got)
	}
	// PutUint48 with short slice is no-op (no panics)
	PutUint48(short, 0xDEADBEEF)
	if short[0] != 0x01 {
		t.Errorf("PutUint48 wrote to short slice unexpectedly")
	}
}

// TestNewHeader tests NewHeader
func TestNewHeader(t *testing.T) {
	h := NewHeader()
	if h == nil {
		t.Fatal("NewHeader returned nil")
	}
	if h.ID != 0 {
		t.Errorf("NewHeader ID: got %d, want 0", h.ID)
	}
	if h.Flags.QR {
		t.Error("NewHeader should not have QR set")
	}
	if !h.Flags.RD {
		t.Error("NewHeader should have RD set")
	}
	if h.QDCount != 0 || h.ANCount != 0 || h.NSCount != 0 || h.ARCount != 0 {
		t.Error("NewHeader counts should all be 0")
	}
}

// TestHeaderSetResponse tests SetResponse
func TestHeaderSetResponse(t *testing.T) {
	h := NewHeader()
	h.SetResponse(RcodeSuccess)

	if !h.Flags.QR {
		t.Error("SetResponse should set QR")
	}
	if h.Flags.RCODE != RcodeSuccess {
		t.Errorf("SetResponse RCODE: got %d, want %d", h.Flags.RCODE, RcodeSuccess)
	}
}

// TestHeaderSetTruncated tests SetTruncated
func TestHeaderSetTruncated(t *testing.T) {
	h := NewHeader()
	h.SetTruncated(true)

	if !h.Flags.TC {
		t.Error("SetTruncated(true) should set TC")
	}

	h.SetTruncated(false)
	if h.Flags.TC {
		t.Error("SetTruncated(false) should clear TC")
	}
}

// TestHeaderSetAuthoritative tests SetAuthoritative
func TestHeaderSetAuthoritative(t *testing.T) {
	h := NewHeader()
	h.SetAuthoritative(true)

	if !h.Flags.AA {
		t.Error("SetAuthoritative(true) should set AA")
	}

	h.SetAuthoritative(false)
	if h.Flags.AA {
		t.Error("SetAuthoritative(false) should clear AA")
	}
}

// TestHeaderClearCounts tests ClearCounts
func TestHeaderClearCounts(t *testing.T) {
	h := Header{
		QDCount: 1,
		ANCount: 2,
		NSCount: 3,
		ARCount: 4,
	}
	h.ClearCounts()

	if h.QDCount != 0 || h.ANCount != 0 || h.NSCount != 0 || h.ARCount != 0 {
		t.Error("ClearCounts should set all counts to 0")
	}
}

// TestHeaderIsSuccess tests IsSuccess
func TestHeaderIsSuccess(t *testing.T) {
	h := Header{Flags: Flags{RCODE: RcodeSuccess}}
	if !h.IsSuccess() {
		t.Error("IsSuccess should return true for RcodeSuccess")
	}

	h.Flags.RCODE = RcodeServerFailure
	if h.IsSuccess() {
		t.Error("IsSuccess should return false for non-success RCODE")
	}
}

// TestHeaderCopy tests Header.Copy
func TestHeaderCopy(t *testing.T) {
	h1 := Header{
		ID:      0x1234,
		Flags:   Flags{QR: true, RD: true},
		QDCount: 1,
		ANCount: 2,
		NSCount: 3,
		ARCount: 4,
	}
	h2 := h1.Copy()

	if h2.ID != h1.ID {
		t.Errorf("Copy ID mismatch")
	}
	if h2.Flags != h1.Flags {
		t.Errorf("Copy Flags mismatch")
	}
	// Verify original is not modified
	h1.ID = 0xFFFF
	if h1.ID == h2.ID {
		t.Errorf("Modifying original should not affect copy")
	}
}

// TestHeaderPackErrors tests header packing error cases
func TestHeaderPackErrors(t *testing.T) {
	h := Header{ID: 0x1234}
	buf := make([]byte, 10) // Too small
	if err := h.Pack(buf); err == nil {
		t.Error("Pack should fail with too small buffer")
	}
}

// TestHeaderUnpackErrors tests header unpacking error cases
func TestHeaderUnpackErrors(t *testing.T) {
	buf := make([]byte, 10) // Too small
	h := Header{}
	if err := h.Unpack(buf); err == nil {
		t.Error("Unpack should fail with too small buffer")
	}
}

// TestFlagsMethods tests Flags helper methods
func TestFlagsMethods(t *testing.T) {
	f := Flags{QR: false}
	if !f.IsQuery() {
		t.Error("IsQuery should return true when QR is false")
	}
	if f.IsResponse() {
		t.Error("IsResponse should return false when QR is false")
	}

	f.QR = true
	if !f.IsResponse() {
		t.Error("IsResponse should return true when QR is true")
	}
	if f.IsQuery() {
		t.Error("IsQuery should return false when QR is true")
	}

	// Test all flag methods
	f = Flags{
		AA: true,
		TC: true,
		RD: true,
		RA: true,
		AD: true,
		CD: true,
	}

	if !f.IsAuthoritative() {
		t.Error("IsAuthoritative should return true")
	}
	if !f.IsTruncated() {
		t.Error("IsTruncated should return true")
	}
	if !f.RecursionDesired() {
		t.Error("RecursionDesired should return true")
	}
	if !f.RecursionAvailable() {
		t.Error("RecursionAvailable should return true")
	}
	if !f.AuthenticData() {
		t.Error("AuthenticData should return true")
	}
	if !f.CheckingDisabled() {
		t.Error("CheckingDisabled should return true")
	}
}

// TestFlagsString tests Flags.String
func TestFlagsString(t *testing.T) {
	tests := []struct {
		name    string
		flags   Flags
		wantHas []string
	}{
		{
			name:    "query",
			flags:   NewQueryFlags(),
			wantHas: []string{"rd", "NOERROR"},
		},
		{
			name:    "response",
			flags:   NewResponseFlags(RcodeSuccess),
			wantHas: []string{"qr", "aa", "ra", "NOERROR"},
		},
		{
			name:    "all_flags",
			flags:   Flags{QR: true, Opcode: OpcodeQuery, AA: true, TC: true, RD: true, RA: true, AD: true, CD: true, RCODE: RcodeRefused},
			wantHas: []string{"qr", "aa", "tc", "rd", "ra", "ad", "cd", "REFUSED"},
		},
		{
			name:    "opcode_notify",
			flags:   Flags{Opcode: OpcodeNotify, RCODE: RcodeSuccess},
			wantHas: []string{"NOTIFY", "NOERROR"},
		},
		{
			name:    "opcode_update",
			flags:   Flags{Opcode: OpcodeUpdate, RCODE: RcodeSuccess},
			wantHas: []string{"UPDATE", "NOERROR"},
		},
		{
			name:    "opcode_status",
			flags:   Flags{Opcode: OpcodeStatus, RCODE: RcodeSuccess},
			wantHas: []string{"STATUS", "NOERROR"},
		},
		{
			name:    "opcode_iquery",
			flags:   Flags{Opcode: OpcodeIQuery, RCODE: RcodeSuccess},
			wantHas: []string{"IQUERY", "NOERROR"},
		},
		{
			name:    "unknown_opcode",
			flags:   Flags{Opcode: 15, RCODE: RcodeSuccess},
			wantHas: []string{"OPCODE15", "NOERROR"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.flags.String()
			for _, want := range tt.wantHas {
				if !strings.Contains(s, want) {
					t.Errorf("Flags.String() = %q, should contain %q", s, want)
				}
			}
		})
	}
}

// TestHeaderString tests Header.String
func TestHeaderString(t *testing.T) {
	h := Header{
		ID:      0x1234,
		Flags:   NewResponseFlags(RcodeSuccess),
		QDCount: 1,
		ANCount: 2,
		NSCount: 0,
		ARCount: 0,
	}
	s := h.String()
	if !strings.Contains(s, "NOERROR") {
		t.Errorf("Header.String() should contain status: %q", s)
	}
}

// TestQuestionHelperMethods tests helper methods
func TestQuestionHelperMethods(t *testing.T) {
	tests := []struct {
		name   string
		create func(string) (*Question, error)
		qtype  uint16
	}{
		{"NewAQuestion", NewAQuestion, TypeA},
		{"NewAAAAQuestion", NewAAAAQuestion, TypeAAAA},
		{"NewMXQuestion", NewMXQuestion, TypeMX},
		{"NewNSQuestion", NewNSQuestion, TypeNS},
		{"NewSOAQuestion", NewSOAQuestion, TypeSOA},
		{"NewTXTQuestion", NewTXTQuestion, TypeTXT},
		{"NewCNAMEQuestion", NewCNAMEQuestion, TypeCNAME},
		{"NewPTRQuestion", NewPTRQuestion, TypePTR},
		{"NewSRVQuestion", NewSRVQuestion, TypeSRV},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := tt.create("example.com.")
			if err != nil {
				t.Fatalf("%s failed: %v", tt.name, err)
			}
			if q.QType != tt.qtype {
				t.Errorf("%s QType: got %d, want %d", tt.name, q.QType, tt.qtype)
			}
			if q.QClass != ClassIN {
				t.Errorf("%s QClass: got %d, want %d", tt.name, q.QClass, ClassIN)
			}
		})
	}
}

// TestQuestionIsEDNS tests IsEDNS
func TestQuestionIsEDNS(t *testing.T) {
	q := must(NewQuestion("example.com.", TypeOPT, ClassIN))
	if !q.IsEDNS() {
		t.Error("IsEDNS should return true for OPT type")
	}

	q2 := must(NewQuestion("example.com.", TypeA, ClassIN))
	if q2.IsEDNS() {
		t.Error("IsEDNS should return false for non-OPT type")
	}
}

// TestQuestionIsClassANY tests IsClassANY
func TestQuestionIsClassANY(t *testing.T) {
	q := must(NewQuestion("example.com.", TypeA, ClassANY))
	if !q.IsClassANY() {
		t.Error("IsClassANY should return true for ANY class")
	}

	q2 := must(NewQuestion("example.com.", TypeA, ClassIN))
	if q2.IsClassANY() {
		t.Error("IsClassANY should return false for non-ANY class")
	}
}

// TestQuestionMatchesType tests MatchesType
func TestQuestionMatchesType(t *testing.T) {
	q := must(NewQuestion("example.com.", TypeA, ClassIN))
	if !q.MatchesType(TypeA) {
		t.Error("MatchesType should return true for matching type")
	}
	if q.MatchesType(TypeAAAA) {
		t.Error("MatchesType should return false for non-matching type")
	}

	qAny := must(NewQuestion("example.com.", TypeANY, ClassIN))
	if !qAny.MatchesType(TypeA) {
		t.Error("MatchesType should return true for TypeANY wildcard")
	}
}

// TestQuestionMatchesClass tests MatchesClass
func TestQuestionMatchesClass(t *testing.T) {
	q := must(NewQuestion("example.com.", TypeA, ClassIN))
	if !q.MatchesClass(ClassIN) {
		t.Error("MatchesClass should return true for matching class")
	}
	if q.MatchesClass(ClassCH) {
		t.Error("MatchesClass should return false for non-matching class")
	}

	qAny := must(NewQuestion("example.com.", TypeA, ClassANY))
	if !qAny.MatchesClass(ClassIN) {
		t.Error("MatchesClass should return true for ClassANY wildcard")
	}
}

// TestQuestionWireLength tests WireLength
func TestQuestionWireLength(t *testing.T) {
	q := must(NewQuestion("example.com.", TypeA, ClassIN))
	// example.com. = 13 bytes (1 + 7 + 1 + 3 + 1) + 4 (type + class) = 17
	expectedLen := 17
	if q.WireLength() != expectedLen {
		t.Errorf("WireLength: got %d, want %d", q.WireLength(), expectedLen)
	}
}

// TestQuestionPackErrors tests question packing error cases
func TestQuestionPackErrors(t *testing.T) {
	q := must(NewQuestion("example.com.", TypeA, ClassIN))

	// Too small buffer for name
	buf := make([]byte, 5)
	_, err := q.Pack(buf, 0, nil)
	if err == nil {
		t.Error("Pack should fail with too small buffer")
	}

	// Too small buffer for type/class
	buf = make([]byte, 15)
	_, err = q.Pack(buf, 10, nil) // offset near end
	if err == nil {
		t.Error("Pack should fail with insufficient buffer for type/class")
	}
}

// TestQuestionUnpackErrors tests question unpacking error cases
func TestQuestionUnpackErrors(t *testing.T) {
	// Too short for name
	_, _, err := UnpackQuestion([]byte{0x07, 'e', 'x', 'a'}, 0)
	if err == nil {
		t.Error("UnpackQuestion should fail with truncated name")
	}

	// Too short for type/class
	name := []byte{0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00}
	_, _, err = UnpackQuestion(name, 0) // missing type/class
	if err == nil {
		t.Error("UnpackQuestion should fail with truncated type/class")
	}
}

// TestQuestionCopy tests Question.Copy
func TestQuestionCopy(t *testing.T) {
	q1 := must(NewQuestion("example.com.", TypeA, ClassIN))
	q2 := q1.Copy()

	if q2 == nil {
		t.Fatal("Copy returned nil")
	}

	if !q1.Name.Equal(q2.Name) {
		t.Error("Copy name mismatch")
	}
	if q1.QType != q2.QType {
		t.Errorf("Copy QType mismatch: got %d, want %d", q2.QType, q1.QType)
	}
	if q1.QClass != q2.QClass {
		t.Errorf("Copy QClass mismatch: got %d, want %d", q2.QClass, q1.QClass)
	}

	// Test nil copy
	var nilQ *Question
	if nilQ.Copy() != nil {
		t.Error("Copy on nil should return nil")
	}
}

// TestQuestionString tests Question.String
func TestQuestionString(t *testing.T) {
	q := must(NewQuestion("example.com.", TypeA, ClassIN))
	s := q.String()
	if !strings.Contains(s, "example.com.") {
		t.Errorf("String should contain name: %q", s)
	}
	if !strings.Contains(s, "IN") {
		t.Errorf("String should contain class: %q", s)
	}
	if !strings.Contains(s, "A") {
		t.Errorf("String should contain type: %q", s)
	}
}
