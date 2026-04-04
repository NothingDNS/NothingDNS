package quic

import (
	"bytes"
	"testing"
)

// =================== Varint Tests ===================

func TestDecodeVarint1Byte(t *testing.T) {
	// 1-byte encoding: prefix 00, value 0-63
	tests := []struct {
		data   []byte
		want   uint64
		wantN  int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x01}, 1, 1},
		{[]byte{0x3f}, 63, 1},
		{[]byte{0x25}, 37, 1},
	}
	for _, tc := range tests {
		got, n := DecodeVarint(tc.data)
		if got != tc.want || n != tc.wantN {
			t.Errorf("DecodeVarint(%x) = (%d, %d), want (%d, %d)", tc.data, got, n, tc.want, tc.wantN)
		}
	}
}

func TestDecodeVarint2Byte(t *testing.T) {
	// 2-byte encoding: prefix 01
	tests := []struct {
		data  []byte
		want  uint64
		wantN int
	}{
		{[]byte{0x40, 0x00}, 0, 2},
		{[]byte{0x40, 0x01}, 1, 2},
		{[]byte{0x7f, 0xff}, 16383, 2},
		{[]byte{0x41, 0x00}, 256, 2},
	}
	for _, tc := range tests {
		got, n := DecodeVarint(tc.data)
		if got != tc.want || n != tc.wantN {
			t.Errorf("DecodeVarint(%x) = (%d, %d), want (%d, %d)", tc.data, got, n, tc.want, tc.wantN)
		}
	}
}

func TestDecodeVarint4Byte(t *testing.T) {
	// 4-byte encoding: prefix 10
	tests := []struct {
		data  []byte
		want  uint64
		wantN int
	}{
		{[]byte{0x80, 0x00, 0x00, 0x01}, 1, 4},
		{[]byte{0x80, 0x00, 0x01, 0x00}, 256, 4},
		{[]byte{0xbf, 0xff, 0xff, 0xff}, 1073741823, 4},
	}
	for _, tc := range tests {
		got, n := DecodeVarint(tc.data)
		if got != tc.want || n != tc.wantN {
			t.Errorf("DecodeVarint(%x) = (%d, %d), want (%d, %d)", tc.data, got, n, tc.want, tc.wantN)
		}
	}
}

func TestDecodeVarint8Byte(t *testing.T) {
	// 8-byte encoding: prefix 11
	data := []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a}
	got, n := DecodeVarint(data)
	if got != 42 || n != 8 {
		t.Errorf("DecodeVarint(%x) = (%d, %d), want (42, 8)", data, got, n)
	}
}

func TestDecodeVarintTooShort(t *testing.T) {
	// 2-byte prefix but only 1 byte
	got, n := DecodeVarint([]byte{0x40})
	if got != 0 || n != 0 {
		t.Errorf("DecodeVarint(truncated) = (%d, %d), want (0, 0)", got, n)
	}
}

func TestDecodeVarintEmpty(t *testing.T) {
	got, n := DecodeVarint(nil)
	if got != 0 || n != 0 {
		t.Errorf("DecodeVarint(nil) = (%d, %d), want (0, 0)", got, n)
	}
}

func TestAppendVarint(t *testing.T) {
	tests := []struct {
		val  uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{37, []byte{0x25}},
		{63, []byte{0x3f}},
		{64, []byte{0x40, 0x40}},
		{16383, []byte{0x7f, 0xff}},
		{16384, []byte{0x80, 0x00, 0x40, 0x00}},
	}
	for _, tc := range tests {
		got := AppendVarint(nil, tc.val)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("AppendVarint(%d) = %x, want %x", tc.val, got, tc.want)
		}

		// Round-trip
		decoded, n := DecodeVarint(got)
		if decoded != tc.val {
			t.Errorf("round-trip: DecodeVarint(AppendVarint(%d)) = %d", tc.val, decoded)
		}
		if n != len(got) {
			t.Errorf("round-trip: consumed %d bytes, encoded as %d", n, len(got))
		}
	}
}

func TestEncodeVarintLen(t *testing.T) {
	tests := []struct {
		val  uint64
		want int
	}{
		{0, 1},
		{63, 1},
		{64, 2},
		{16383, 2},
		{16384, 4},
		{1073741823, 4},
		{1073741824, 8},
	}
	for _, tc := range tests {
		got := EncodeVarintLen(tc.val)
		if got != tc.want {
			t.Errorf("EncodeVarintLen(%d) = %d, want %d", tc.val, got, tc.want)
		}
	}
}

// =================== Packet Header Tests ===================

func TestIsLongHeader(t *testing.T) {
	tests := []struct {
		b    byte
		want bool
	}{
		{0xc0, true},  // 1100 0000
		{0x80, true},  // 1000 0000
		{0xff, true},  // 1111 1111
		{0x40, false}, // 0100 0000
		{0x00, false}, // 0000 0000
		{0x7f, false}, // 0111 1111
	}
	for _, tc := range tests {
		got := IsLongHeader(tc.b)
		if got != tc.want {
			t.Errorf("IsLongHeader(0x%02x) = %v, want %v", tc.b, got, tc.want)
		}
	}
}

func TestParsePacketType(t *testing.T) {
	tests := []struct {
		b    byte
		want uint8
	}{
		{0xc0, 0x0}, // Initial
		{0xd0, 0x1}, // 0-RTT
		{0xe0, 0x2}, // Handshake
		{0xf0, 0x3}, // Retry
	}
	for _, tc := range tests {
		got := ParsePacketType(tc.b)
		if got != tc.want {
			t.Errorf("ParsePacketType(0x%02x) = %d, want %d", tc.b, got, tc.want)
		}
	}
}

func TestParseLongHeader(t *testing.T) {
	// Build a minimal Initial packet header
	// First byte: 1|1|00|00|01 = 0xC1 (long header, Initial, 2-byte pkt num)
	// Version: 0x00000001
	// DCID len: 8, DCID: 0102030405060708
	// SCID len: 0
	// Token len: 0
	// Length: varint
	// Pkt num: 0x0000
	data := []byte{
		0xC1,                                           // first byte
		0x00, 0x00, 0x00, 0x01,                         // version
		0x08,                                           // DCID len
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x00,                                           // SCID len
		0x00,                                           // Token len
		0x03,                                           // Length (varint, 1 byte = 3)
		0x00, 0x00,                                     // Packet number + payload
		0xAA,                                           // payload byte
	}

	hdr, consumed, err := ParseLongHeader(data)
	if err != nil {
		t.Fatalf("ParseLongHeader: %v", err)
	}

	if hdr.Type != PacketTypeInitial {
		t.Errorf("Type = %d, want %d", hdr.Type, PacketTypeInitial)
	}
	if hdr.Version != Version1 {
		t.Errorf("Version = %d, want %d", hdr.Version, Version1)
	}
	if len(hdr.DestConnID) != 8 {
		t.Errorf("DestConnID len = %d, want 8", len(hdr.DestConnID))
	}
	if len(hdr.SrcConnID) != 0 {
		t.Errorf("SrcConnID len = %d, want 0", len(hdr.SrcConnID))
	}
	_ = consumed
}

func TestParseLongHeaderTooShort(t *testing.T) {
	_, _, err := ParseLongHeader([]byte{0xC0})
	if err == nil {
		t.Error("expected error for too-short packet")
	}
}

func TestParseLongHeaderInvalidConnID(t *testing.T) {
	data := []byte{
		0xC0,                   // first byte
		0x00, 0x00, 0x00, 0x01, // version
		0x15, // DCID len = 21 (too large)
	}
	_, _, err := ParseLongHeader(data)
	if err == nil {
		t.Error("expected error for invalid connection ID")
	}
}

func TestBuildLongHeader(t *testing.T) {
	hdr := &LongHeader{
		Type:       PacketTypeInitial,
		Version:    Version1,
		DestConnID: ConnectionID{1, 2, 3, 4, 5, 6, 7, 8},
		SrcConnID:  ConnectionID{},
		Payload:    []byte{0xAA, 0xBB},
	}

	pkt, err := BuildLongHeader(hdr, 0, 1)
	if err != nil {
		t.Fatalf("BuildLongHeader: %v", err)
	}

	if len(pkt) == 0 {
		t.Error("expected non-empty packet")
	}

	// Verify it parses back
	parsed, _, err := ParseLongHeader(pkt)
	if err != nil {
		t.Fatalf("ParseLongHeader round-trip: %v", err)
	}
	if parsed.Type != PacketTypeInitial {
		t.Errorf("Type = %d, want %d", parsed.Type, PacketTypeInitial)
	}
	if !parsed.DestConnID.Equal(hdr.DestConnID) {
		t.Errorf("DestConnID mismatch: got %v, want %v", parsed.DestConnID, hdr.DestConnID)
	}
}

func TestBuildLongHeaderInvalidPktNumLen(t *testing.T) {
	hdr := &LongHeader{
		Type:       PacketTypeInitial,
		Version:    Version1,
		DestConnID: ConnectionID{1, 2, 3, 4},
		SrcConnID:  ConnectionID{},
	}
	_, err := BuildLongHeader(hdr, 0, 5)
	if err == nil {
		t.Error("expected error for invalid packet number length")
	}
}

func TestParseShortHeader(t *testing.T) {
	connIDLen := 4
	data := []byte{
		0x40,       // short header first byte
		0x01, 0x02, 0x03, 0x04, // DCID
		0xAA, 0xBB, // payload
	}

	hdr, consumed, err := ParseShortHeader(data, connIDLen)
	if err != nil {
		t.Fatalf("ParseShortHeader: %v", err)
	}

	if len(hdr.DestConnID) != connIDLen {
		t.Errorf("DestConnID len = %d, want %d", len(hdr.DestConnID), connIDLen)
	}
	if consumed != 1+connIDLen {
		t.Errorf("consumed = %d, want %d", consumed, 1+connIDLen)
	}
}

func TestParseShortHeaderLongHeader(t *testing.T) {
	data := []byte{0xC0, 0x00, 0x00, 0x00, 0x01}
	_, _, err := ParseShortHeader(data, 4)
	if err == nil {
		t.Error("expected error when passing long header to ParseShortHeader")
	}
}

// =================== ConnectionID Tests ===================

func TestConnectionIDEqual(t *testing.T) {
	a := ConnectionID{1, 2, 3, 4}
	b := ConnectionID{1, 2, 3, 4}
	c := ConnectionID{1, 2, 3, 5}
	d := ConnectionID{1, 2, 3}

	if !a.Equal(b) {
		t.Error("equal ConnectionIDs should be equal")
	}
	if a.Equal(c) {
		t.Error("different ConnectionIDs should not be equal")
	}
	if a.Equal(d) {
		t.Error("different length ConnectionIDs should not be equal")
	}
}

func TestConnectionIDString(t *testing.T) {
	cid := ConnectionID{0x01, 0x02, 0xab, 0xcd}
	s := cid.String()
	if s != "0102abcd" {
		t.Errorf("ConnectionID.String() = %q, want %q", s, "0102abcd")
	}
}

func TestGenerateConnectionID(t *testing.T) {
	cid, err := GenerateConnectionID(8)
	if err != nil {
		t.Fatalf("GenerateConnectionID: %v", err)
	}
	if len(cid) != 8 {
		t.Errorf("len = %d, want 8", len(cid))
	}

	// Two generated CIDs should be different (probabilistic but extremely unlikely to fail)
	cid2, _ := GenerateConnectionID(8)
	if cid.Equal(cid2) {
		t.Error("two random CIDs should differ")
	}
}

func TestGenerateConnectionIDInvalidLength(t *testing.T) {
	_, err := GenerateConnectionID(0)
	if err == nil {
		t.Error("expected error for zero-length CID")
	}
	_, err = GenerateConnectionID(21)
	if err == nil {
		t.Error("expected error for too-long CID")
	}
}

func TestGenerateInitialConnectionID(t *testing.T) {
	cid, err := GenerateInitialConnectionID()
	if err != nil {
		t.Fatalf("GenerateInitialConnectionID: %v", err)
	}
	if len(cid) != MinInitialConnIDLen {
		t.Errorf("len = %d, want %d", len(cid), MinInitialConnIDLen)
	}
}

// =================== Transport Params Tests ===================

func TestDefaultTransportParams(t *testing.T) {
	tp := DefaultTransportParams()
	if tp.MaxUDPPayloadSize != DefaultMaxUDPPayloadSize {
		t.Errorf("MaxUDPPayloadSize = %d, want %d", tp.MaxUDPPayloadSize, DefaultMaxUDPPayloadSize)
	}
	if tp.InitialMaxData != DefaultInitialMaxData {
		t.Errorf("InitialMaxData = %d, want %d", tp.InitialMaxData, DefaultInitialMaxData)
	}
	if tp.InitialMaxStreamsBidi != DefaultInitialMaxStreamsBidi {
		t.Errorf("InitialMaxStreamsBidi = %d, want %d", tp.InitialMaxStreamsBidi, DefaultInitialMaxStreamsBidi)
	}
	if err := tp.Validate(); err != nil {
		t.Errorf("default params should validate: %v", err)
	}
}

func TestTransportParamsEncodeDecode(t *testing.T) {
	tp := DefaultTransportParams()

	encoded := tp.Encode()
	decoded, err := DecodeTransportParams(encoded)
	if err != nil {
		t.Fatalf("DecodeTransportParams: %v", err)
	}

	if decoded.MaxUDPPayloadSize != tp.MaxUDPPayloadSize {
		t.Errorf("MaxUDPPayloadSize = %d, want %d", decoded.MaxUDPPayloadSize, tp.MaxUDPPayloadSize)
	}
	if decoded.InitialMaxData != tp.InitialMaxData {
		t.Errorf("InitialMaxData = %d, want %d", decoded.InitialMaxData, tp.InitialMaxData)
	}
	if decoded.InitialMaxStreamsBidi != tp.InitialMaxStreamsBidi {
		t.Errorf("InitialMaxStreamsBidi = %d, want %d", decoded.InitialMaxStreamsBidi, tp.InitialMaxStreamsBidi)
	}
}

func TestTransportParamsValidateTooSmall(t *testing.T) {
	tp := DefaultTransportParams()
	tp.MaxUDPPayloadSize = 1000
	if err := tp.Validate(); err == nil {
		t.Error("expected validation error for small MaxUDPPayloadSize")
	}
}

func TestTransportParamsValidateTooManyStreams(t *testing.T) {
	tp := DefaultTransportParams()
	tp.InitialMaxStreamsBidi = 70000
	if err := tp.Validate(); err == nil {
		t.Error("expected validation error for too many streams")
	}
}

func TestTransportParamsForTLS(t *testing.T) {
	tp := DefaultTransportParams()
	encoded := EncodeTransportParamsForTLS(tp)
	if len(encoded) == 0 {
		t.Error("expected non-empty encoded transport params")
	}

	decoded, err := DecodeTransportParamsFromTLS(encoded)
	if err != nil {
		t.Fatalf("DecodeTransportParamsFromTLS: %v", err)
	}
	if decoded.InitialMaxData != tp.InitialMaxData {
		t.Errorf("InitialMaxData = %d, want %d", decoded.InitialMaxData, tp.InitialMaxData)
	}
}

// =================== Stream Tests ===================

func TestStreamReadAfterClose(t *testing.T) {
	s := &Stream{}
	s.AppendReadData([]byte("hello"), false)
	s.Close()

	buf := make([]byte, 10)
	n, err := s.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("Read = %q, want %q", string(buf[:n]), "hello")
	}

	// After draining, should get EOF
	_, err = s.Read(buf)
	if err == nil {
		t.Error("expected EOF after draining")
	}
}

func TestStreamWriteAfterClose(t *testing.T) {
	s := &Stream{}
	s.Close()
	_, err := s.Write([]byte("data"))
	if err == nil {
		t.Error("expected error writing to closed stream")
	}
}

func TestStreamAppendReadDataWithFin(t *testing.T) {
	s := &Stream{}
	s.AppendReadData([]byte("data"), true)

	buf := make([]byte, 10)
	n, _ := s.Read(buf)
	if string(buf[:n]) != "data" {
		t.Errorf("Read = %q, want %q", string(buf[:n]), "data")
	}

	_, err := s.Read(buf)
	if err == nil {
		t.Error("expected EOF after fin")
	}
}

// =================== Config Tests ===================

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}
	if cfg.MaxStreams != DefaultInitialMaxStreamsBidi {
		t.Errorf("MaxStreams = %d, want %d", cfg.MaxStreams, DefaultInitialMaxStreamsBidi)
	}
	if cfg.TransportParams == nil {
		t.Error("TransportParams should not be nil")
	}
}

// =================== Frame Tests ===================

func TestBuildAndParseStreamFrame(t *testing.T) {
	sf := &StreamFrame{
		StreamID: 0,
		Data:     []byte("hello quic"),
		Fin:      true,
	}

	encoded := BuildStreamFrame(sf, false, true)

	// First byte is the frame type
	frameType := encoded[0]
	parsed, consumed, err := ParseStreamFrame(frameType, encoded[1:])
	if err != nil {
		t.Fatalf("ParseStreamFrame: %v", err)
	}

	if parsed.StreamID != sf.StreamID {
		t.Errorf("StreamID = %d, want %d", parsed.StreamID, sf.StreamID)
	}
	if string(parsed.Data) != string(sf.Data) {
		t.Errorf("Data = %q, want %q", string(parsed.Data), string(sf.Data))
	}
	if !parsed.Fin {
		t.Error("Fin should be true")
	}
	_ = consumed
}

func TestBuildAndParseStreamFrameWithOffset(t *testing.T) {
	sf := &StreamFrame{
		StreamID: 4,
		Offset:   1024,
		Data:     []byte("data"),
		Fin:      false,
	}

	encoded := BuildStreamFrame(sf, true, true)
	frameType := encoded[0]
	parsed, _, err := ParseStreamFrame(frameType, encoded[1:])
	if err != nil {
		t.Fatalf("ParseStreamFrame: %v", err)
	}
	if parsed.Offset != sf.Offset {
		t.Errorf("Offset = %d, want %d", parsed.Offset, sf.Offset)
	}
}

func TestBuildAndParseCryptoFrame(t *testing.T) {
	cf := &CryptoFrame{
		Offset: 0,
		Data:   []byte{0x01, 0x02, 0x03},
	}

	encoded := BuildCryptoFrame(cf)
	parsed, consumed, err := ParseCryptoFrame(encoded[1:]) // skip frame type byte
	if err != nil {
		t.Fatalf("ParseCryptoFrame: %v", err)
	}
	if parsed.Offset != cf.Offset {
		t.Errorf("Offset = %d, want %d", parsed.Offset, cf.Offset)
	}
	if !bytes.Equal(parsed.Data, cf.Data) {
		t.Errorf("Data = %v, want %v", parsed.Data, cf.Data)
	}
	_ = consumed
}

// =================== PacketNumberLen Tests ===================

func TestPacketNumberLen(t *testing.T) {
	tests := []struct {
		pn   uint64
		want int
	}{
		{0, 1},
		{255, 1},
		{256, 2},
		{65535, 2},
		{65536, 3},
		{16777215, 3},
		{16777216, 4},
	}
	for _, tc := range tests {
		got := PacketNumberLen(tc.pn)
		if got != tc.want {
			t.Errorf("PacketNumberLen(%d) = %d, want %d", tc.pn, got, tc.want)
		}
	}
}
