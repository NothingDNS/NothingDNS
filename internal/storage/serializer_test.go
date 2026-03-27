package storage

import (
	"bytes"
	"testing"
)

func TestTLVEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		typ   byte
		value []byte
	}{
		{"simple", TypeRecord, []byte("hello world")},
		{"empty", TypeRecord, []byte{}},
		{"binary", TypeIndex, []byte{0x00, 0x01, 0x02, 0xFF}},
		{"zone", TypeZone, []byte("example.com")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded, err := EncodeTLV(tt.typ, tt.value)
			if err != nil {
				t.Fatalf("EncodeTLV failed: %v", err)
			}

			// Decode
			decoded, size, err := DecodeTLV(encoded)
			if err != nil {
				t.Fatalf("DecodeTLV failed: %v", err)
			}

			if size != len(encoded) {
				t.Errorf("Expected size %d, got %d", len(encoded), size)
			}

			if decoded.Type != tt.typ {
				t.Errorf("Expected type %d, got %d", tt.typ, decoded.Type)
			}

			if !bytes.Equal(decoded.Value, tt.value) {
				t.Errorf("Expected value %v, got %v", tt.value, decoded.Value)
			}
		})
	}
}

func TestTLVEncoderDecoder(t *testing.T) {
	var buf bytes.Buffer
	encoder := NewTLVEncoder(&buf)

	entries := []*TLV{
		{Type: TypeRecord, Value: []byte("record1")},
		{Type: TypeZone, Value: []byte("example.com")},
		{Type: TypeConfig, Value: []byte("config_data")},
	}

	// Encode all entries
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			t.Fatalf("Encode failed: %v", err)
		}
	}

	// Decode all entries
	decoder := NewTLVDecoder(&buf)
	var decoded []*TLV

	for {
		entry, err := decoder.Decode()
		if err != nil {
			break
		}
		decoded = append(decoded, entry)
	}

	if len(decoded) != len(entries) {
		t.Fatalf("Expected %d entries, got %d", len(entries), len(decoded))
	}

	for i, entry := range decoded {
		if entry.Type != entries[i].Type {
			t.Errorf("Entry %d: expected type %d, got %d", i, entries[i].Type, entry.Type)
		}
		if !bytes.Equal(entry.Value, entries[i].Value) {
			t.Errorf("Entry %d: value mismatch", i)
		}
	}
}

func TestBatchEncoderDecoder(t *testing.T) {
	encoder := NewBatchEncoder(256)

	entries := []struct {
		typ   byte
		value []byte
	}{
		{TypeRecord, []byte("record1")},
		{TypeZone, []byte("example.com")},
		{TypeConfig, []byte("config_data")},
	}

	// Add all entries
	for _, e := range entries {
		if err := encoder.Add(e.typ, e.value); err != nil {
			t.Fatalf("Add failed: %v", err)
		}
	}

	// Decode
	decoder := NewBatchDecoder(encoder.Bytes())
	count := 0

	for decoder.HasNext() {
		entry, err := decoder.Next()
		if err != nil {
			t.Fatalf("Next failed: %v", err)
		}

		if entry.Type != entries[count].typ {
			t.Errorf("Entry %d: expected type %d, got %d", count, entries[count].typ, entry.Type)
		}
		if !bytes.Equal(entry.Value, entries[count].value) {
			t.Errorf("Entry %d: value mismatch", count)
		}
		count++
	}

	if count != len(entries) {
		t.Errorf("Expected %d entries, got %d", len(entries), count)
	}
}

func TestTLVValueTooLarge(t *testing.T) {
	// Create a value larger than MaxValueSize
	largeValue := make([]byte, MaxValueSize+1)

	_, err := EncodeTLV(TypeRecord, largeValue)
	if err != ErrValueTooLarge {
		t.Errorf("Expected ErrValueTooLarge, got %v", err)
	}
}

func TestTLVUnexpectedEOF(t *testing.T) {
	// Create incomplete TLV data
	incomplete := []byte{0x01, 0x00, 0x00, 0x00, 0x10} // Says length 16 but no data

	_, _, err := DecodeTLV(incomplete)
	if err != ErrUnexpectedEOF {
		t.Errorf("Expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestBatchEncoderReset(t *testing.T) {
	encoder := NewBatchEncoder(256)

	encoder.Add(TypeRecord, []byte("test1"))
	if encoder.Len() == 0 {
		t.Error("Expected non-zero length after Add")
	}

	encoder.Reset()
	if encoder.Len() != 0 {
		t.Errorf("Expected zero length after Reset, got %d", encoder.Len())
	}
}

func TestBatchDecoderPosition(t *testing.T) {
	encoder := NewBatchEncoder(256)
	encoder.Add(TypeRecord, []byte("test1"))
	encoder.Add(TypeZone, []byte("test2"))

	decoder := NewBatchDecoder(encoder.Bytes())

	if decoder.Pos() != 0 {
		t.Errorf("Expected initial pos 0, got %d", decoder.Pos())
	}

	decoder.Next()
	if decoder.Pos() == 0 {
		t.Error("Expected pos to advance after Next")
	}
}

// TestTLVEncoderEncodeWithType tests EncodeWithType method
func TestTLVEncoderEncodeWithType(t *testing.T) {
	var buf bytes.Buffer
	encoder := NewTLVEncoder(&buf)

	err := encoder.EncodeWithType(TypeRecord, []byte("test data"))
	if err != nil {
		t.Fatalf("EncodeWithType failed: %v", err)
	}

	// Verify the data was written
	if buf.Len() == 0 {
		t.Error("Expected data to be written to buffer")
	}

	// Decode to verify
	decoder := NewTLVDecoder(&buf)
	tlv, err := decoder.Decode()
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if tlv.Type != TypeRecord {
		t.Errorf("Expected type %d, got %d", TypeRecord, tlv.Type)
	}
	if string(tlv.Value) != "test data" {
		t.Errorf("Expected value 'test data', got %q", string(tlv.Value))
	}
}

// TestTLVDecoderDecodeType tests DecodeType method
func TestTLVDecoderDecodeType(t *testing.T) {
	// Encode some data
	var buf bytes.Buffer
	encoder := NewTLVEncoder(&buf)
	encoder.EncodeWithType(TypeZone, []byte("zone data"))

	decoder := NewTLVDecoder(&buf)

	// Use DecodeType to peek at the type
	typ, err := decoder.DecodeType()
	if err != nil {
		t.Fatalf("DecodeType failed: %v", err)
	}

	if typ != TypeZone {
		t.Errorf("Expected type %d, got %d", TypeZone, typ)
	}
}
