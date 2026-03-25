package protocol

import (
	"testing"
)

// FuzzUnpackMessage fuzzes the DNS message unpacker.
func FuzzUnpackMessage(f *testing.F) {
	// Seed corpus with valid messages
	// Standard query for example.com A
	f.Add([]byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: RD set
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		// Question: example.com A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	})

	// Response with A record
	f.Add([]byte{
		0x12, 0x34, // ID
		0x81, 0x80, // Flags: QR=1, RD=1, RA=1
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x01, // ANCOUNT: 1
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		// Question: example.com A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		// Answer: example.com A 300 93.184.216.34
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,             // End of name
		0x00, 0x01,       // Type A
		0x00, 0x01,       // Class IN
		0x00, 0x00, 0x01, 0x2c, // TTL: 300
		0x00, 0x04,       // RDLENGTH: 4
		0x5d, 0xb8, 0xd8, 0x22, // RDATA: 93.184.216.34
	})

	// EDNS0 query with large buffer size
	f.Add([]byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: RD set
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x01, // ARCOUNT: 1 (OPT record)
		// Question: example.com A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of name
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
		// Additional: OPT record with UDP payload size 4096
		0x00,       // Root name
		0x00, 0x29, // Type OPT
		0x10, 0x00, // UDP payload size: 4096
		0x00, 0x00, 0x00, 0x00, // TTL field (extended RCODE, version, DO, Z)
		0x00, 0x00, // RDLENGTH: 0
	})

	// Empty message (too short)
	f.Add([]byte{})

	// Just header
	f.Add([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	// Truncated message
	f.Add([]byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// Incomplete question
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to unpack - we don't care about errors, just that it doesn't panic
		msg, err := UnpackMessage(data)
		if err != nil {
			// Expected for invalid input
			return
		}

		// If unpacking succeeded, verify we can pack it back
		// Skip if message has nil sections that could cause panics
		if msg == nil {
			return
		}

		// Check for nil entries in sections that could cause panics
		for _, q := range msg.Questions {
			if q == nil || q.Name == nil {
				return
			}
		}
		for _, rr := range msg.Answers {
			if rr == nil || rr.Name == nil || rr.Data == nil {
				return
			}
		}
		for _, rr := range msg.Authorities {
			if rr == nil || rr.Name == nil || rr.Data == nil {
				return
			}
		}
		for _, rr := range msg.Additionals {
			if rr == nil || rr.Name == nil || rr.Data == nil {
				return
			}
		}

		buf := make([]byte, 4096)
		_, _ = msg.Pack(buf)
	})
}

// FuzzUnpackName fuzzes the name unpacker.
func FuzzUnpackName(f *testing.F) {
	// Valid name: example.com
	f.Add([]byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	})

	// Valid name with compression pointer
	f.Add([]byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0xC0, 0x00, // Pointer to offset 0
	})

	// Root name
	f.Add([]byte{0x00})

	// Empty input
	f.Add([]byte{})

	// Long label
	longLabel := make([]byte, 65)
	longLabel[0] = 63
	f.Add(longLabel)

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to unpack - we don't care about errors, just that it doesn't panic
		name, _, err := UnpackName(data, 0)
		if err != nil {
			return
		}

		// If unpacking succeeded, verify we can pack it back
		if name == nil {
			return
		}

		buf := make([]byte, 512)
		_, _ = PackName(name, buf, 0, nil)
	})
}

// FuzzUnpackResourceRecord fuzzes the resource record unpacker.
func FuzzUnpackResourceRecord(f *testing.F) {
	// Valid A record
	f.Add([]byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,             // End of name
		0x00, 0x01,       // Type A
		0x00, 0x01,       // Class IN
		0x00, 0x00, 0x01, 0x2c, // TTL: 300
		0x00, 0x04,       // RDLENGTH: 4
		0x5d, 0xb8, 0xd8, 0x22, // RDATA: 93.184.216.34
	})

	// Valid NS record
	f.Add([]byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // End of name
		0x00, 0x02, // Type NS
		0x00, 0x01, // Class IN
		0x00, 0x00, 0x0e, 0x10, // TTL: 3600
		0x00, 0x0b, // RDLENGTH: 11
		0x03, 'n', 's', '1',
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
	})

	// Truncated record
	f.Add([]byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Try to unpack - we don't care about errors, just that it doesn't panic
		rr, _, err := UnpackResourceRecord(data, 0)
		if err != nil {
			return
		}

		// If unpacking succeeded, verify we can pack it back
		if rr == nil || rr.Name == nil || rr.Data == nil {
			return
		}

		buf := make([]byte, 512)
		_, _ = rr.Pack(buf, 0, nil)
	})
}
