package protocol

import (
	"bytes"
	"testing"
)

// TestEDEPackUnpack tests round-trip pack/unpack for various info codes with and without extra text.
func TestEDEPackUnpack(t *testing.T) {
	tests := []struct {
		name      string
		infoCode  uint16
		extraText string
	}{
		{
			name:      "blocked with text",
			infoCode:  EDEBlocked,
			extraText: "domain is on blocklist",
		},
		{
			name:      "censored with text",
			infoCode:  EDECensored,
			extraText: "government order",
		},
		{
			name:      "stale answer without text",
			infoCode:  EDEStaleAnswer,
			extraText: "",
		},
		{
			name:      "other error with UTF-8 text",
			infoCode:  EDEOtherError,
			extraText: "hata olustu",
		},
		{
			name:      "filtered with long text",
			infoCode:  EDEFiltered,
			extraText: "this domain was filtered due to category: malware",
		},
		{
			name:      "network error",
			infoCode:  EDENetworkError,
			extraText: "upstream timeout",
		},
		{
			name:      "max info code",
			infoCode:  65535,
			extraText: "unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := NewEDNS0ExtendedError(tt.infoCode, tt.extraText)
			packed := original.Pack()

			// Verify wire length: 2 bytes info code + len(extra text)
			expectedLen := 2 + len(tt.extraText)
			if len(packed) != expectedLen {
				t.Fatalf("Pack() length = %d, want %d", len(packed), expectedLen)
			}

			unpacked, err := UnpackEDNS0ExtendedError(packed)
			if err != nil {
				t.Fatalf("UnpackEDNS0ExtendedError() error = %v", err)
			}

			if unpacked.InfoCode != tt.infoCode {
				t.Errorf("InfoCode = %d, want %d", unpacked.InfoCode, tt.infoCode)
			}
			if unpacked.ExtraText != tt.extraText {
				t.Errorf("ExtraText = %q, want %q", unpacked.ExtraText, tt.extraText)
			}
		})
	}
}

// TestEDEPackUnpackEmpty tests round-trip with empty extra text.
func TestEDEPackUnpackEmpty(t *testing.T) {
	original := NewEDNS0ExtendedError(EDENotReady, "")
	packed := original.Pack()

	if len(packed) != 2 {
		t.Fatalf("Pack() with empty text: length = %d, want 2", len(packed))
	}

	unpacked, err := UnpackEDNS0ExtendedError(packed)
	if err != nil {
		t.Fatalf("UnpackEDNS0ExtendedError() error = %v", err)
	}

	if unpacked.InfoCode != EDENotReady {
		t.Errorf("InfoCode = %d, want %d", unpacked.InfoCode, EDENotReady)
	}
	if unpacked.ExtraText != "" {
		t.Errorf("ExtraText = %q, want empty string", unpacked.ExtraText)
	}
}

// TestEDEInfoCodeString verifies all EDE info code names.
func TestEDEInfoCodeString(t *testing.T) {
	tests := []struct {
		code uint16
		want string
	}{
		{EDEOtherError, "Other Error"},
		{EDEUnsupportedDNSKEYAlgo, "Unsupported DNSKEY Algorithm"},
		{EDEUnsupportedDSDigest, "Unsupported DS Digest Type"},
		{EDEStaleAnswer, "Stale Answer"},
		{EDEForgedAnswer, "Forged Answer"},
		{EDEDNSSECIndeterminate, "DNSSEC Indeterminate"},
		{EDEDNSSECBogus, "DNSSEC Bogus"},
		{EDENSECMissing, "Signature Expired"},
		{EDECachedError, "Cached Error"},
		{EDENotReady, "Not Ready"},
		{EDEBlocked, "Blocked"},
		{EDECensored, "Censored"},
		{EDEFiltered, "Filtered"},
		{EDEProhibited, "Prohibited"},
		{EDEStaleNXDOMAIN, "Stale NXDOMAIN Answer"},
		{EDENotAuthoritative, "Not Authoritative"},
		{EDENotSupported, "Not Supported"},
		{EDENoReachableAuthority, "No Reachable Authority"},
		{EDENetworkError, "Network Error"},
		{EDEInvalidData, "Invalid Data"},
		{EDESignatureExpiredBefore, "Signature Expired Before Valid Period"},
		{EDESignatureNotYetValid, "Signature Not Yet Valid"},
		{EDETooEarly, "DNSKEY Missing"},
		{EDEUnsupportedNSEC3Iter, "Unsupported NSEC3 Iterations Value"},
		{EDENoNSECRecords, "Unable to Conform to Policy"},
		{EDENoZoneKeyBitSet, "Synthesized"},
		{EDENSECMissingCoverage, "NSEC Missing Coverage"},
		// Unknown code falls back to EDExx format
		{9999, "EDE9999"},
		{65535, "EDE65535"},
	}

	for _, tt := range tests {
		got := EDEInfoCodeString(tt.code)
		if got != tt.want {
			t.Errorf("EDEInfoCodeString(%d) = %q, want %q", tt.code, got, tt.want)
		}
	}
}

// TestEDEString verifies the human-readable String() format.
func TestEDEString(t *testing.T) {
	tests := []struct {
		name      string
		infoCode  uint16
		extraText string
		want      string
	}{
		{
			name:      "with extra text",
			infoCode:  EDEBlocked,
			extraText: "domain is on blocklist",
			want:      "Blocked (10): domain is on blocklist",
		},
		{
			name:      "without extra text",
			infoCode:  EDEStaleAnswer,
			extraText: "",
			want:      "Stale Answer (3)",
		},
		{
			name:      "unknown code with text",
			infoCode:  1000,
			extraText: "custom error",
			want:      "EDE1000 (1000): custom error",
		},
		{
			name:      "censored without text",
			infoCode:  EDECensored,
			extraText: "",
			want:      "Censored (11)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ede := NewEDNS0ExtendedError(tt.infoCode, tt.extraText)
			got := ede.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestUnpackEDETooShort verifies that data shorter than 2 bytes returns an error.
func TestUnpackEDETooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnpackEDNS0ExtendedError(tt.data)
			if err == nil {
				t.Error("UnpackEDNS0ExtendedError() expected error for short data, got nil")
			}
		})
	}
}

// TestAddExtendedError tests adding an EDE to a message.
func TestAddExtendedError(t *testing.T) {
	t.Run("add to message without OPT", func(t *testing.T) {
		msg := &Message{
			Header:      Header{},
			Questions:   make([]*Question, 0),
			Answers:     make([]*ResourceRecord, 0),
			Authorities: make([]*ResourceRecord, 0),
			Additionals: make([]*ResourceRecord, 0),
		}

		AddExtendedError(msg, EDEBlocked, "test block")

		opt := msg.GetOPT()
		if opt == nil {
			t.Fatal("expected OPT record to be created")
		}

		optData, ok := opt.Data.(*RDataOPT)
		if !ok {
			t.Fatal("OPT record Data is not *RDataOPT")
		}

		edeOpt := optData.GetOption(OptionCodeExtendedError)
		if edeOpt == nil {
			t.Fatal("expected EDE option in OPT record")
		}

		ede, err := UnpackEDNS0ExtendedError(edeOpt.Data)
		if err != nil {
			t.Fatalf("UnpackEDNS0ExtendedError() error = %v", err)
		}

		if ede.InfoCode != EDEBlocked {
			t.Errorf("InfoCode = %d, want %d", ede.InfoCode, EDEBlocked)
		}
		if ede.ExtraText != "test block" {
			t.Errorf("ExtraText = %q, want %q", ede.ExtraText, "test block")
		}
	})

	t.Run("add to message with existing OPT", func(t *testing.T) {
		msg := &Message{
			Header:      Header{},
			Questions:   make([]*Question, 0),
			Answers:     make([]*ResourceRecord, 0),
			Authorities: make([]*ResourceRecord, 0),
			Additionals: make([]*ResourceRecord, 0),
		}

		// Set up EDNS0 first
		msg.SetEDNS0(4096, true)

		AddExtendedError(msg, EDEFiltered, "category: malware")

		opt := msg.GetOPT()
		if opt == nil {
			t.Fatal("expected OPT record")
		}

		optData := opt.Data.(*RDataOPT)
		edeOpt := optData.GetOption(OptionCodeExtendedError)
		if edeOpt == nil {
			t.Fatal("expected EDE option in OPT record")
		}

		ede, err := UnpackEDNS0ExtendedError(edeOpt.Data)
		if err != nil {
			t.Fatalf("UnpackEDNS0ExtendedError() error = %v", err)
		}

		if ede.InfoCode != EDEFiltered {
			t.Errorf("InfoCode = %d, want %d", ede.InfoCode, EDEFiltered)
		}
		if ede.ExtraText != "category: malware" {
			t.Errorf("ExtraText = %q, want %q", ede.ExtraText, "category: malware")
		}

		// Verify UDP size was preserved (not overwritten)
		if opt.Class != 4096 {
			t.Errorf("OPT Class (UDP size) = %d, want 4096", opt.Class)
		}
	})

	t.Run("ToEDNS0Option wire roundtrip", func(t *testing.T) {
		ede := NewEDNS0ExtendedError(EDEProhibited, "not allowed")
		option := ede.ToEDNS0Option()

		if option.Code != OptionCodeExtendedError {
			t.Errorf("option Code = %d, want %d", option.Code, OptionCodeExtendedError)
		}

		// Verify the wire data round-trips correctly
		unpacked, err := UnpackEDNS0ExtendedError(option.Data)
		if err != nil {
			t.Fatalf("UnpackEDNS0ExtendedError() error = %v", err)
		}

		if unpacked.InfoCode != EDEProhibited {
			t.Errorf("InfoCode = %d, want %d", unpacked.InfoCode, EDEProhibited)
		}
		if unpacked.ExtraText != "not allowed" {
			t.Errorf("ExtraText = %q, want %q", unpacked.ExtraText, "not allowed")
		}

		// Also verify the raw wire bytes
		expectedData := []byte{0x00, 0x0D} // info code 13 big-endian
		expectedData = append(expectedData, []byte("not allowed")...)
		if !bytes.Equal(option.Data, expectedData) {
			t.Errorf("wire data = %x, want %x", option.Data, expectedData)
		}
	})
}
