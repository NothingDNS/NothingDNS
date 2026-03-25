package protocol

import (
	"bytes"
	"net"
	"testing"
)

// TestHeaderRoundTrip tests DNS header pack/unpack round-trip.
func TestHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		header Header
	}{
		{
			name: "standard query",
			header: Header{
				ID:      0x1234,
				Flags:   NewQueryFlags(),
				QDCount: 1,
				ANCount: 0,
				NSCount: 0,
				ARCount: 0,
			},
		},
		{
			name: "response with AA",
			header: Header{
				ID:    0x5678,
				Flags: NewResponseFlags(RcodeSuccess),
				QDCount: 1,
				ANCount: 1,
			},
		},
		{
			name: "truncated response",
			header: Header{
				ID:    0x9ABC,
				Flags: Flags{QR: true, TC: true, RCODE: RcodeServerFailure},
				QDCount: 1,
				ANCount: 0,
			},
		},
		{
			name: "all flags set",
			header: Header{
				ID: 0xDEF0,
				Flags: Flags{
					QR:     true,
					Opcode: OpcodeQuery,
					AA:     true,
					TC:     true,
					RD:     true,
					RA:     true,
					AD:     true,
					CD:     true,
					RCODE:  RcodeRefused,
				},
				QDCount: 1,
				ANCount: 2,
				NSCount: 3,
				ARCount: 4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, HeaderLen)
			err := tt.header.Pack(buf)
			if err != nil {
				t.Fatalf("Pack() error = %v", err)
			}

			var unpacked Header
			err = unpacked.Unpack(buf)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}

			if unpacked.ID != tt.header.ID {
				t.Errorf("ID mismatch: got %04x, want %04x", unpacked.ID, tt.header.ID)
			}
			if unpacked.Flags != tt.header.Flags {
				t.Errorf("Flags mismatch: got %+v, want %+v", unpacked.Flags, tt.header.Flags)
			}
			if unpacked.QDCount != tt.header.QDCount {
				t.Errorf("QDCount mismatch: got %d, want %d", unpacked.QDCount, tt.header.QDCount)
			}
			if unpacked.ANCount != tt.header.ANCount {
				t.Errorf("ANCount mismatch: got %d, want %d", unpacked.ANCount, tt.header.ANCount)
			}
			if unpacked.NSCount != tt.header.NSCount {
				t.Errorf("NSCount mismatch: got %d, want %d", unpacked.NSCount, tt.header.NSCount)
			}
			if unpacked.ARCount != tt.header.ARCount {
				t.Errorf("ARCount mismatch: got %d, want %d", unpacked.ARCount, tt.header.ARCount)
			}
		})
	}
}

// TestQuestionRoundTrip tests question pack/unpack round-trip.
func TestQuestionRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		question *Question
	}{
		{
			name:     "A query for example.com",
			question: must(NewQuestion("example.com.", TypeA, ClassIN)),
		},
		{
			name:     "AAAA query for www.example.com",
			question: must(NewQuestion("www.example.com.", TypeAAAA, ClassIN)),
		},
		{
			name:     "MX query",
			question: must(NewQuestion("example.com.", TypeMX, ClassIN)),
		},
		{
			name:     "wildcard query",
			question: must(NewQuestion("*.example.com.", TypeA, ClassIN)),
		},
		{
			name:     "root query",
			question: must(NewQuestion(".", TypeNS, ClassIN)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 512)
			n, err := tt.question.Pack(buf, 0, nil)
			if err != nil {
				t.Fatalf("Pack() error = %v", err)
			}

			unpacked, consumed, err := UnpackQuestion(buf, 0)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}

			if consumed != n {
				t.Errorf("bytes consumed = %d, want %d", consumed, n)
			}

			if !unpacked.Name.Equal(tt.question.Name) {
				t.Errorf("Name mismatch: got %s, want %s", unpacked.Name, tt.question.Name)
			}
			if unpacked.QType != tt.question.QType {
				t.Errorf("QType mismatch: got %d, want %d", unpacked.QType, tt.question.QType)
			}
			if unpacked.QClass != tt.question.QClass {
				t.Errorf("QClass mismatch: got %d, want %d", unpacked.QClass, tt.question.QClass)
			}
		})
	}
}

// TestRDataARoundTrip tests A record pack/unpack round-trip.
func TestRDataARoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
	}{
		{"IPv4 localhost", "127.0.0.1"},
		{"IPv4 private", "192.168.1.1"},
		{"IPv4 public", "8.8.8.8"},
		{"IPv4 zero", "0.0.0.0"},
		{"IPv4 broadcast", "255.255.255.255"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdata := &RDataA{}
			rdata.SetIP(net.ParseIP(tt.addr))

			buf := make([]byte, 16)
			n, err := rdata.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack() error = %v", err)
			}
			if n != 4 {
				t.Errorf("Pack() returned %d bytes, want 4", n)
			}

			unpacked := &RDataA{}
			_, err = unpacked.Unpack(buf, 0, 4)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}

			if !bytes.Equal(rdata.Address[:], unpacked.Address[:]) {
				t.Errorf("Address mismatch: got %v, want %v", unpacked.Address, rdata.Address)
			}
		})
	}
}

// TestRDataAAAARoundTrip tests AAAA record pack/unpack round-trip.
func TestRDataAAAARoundTrip(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{"IPv6 localhost", "::1"},
		{"IPv6 public", "2001:4860:4860::8888"},
		{"IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"IPv6 zero", "::"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdata := &RDataAAAA{}
			rdata.SetIP(net.ParseIP(tt.addr))

			buf := make([]byte, 32)
			n, err := rdata.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack() error = %v", err)
			}
			if n != 16 {
				t.Errorf("Pack() returned %d bytes, want 16", n)
			}

			unpacked := &RDataAAAA{}
			_, err = unpacked.Unpack(buf, 0, 16)
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}

			if !bytes.Equal(rdata.Address[:], unpacked.Address[:]) {
				t.Errorf("Address mismatch: got %v, want %v", unpacked.Address, rdata.Address)
			}
		})
	}
}

// TestRDataCNAMERoundTrip tests CNAME record pack/unpack round-trip.
func TestRDataCNAMERoundTrip(t *testing.T) {
	rdata := &RDataCNAME{CName: must(ParseName("www.example.com."))}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataCNAME{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if !unpacked.CName.Equal(rdata.CName) {
		t.Errorf("CName mismatch: got %s, want %s", unpacked.CName, rdata.CName)
	}
}

// TestRDataNSRoundTrip tests NS record pack/unpack round-trip.
func TestRDataNSRoundTrip(t *testing.T) {
	rdata := &RDataNS{NSDName: must(ParseName("ns1.example.com."))}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataNS{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if !unpacked.NSDName.Equal(rdata.NSDName) {
		t.Errorf("NSDName mismatch: got %s, want %s", unpacked.NSDName, rdata.NSDName)
	}
}

// TestRDataPTRRoundTrip tests PTR record pack/unpack round-trip.
func TestRDataPTRRoundTrip(t *testing.T) {
	rdata := &RDataPTR{PtrDName: must(ParseName("www.example.com."))}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataPTR{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if !unpacked.PtrDName.Equal(rdata.PtrDName) {
		t.Errorf("PtrDName mismatch: got %s, want %s", unpacked.PtrDName, rdata.PtrDName)
	}
}

// TestRDataMXRoundTrip tests MX record pack/unpack round-trip.
func TestRDataMXRoundTrip(t *testing.T) {
	rdata := &RDataMX{
		Preference: 10,
		Exchange:   must(ParseName("mail.example.com.")),
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataMX{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if unpacked.Preference != rdata.Preference {
		t.Errorf("Preference mismatch: got %d, want %d", unpacked.Preference, rdata.Preference)
	}
	if !unpacked.Exchange.Equal(rdata.Exchange) {
		t.Errorf("Exchange mismatch: got %s, want %s", unpacked.Exchange, rdata.Exchange)
	}
}

// TestRDataTXTRoundTrip tests TXT record pack/unpack round-trip.
func TestRDataTXTRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		strings []string
	}{
		{"single", []string{"hello world"}},
		{"multiple", []string{"part1", "part2", "part3"}},
		{"empty", []string{""}},
		{"long", []string{"v=spf1 include:_spf.google.com include:example.com ~all"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdata := &RDataTXT{Strings: tt.strings}

			buf := make([]byte, 512)
			n, err := rdata.Pack(buf, 0)
			if err != nil {
				t.Fatalf("Pack() error = %v", err)
			}

			unpacked := &RDataTXT{}
			_, err = unpacked.Unpack(buf, 0, uint16(n))
			if err != nil {
				t.Fatalf("Unpack() error = %v", err)
			}

			if len(unpacked.Strings) != len(rdata.Strings) {
				t.Fatalf("Strings length mismatch: got %d, want %d", len(unpacked.Strings), len(rdata.Strings))
			}
			for i := range unpacked.Strings {
				if unpacked.Strings[i] != rdata.Strings[i] {
					t.Errorf("String[%d] mismatch: got %q, want %q", i, unpacked.Strings[i], rdata.Strings[i])
				}
			}
		})
	}
}

// TestRDataSOARoundTrip tests SOA record pack/unpack round-trip.
func TestRDataSOARoundTrip(t *testing.T) {
	rdata := &RDataSOA{
		MName:   must(ParseName("ns1.example.com.")),
		RName:   must(ParseName("admin.example.com.")),
		Serial:  2024010101,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: 300,
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataSOA{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if !unpacked.MName.Equal(rdata.MName) {
		t.Errorf("MName mismatch: got %s, want %s", unpacked.MName, rdata.MName)
	}
	if !unpacked.RName.Equal(rdata.RName) {
		t.Errorf("RName mismatch: got %s, want %s", unpacked.RName, rdata.RName)
	}
	if unpacked.Serial != rdata.Serial {
		t.Errorf("Serial mismatch: got %d, want %d", unpacked.Serial, rdata.Serial)
	}
	if unpacked.Refresh != rdata.Refresh {
		t.Errorf("Refresh mismatch: got %d, want %d", unpacked.Refresh, rdata.Refresh)
	}
	if unpacked.Retry != rdata.Retry {
		t.Errorf("Retry mismatch: got %d, want %d", unpacked.Retry, rdata.Retry)
	}
	if unpacked.Expire != rdata.Expire {
		t.Errorf("Expire mismatch: got %d, want %d", unpacked.Expire, rdata.Expire)
	}
	if unpacked.Minimum != rdata.Minimum {
		t.Errorf("Minimum mismatch: got %d, want %d", unpacked.Minimum, rdata.Minimum)
	}
}

// TestRDataSRVRoundTrip tests SRV record pack/unpack round-trip.
func TestRDataSRVRoundTrip(t *testing.T) {
	rdata := &RDataSRV{
		Priority: 10,
		Weight:   5,
		Port:     443,
		Target:   must(ParseName("www.example.com.")),
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataSRV{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if unpacked.Priority != rdata.Priority {
		t.Errorf("Priority mismatch: got %d, want %d", unpacked.Priority, rdata.Priority)
	}
	if unpacked.Weight != rdata.Weight {
		t.Errorf("Weight mismatch: got %d, want %d", unpacked.Weight, rdata.Weight)
	}
	if unpacked.Port != rdata.Port {
		t.Errorf("Port mismatch: got %d, want %d", unpacked.Port, rdata.Port)
	}
	if !unpacked.Target.Equal(rdata.Target) {
		t.Errorf("Target mismatch: got %s, want %s", unpacked.Target, rdata.Target)
	}
}

// TestRDataCAARoundTrip tests CAA record pack/unpack round-trip.
func TestRDataCAARoundTrip(t *testing.T) {
	rdata := &RDataCAA{
		Flags: 128,
		Tag:   "issue",
		Value: "letsencrypt.org",
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataCAA{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if unpacked.Flags != rdata.Flags {
		t.Errorf("Flags mismatch: got %d, want %d", unpacked.Flags, rdata.Flags)
	}
	if unpacked.Tag != rdata.Tag {
		t.Errorf("Tag mismatch: got %s, want %s", unpacked.Tag, rdata.Tag)
	}
	if unpacked.Value != rdata.Value {
		t.Errorf("Value mismatch: got %s, want %s", unpacked.Value, rdata.Value)
	}
}

// TestRDataNAPTRRoundTrip tests NAPTR record pack/unpack round-trip.
func TestRDataNAPTRRoundTrip(t *testing.T) {
	rdata := &RDataNAPTR{
		Order:       100,
		Preference:  10,
		Flags:       "U",
		Service:     "SIP+D2U",
		Regexp:      "!^.*$!sip:info@example.com!",
		Replacement: must(ParseName("sip.example.com.")),
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataNAPTR{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if unpacked.Order != rdata.Order {
		t.Errorf("Order mismatch: got %d, want %d", unpacked.Order, rdata.Order)
	}
	if unpacked.Preference != rdata.Preference {
		t.Errorf("Preference mismatch: got %d, want %d", unpacked.Preference, rdata.Preference)
	}
	if unpacked.Flags != rdata.Flags {
		t.Errorf("Flags mismatch: got %s, want %s", unpacked.Flags, rdata.Flags)
	}
	if unpacked.Service != rdata.Service {
		t.Errorf("Service mismatch: got %s, want %s", unpacked.Service, rdata.Service)
	}
	if unpacked.Regexp != rdata.Regexp {
		t.Errorf("Regexp mismatch: got %s, want %s", unpacked.Regexp, rdata.Regexp)
	}
	if !unpacked.Replacement.Equal(rdata.Replacement) {
		t.Errorf("Replacement mismatch: got %s, want %s", unpacked.Replacement, rdata.Replacement)
	}
}

// TestRDataSSHFPRoundTrip tests SSHFP record pack/unpack round-trip.
func TestRDataSSHFPRoundTrip(t *testing.T) {
	fp := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	rdata := &RDataSSHFP{
		Algorithm:   2,
		FPType:      1,
		Fingerprint: fp,
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataSSHFP{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if unpacked.Algorithm != rdata.Algorithm {
		t.Errorf("Algorithm mismatch: got %d, want %d", unpacked.Algorithm, rdata.Algorithm)
	}
	if unpacked.FPType != rdata.FPType {
		t.Errorf("FPType mismatch: got %d, want %d", unpacked.FPType, rdata.FPType)
	}
	if !bytes.Equal(unpacked.Fingerprint, rdata.Fingerprint) {
		t.Errorf("Fingerprint mismatch: got %x, want %x", unpacked.Fingerprint, rdata.Fingerprint)
	}
}

// TestRDataTLSARoundTrip tests TLSA record pack/unpack round-trip.
func TestRDataTLSARoundTrip(t *testing.T) {
	cert := []byte{0xab, 0xcd, 0xef, 0x12, 0x34}
	rdata := &RDataTLSA{
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  cert,
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataTLSA{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if unpacked.Usage != rdata.Usage {
		t.Errorf("Usage mismatch: got %d, want %d", unpacked.Usage, rdata.Usage)
	}
	if unpacked.Selector != rdata.Selector {
		t.Errorf("Selector mismatch: got %d, want %d", unpacked.Selector, rdata.Selector)
	}
	if unpacked.MatchingType != rdata.MatchingType {
		t.Errorf("MatchingType mismatch: got %d, want %d", unpacked.MatchingType, rdata.MatchingType)
	}
	if !bytes.Equal(unpacked.Certificate, rdata.Certificate) {
		t.Errorf("Certificate mismatch: got %x, want %x", unpacked.Certificate, rdata.Certificate)
	}
}

// TestRDataOPTRoundTrip tests OPT record pack/unpack round-trip.
func TestRDataOPTRoundTrip(t *testing.T) {
	rdata := &RDataOPT{
		Options: []EDNS0Option{
			{Code: OptionCodeNSID, Data: []byte("ns1")},
			{Code: OptionCodeClientSubnet, Data: []byte{0x00, 0x01, 0x18, 0x00, 0xc0, 0xa8, 0x01}},
		},
	}

	buf := make([]byte, 512)
	n, err := rdata.Pack(buf, 0)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked := &RDataOPT{}
	_, err = unpacked.Unpack(buf, 0, uint16(n))
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if len(unpacked.Options) != len(rdata.Options) {
		t.Fatalf("Options length mismatch: got %d, want %d", len(unpacked.Options), len(rdata.Options))
	}
	for i := range unpacked.Options {
		if unpacked.Options[i].Code != rdata.Options[i].Code {
			t.Errorf("Option[%d].Code mismatch: got %d, want %d", i, unpacked.Options[i].Code, rdata.Options[i].Code)
		}
		if !bytes.Equal(unpacked.Options[i].Data, rdata.Options[i].Data) {
			t.Errorf("Option[%d].Data mismatch: got %x, want %x", i, unpacked.Options[i].Data, rdata.Options[i].Data)
		}
	}
}

// TestMessageRoundTrip tests full DNS message pack/unpack round-trip.
func TestMessageRoundTrip(t *testing.T) {
	msg := NewMessage(Header{
		ID:      0x1234,
		Flags:   NewQueryFlags(),
		QDCount: 1,
	})

	q := must(NewQuestion("example.com.", TypeA, ClassIN))
	msg.AddQuestion(q)

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked, err := UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if unpacked.Header.ID != msg.Header.ID {
		t.Errorf("Header.ID mismatch: got %04x, want %04x", unpacked.Header.ID, msg.Header.ID)
	}
	if len(unpacked.Questions) != len(msg.Questions) {
		t.Errorf("Questions length mismatch: got %d, want %d", len(unpacked.Questions), len(msg.Questions))
	}
}

// TestMessageWithAnswersRoundTrip tests message with answers.
func TestMessageWithAnswersRoundTrip(t *testing.T) {
	msg := NewMessage(Header{
		ID:    0x5678,
		Flags: NewResponseFlags(RcodeSuccess),
	})

	q := must(NewQuestion("example.com.", TypeA, ClassIN))
	msg.AddQuestion(q)

	a := &ResourceRecord{
		Name:  must(ParseName("example.com")),
		Type:  TypeA,
		Class: ClassIN,
		TTL:   300,
		Data:  &RDataA{Address: [4]byte{93, 184, 216, 34}},
	}
	msg.AddAnswer(a)

	buf := make([]byte, 512)
	n, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	unpacked, err := UnpackMessage(buf[:n])
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if len(unpacked.Answers) != 1 {
		t.Fatalf("Answers length = %d, want 1", len(unpacked.Answers))
	}
	if unpacked.Answers[0].TTL != 300 {
		t.Errorf("Answer TTL = %d, want 300", unpacked.Answers[0].TTL)
	}
}

// TestNameCompression tests that name compression works correctly.
func TestNameCompression(t *testing.T) {
	msg := NewMessage(Header{
		ID:    0x9abc,
		Flags: NewResponseFlags(RcodeSuccess),
	})

	q := must(NewQuestion("www.example.com", TypeA, ClassIN))
	msg.AddQuestion(q)

	// Add multiple answers that share the same domain suffix
	for _, name := range []string{"www.example.com", "mail.example.com", "ftp.example.com"} {
		a := &ResourceRecord{
			Name:  must(ParseName(name + ".")),
			Type:  TypeA,
			Class: ClassIN,
			TTL:   300,
			Data:  &RDataA{Address: [4]byte{192, 0, 2, 1}},
		}
		msg.AddAnswer(a)
	}

	buf := make([]byte, 512)
	_, err := msg.Pack(buf)
	if err != nil {
		t.Fatalf("Pack() error = %v", err)
	}

	// Unpack and verify
	unpacked, err := UnpackMessage(buf)
	if err != nil {
		t.Fatalf("Unpack() error = %v", err)
	}

	if len(unpacked.Answers) != 3 {
		t.Fatalf("Answers length = %d, want 3", len(unpacked.Answers))
	}
}

// TestEDNS0ClientSubnet tests ECS option pack/unpack.
func TestEDNS0ClientSubnet(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		bits uint8
	}{
		{"IPv4 /24", "192.168.1.0", 24},
		{"IPv4 /32", "10.0.0.1", 32},
		{"IPv6 /64", "2001:db8::", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecs := NewEDNS0ClientSubnet(net.ParseIP(tt.ip), tt.bits)
			data := ecs.Pack()

			unpacked, err := UnpackEDNS0ClientSubnet(data)
			if err != nil {
				t.Fatalf("UnpackEDNS0ClientSubnet() error = %v", err)
			}

			if unpacked.Family != ecs.Family {
				t.Errorf("Family = %d, want %d", unpacked.Family, ecs.Family)
			}
			if unpacked.SourcePrefixLength != ecs.SourcePrefixLength {
				t.Errorf("SourcePrefixLength = %d, want %d", unpacked.SourcePrefixLength, ecs.SourcePrefixLength)
			}
		})
	}
}

// Helper function
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
