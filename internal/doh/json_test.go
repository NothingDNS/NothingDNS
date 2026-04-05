package doh

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

func TestEncodeJSON_ARecord(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    1234,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
			},
		},
	}

	data, err := EncodeJSON(msg)
	if err != nil {
		t.Fatalf("EncodeJSON failed: %v", err)
	}

	var resp JSONResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if resp.Status != 0 {
		t.Errorf("Expected Status 0, got %d", resp.Status)
	}
	if !resp.RA {
		t.Error("Expected RA to be true")
	}
	if resp.RD {
		// NewResponseFlags does not set RD
		t.Error("Expected RD to be false for this response")
	}
	if resp.TC {
		t.Error("Expected TC to be false")
	}

	if len(resp.Question) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(resp.Question))
	}
	if resp.Question[0].Name != "example.com." {
		t.Errorf("Expected question name 'example.com.', got %q", resp.Question[0].Name)
	}
	if resp.Question[0].Type != protocol.TypeA {
		t.Errorf("Expected question type %d, got %d", protocol.TypeA, resp.Question[0].Type)
	}

	if len(resp.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(resp.Answer))
	}
	if resp.Answer[0].Name != "example.com." {
		t.Errorf("Expected answer name 'example.com.', got %q", resp.Answer[0].Name)
	}
	if resp.Answer[0].Type != protocol.TypeA {
		t.Errorf("Expected answer type %d, got %d", protocol.TypeA, resp.Answer[0].Type)
	}
	if resp.Answer[0].TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", resp.Answer[0].TTL)
	}
	if resp.Answer[0].Data != "93.184.216.34" {
		t.Errorf("Expected data '93.184.216.34', got %q", resp.Answer[0].Data)
	}
}

func TestEncodeJSON_MultipleAnswerTypes(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				QType:  protocol.TypeANY,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{93, 184, 216, 34}},
			},
			{
				Name: &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				Type: protocol.TypeAAAA,
				Class: protocol.ClassIN,
				TTL:  600,
				Data: makeAAAA("2606:2800:220:1:248:1893:25c8:1946"),
			},
			{
				Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				Type:  protocol.TypeMX,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data: &protocol.RDataMX{
					Preference: 10,
					Exchange:   &protocol.Name{Labels: []string{"mail", "example", "com"}, FQDN: true},
				},
			},
		},
	}

	data, err := EncodeJSON(msg)
	if err != nil {
		t.Fatalf("EncodeJSON failed: %v", err)
	}

	var resp JSONResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if len(resp.Answer) != 3 {
		t.Fatalf("Expected 3 answers, got %d", len(resp.Answer))
	}

	// Check A record
	if resp.Answer[0].Type != protocol.TypeA {
		t.Errorf("Expected first answer type A(%d), got %d", protocol.TypeA, resp.Answer[0].Type)
	}
	if resp.Answer[0].Data != "93.184.216.34" {
		t.Errorf("Expected A data '93.184.216.34', got %q", resp.Answer[0].Data)
	}

	// Check AAAA record
	if resp.Answer[1].Type != protocol.TypeAAAA {
		t.Errorf("Expected second answer type AAAA(%d), got %d", protocol.TypeAAAA, resp.Answer[1].Type)
	}
	if resp.Answer[1].TTL != 600 {
		t.Errorf("Expected AAAA TTL 600, got %d", resp.Answer[1].TTL)
	}

	// Check MX record
	if resp.Answer[2].Type != protocol.TypeMX {
		t.Errorf("Expected third answer type MX(%d), got %d", protocol.TypeMX, resp.Answer[2].Type)
	}
	if resp.Answer[2].Data != "10 mail.example.com." {
		t.Errorf("Expected MX data '10 mail.example.com.', got %q", resp.Answer[2].Data)
	}
}

func TestEncodeJSON_AuthoritySection(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   86400,
				Data:  &protocol.RDataNS{NSDName: &protocol.Name{Labels: []string{"ns1", "example", "com"}, FQDN: true}},
			},
			{
				Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				Type:  protocol.TypeNS,
				Class: protocol.ClassIN,
				TTL:   86400,
				Data:  &protocol.RDataNS{NSDName: &protocol.Name{Labels: []string{"ns2", "example", "com"}, FQDN: true}},
			},
		},
	}

	data, err := EncodeJSON(msg)
	if err != nil {
		t.Fatalf("EncodeJSON failed: %v", err)
	}

	var resp JSONResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if len(resp.Authority) != 2 {
		t.Fatalf("Expected 2 authority records, got %d", len(resp.Authority))
	}

	if resp.Authority[0].Type != protocol.TypeNS {
		t.Errorf("Expected authority type NS(%d), got %d", protocol.TypeNS, resp.Authority[0].Type)
	}
	if resp.Authority[0].Data != "ns1.example.com." {
		t.Errorf("Expected NS data 'ns1.example.com.', got %q", resp.Authority[0].Data)
	}
	if resp.Authority[0].TTL != 86400 {
		t.Errorf("Expected TTL 86400, got %d", resp.Authority[0].TTL)
	}
	if resp.Authority[1].Data != "ns2.example.com." {
		t.Errorf("Expected NS data 'ns2.example.com.', got %q", resp.Authority[1].Data)
	}

	// Answer section should be empty
	if len(resp.Answer) != 0 {
		t.Errorf("Expected 0 answers, got %d", len(resp.Answer))
	}
}

func TestParseJSONQueryParams_Basic(t *testing.T) {
	msg, err := ParseJSONQueryParams("example.com", "A")
	if err != nil {
		t.Fatalf("ParseJSONQueryParams failed: %v", err)
	}

	if len(msg.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(msg.Questions))
	}

	q := msg.Questions[0]
	if q.Name.String() != "example.com." {
		t.Errorf("Expected name 'example.com.', got %q", q.Name.String())
	}
	if q.QType != protocol.TypeA {
		t.Errorf("Expected type A(%d), got %d", protocol.TypeA, q.QType)
	}
	if q.QClass != protocol.ClassIN {
		t.Errorf("Expected class IN(%d), got %d", protocol.ClassIN, q.QClass)
	}

	// Should be a query, not a response
	if !msg.IsQuery() {
		t.Error("Expected query message, got response")
	}
}

func TestParseJSONQueryParams_NumericType(t *testing.T) {
	msg, err := ParseJSONQueryParams("example.com", "28")
	if err != nil {
		t.Fatalf("ParseJSONQueryParams failed: %v", err)
	}

	if len(msg.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(msg.Questions))
	}

	q := msg.Questions[0]
	if q.QType != protocol.TypeAAAA {
		t.Errorf("Expected type AAAA(%d), got %d", protocol.TypeAAAA, q.QType)
	}
}

func TestParseJSONQueryParams_DefaultType(t *testing.T) {
	msg, err := ParseJSONQueryParams("example.com", "")
	if err != nil {
		t.Fatalf("ParseJSONQueryParams failed: %v", err)
	}

	q := msg.Questions[0]
	if q.QType != protocol.TypeA {
		t.Errorf("Expected default type A(%d), got %d", protocol.TypeA, q.QType)
	}
}

func TestParseJSONQueryParams_FQDN(t *testing.T) {
	// With trailing dot
	msg, err := ParseJSONQueryParams("example.com.", "A")
	if err != nil {
		t.Fatalf("ParseJSONQueryParams failed: %v", err)
	}

	q := msg.Questions[0]
	if q.Name.String() != "example.com." {
		t.Errorf("Expected name 'example.com.', got %q", q.Name.String())
	}
}

func TestParseJSONQueryParams_CaseInsensitiveType(t *testing.T) {
	for _, tc := range []struct {
		input    string
		expected uint16
	}{
		{"a", protocol.TypeA},
		{"aaaa", protocol.TypeAAAA},
		{"mx", protocol.TypeMX},
		{"Cname", protocol.TypeCNAME},
		{"TXT", protocol.TypeTXT},
	} {
		msg, err := ParseJSONQueryParams("example.com", tc.input)
		if err != nil {
			t.Fatalf("ParseJSONQueryParams(%q) failed: %v", tc.input, err)
		}
		if msg.Questions[0].QType != tc.expected {
			t.Errorf("ParseJSONQueryParams(%q): expected type %d, got %d",
				tc.input, tc.expected, msg.Questions[0].QType)
		}
	}
}

func TestParseJSONQueryParams_MissingName(t *testing.T) {
	_, err := ParseJSONQueryParams("", "A")
	if err == nil {
		t.Error("Expected error for empty name")
	}
}

func TestParseJSONQueryParams_UnknownType(t *testing.T) {
	_, err := ParseJSONQueryParams("example.com", "INVALID")
	if err == nil {
		t.Error("Expected error for unknown type")
	}
}

func TestDecodeJSONQuery_Roundtrip(t *testing.T) {
	// Create a JSON query body
	queryJSON := `{"name": "example.com", "type": "AAAA"}`

	// Decode the query
	msg, err := DecodeJSONQuery([]byte(queryJSON))
	if err != nil {
		t.Fatalf("DecodeJSONQuery failed: %v", err)
	}

	if len(msg.Questions) != 1 {
		t.Fatalf("Expected 1 question, got %d", len(msg.Questions))
	}

	q := msg.Questions[0]
	if q.Name.String() != "example.com." {
		t.Errorf("Expected name 'example.com.', got %q", q.Name.String())
	}
	if q.QType != protocol.TypeAAAA {
		t.Errorf("Expected type AAAA(%d), got %d", protocol.TypeAAAA, q.QType)
	}

	// Now build a response and encode it as JSON
	resp := &protocol.Message{
		Header: protocol.Header{
			ID:    msg.Header.ID,
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: msg.Questions,
		Answers: []*protocol.ResourceRecord{
			{
				Name: q.Name,
				Type: protocol.TypeAAAA,
				Class: protocol.ClassIN,
				TTL:  600,
				Data: makeAAAA("2001:db8::1"),
			},
		},
	}

	jsonData, err := EncodeJSON(resp)
	if err != nil {
		t.Fatalf("EncodeJSON failed: %v", err)
	}

	var jsonResp JSONResponse
	if err := json.Unmarshal(jsonData, &jsonResp); err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v", err)
	}

	if jsonResp.Status != 0 {
		t.Errorf("Expected Status 0, got %d", jsonResp.Status)
	}
	if len(jsonResp.Question) != 1 {
		t.Fatalf("Expected 1 question in response, got %d", len(jsonResp.Question))
	}
	if jsonResp.Question[0].Name != "example.com." {
		t.Errorf("Expected question name 'example.com.', got %q", jsonResp.Question[0].Name)
	}
	if len(jsonResp.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(jsonResp.Answer))
	}
	if jsonResp.Answer[0].Type != protocol.TypeAAAA {
		t.Errorf("Expected AAAA type, got %d", jsonResp.Answer[0].Type)
	}
	if jsonResp.Answer[0].TTL != 600 {
		t.Errorf("Expected TTL 600, got %d", jsonResp.Answer[0].TTL)
	}
}

func TestDecodeJSONQuery_EmptyBody(t *testing.T) {
	_, err := DecodeJSONQuery([]byte{})
	if err == nil {
		t.Error("Expected error for empty body")
	}
}

func TestDecodeJSONQuery_InvalidJSON(t *testing.T) {
	_, err := DecodeJSONQuery([]byte("not json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestDecodeJSONQuery_MissingName(t *testing.T) {
	_, err := DecodeJSONQuery([]byte(`{"type": "A"}`))
	if err == nil {
		t.Error("Expected error for missing name")
	}
}

func TestEncodeJSON_NilMessage(t *testing.T) {
	_, err := EncodeJSON(nil)
	if err == nil {
		t.Error("Expected error for nil message")
	}
}

func TestEncodeJSON_EmptySections(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeNameError),
		},
		Questions: []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{"nonexistent", "example", "com"}, FQDN: true},
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	data, err := EncodeJSON(msg)
	if err != nil {
		t.Fatalf("EncodeJSON failed: %v", err)
	}

	var resp JSONResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if resp.Status != int(protocol.RcodeNameError) {
		t.Errorf("Expected Status %d (NXDOMAIN), got %d", protocol.RcodeNameError, resp.Status)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("Expected empty answer, got %d records", len(resp.Answer))
	}
	if len(resp.Authority) != 0 {
		t.Errorf("Expected empty authority, got %d records", len(resp.Authority))
	}
}

func TestEncodeJSON_OPTFiltered(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.NewResponseFlags(protocol.RcodeSuccess),
		},
		Questions: []*protocol.Question{
			{
				Name:   &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  &protocol.Name{Labels: []string{"example", "com"}, FQDN: true},
				Type:  protocol.TypeA,
				Class: protocol.ClassIN,
				TTL:   300,
				Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
			},
		},
	}

	// Add an OPT record to the additional section
	msg.SetEDNS0(4096, false)

	data, err := EncodeJSON(msg)
	if err != nil {
		t.Fatalf("EncodeJSON failed: %v", err)
	}

	var resp JSONResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// OPT records should be filtered from JSON output
	if len(resp.Additional) != 0 {
		t.Errorf("Expected 0 additional records (OPT filtered), got %d", len(resp.Additional))
	}
}

func TestEncodeJSON_Flags(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{
				QR:    true,
				RD:    true,
				RA:    true,
				AD:    true,
				CD:    true,
				TC:    true,
				RCODE: protocol.RcodeSuccess,
			},
		},
	}

	data, err := EncodeJSON(msg)
	if err != nil {
		t.Fatalf("EncodeJSON failed: %v", err)
	}

	var resp JSONResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if !resp.TC {
		t.Error("Expected TC true")
	}
	if !resp.RD {
		t.Error("Expected RD true")
	}
	if !resp.RA {
		t.Error("Expected RA true")
	}
	if !resp.AD {
		t.Error("Expected AD true")
	}
	if !resp.CD {
		t.Error("Expected CD true")
	}
}

// makeAAAA creates an RDataAAAA from a string IPv6 address.
func makeAAAA(addr string) *protocol.RDataAAAA {
	ip := net.ParseIP(addr)
	if ip == nil {
		panic("invalid IPv6 address: " + addr)
	}
	var a protocol.RDataAAAA
	copy(a.Address[:], ip.To16())
	return &a
}
