package transfer

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestNewNOTIFYSender(t *testing.T) {
	sender := NewNOTIFYSender(":53")

	if sender == nil {
		t.Fatal("NewNOTIFYSender() returned nil")
	}

	if sender.serverAddr != ":53" {
		t.Errorf("Expected serverAddr :53, got %s", sender.serverAddr)
	}

	if sender.timeout != 5*time.Second {
		t.Errorf("Expected default timeout 5s, got %v", sender.timeout)
	}
}

func TestNOTIFYSender_SetTimeout(t *testing.T) {
	sender := NewNOTIFYSender(":53")
	sender.SetTimeout(10 * time.Second)

	if sender.timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", sender.timeout)
	}
}

func TestNOTIFYSender_buildNOTIFYRequest(t *testing.T) {
	sender := NewNOTIFYSender(":53")

	req, err := sender.buildNOTIFYRequest("example.com.", 2024010101)
	if err != nil {
		t.Fatalf("buildNOTIFYRequest() error = %v", err)
	}

	// Check header
	if req.Header.QDCount != 1 {
		t.Errorf("Expected QDCount 1, got %d", req.Header.QDCount)
	}

	if req.Header.ANCount != 1 {
		t.Errorf("Expected ANCount 1, got %d", req.Header.ANCount)
	}

	if req.Header.Flags.Opcode != protocol.OpcodeNotify {
		t.Errorf("Expected Opcode NOTIFY, got %d", req.Header.Flags.Opcode)
	}

	if req.Header.Flags.QR {
		t.Error("Expected QR=0 for request")
	}

	// Check question
	if len(req.Questions) != 1 {
		t.Fatal("Expected 1 question")
	}

	q := req.Questions[0]
	if q.QType != protocol.TypeSOA {
		t.Errorf("Expected QType SOA, got %d", q.QType)
	}

	// Check answer
	if len(req.Answers) != 1 {
		t.Fatal("Expected 1 answer")
	}

	if req.Answers[0].Type != protocol.TypeSOA {
		t.Errorf("Expected SOA answer, got type %d", req.Answers[0].Type)
	}

	if soaData, ok := req.Answers[0].Data.(*protocol.RDataSOA); ok {
		if soaData.Serial != 2024010101 {
			t.Errorf("Expected serial 2024010101, got %d", soaData.Serial)
		}
	} else {
		t.Error("Answer data is not *protocol.RDataSOA")
	}
}

func TestNewNOTIFYSlaveHandler(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewNOTIFYSlaveHandler(zones)

	if handler == nil {
		t.Fatal("NewNOTIFYSlaveHandler() returned nil")
	}

	if handler.zones == nil {
		t.Error("zones map not initialized")
	}

	if handler.notifyChan == nil {
		t.Error("notifyChan not initialized")
	}
}

func TestNOTIFYSlaveHandler_GetNotifyChannel(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewNOTIFYSlaveHandler(zones)

	ch := handler.GetNotifyChannel()
	if ch == nil {
		t.Error("GetNotifyChannel() returned nil")
	}
}

func TestNOTIFYSlaveHandler_HandleNOTIFY_NoZone(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewNOTIFYSlaveHandler(zones)

	// Create NOTIFY request for non-existent zone
	name, _ := protocol.ParseName("nonexistent.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeSOA,
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	resp, err := handler.HandleNOTIFY(req, clientIP)

	if err != nil {
		t.Fatalf("HandleNOTIFY() error = %v", err)
	}

	if resp == nil {
		t.Fatal("HandleNOTIFY() returned nil response")
	}

	// Should return NotAuth since we don't have the zone
	if resp.Header.Flags.RCODE != protocol.RcodeNotAuth {
		t.Errorf("Expected rcode NotAuth, got %d", resp.Header.Flags.RCODE)
	}
}

func TestNOTIFYSlaveHandler_HandleNOTIFY_Success(t *testing.T) {
	zones := make(map[string]*zone.Zone)

	// Add a zone
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   "ns1.example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010101,
		Refresh: 3600,
	}
	zones["example.com."] = z

	handler := NewNOTIFYSlaveHandler(zones)

	// Create NOTIFY request with newer serial
	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	soaData := &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  2024010102, // Newer serial
		Refresh: 3600,
		Retry:   600,
		Expire:  604800,
		Minimum: 86400,
	}

	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data:  soaData,
	}

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      1234,
			QDCount: 1,
			ANCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{
			{
				Name:   origin,
				QType:  protocol.TypeSOA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{soaRR},
	}

	clientIP := net.ParseIP("127.0.0.1")
	resp, err := handler.HandleNOTIFY(req, clientIP)

	if err != nil {
		t.Fatalf("HandleNOTIFY() error = %v", err)
	}

	if resp == nil {
		t.Fatal("HandleNOTIFY() returned nil response")
	}

	// Should return success
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("Expected rcode Success, got %d", resp.Header.Flags.RCODE)
	}

	// Check that QR bit is set in response
	if !resp.Header.Flags.QR {
		t.Error("Expected QR=1 in response")
	}

	// Check that a NOTIFY request was sent to the channel
	select {
	case notifyReq := <-handler.GetNotifyChannel():
		if notifyReq.ZoneName != "example.com." {
			t.Errorf("Expected zone example.com., got %s", notifyReq.ZoneName)
		}
		if notifyReq.Serial != 2024010102 {
			t.Errorf("Expected serial 2024010102, got %d", notifyReq.Serial)
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for NOTIFY request on channel")
	}
}

func TestNOTIFYSlaveHandler_HandleNOTIFY_InvalidQuestionCount(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewNOTIFYSlaveHandler(zones)

	req := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{},
	}

	clientIP := net.ParseIP("127.0.0.1")
	_, err := handler.HandleNOTIFY(req, clientIP)

	if err == nil {
		t.Error("Expected error for empty questions")
	}
}

func TestNOTIFYSlaveHandler_HandleNOTIFY_WrongQType(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewNOTIFYSlaveHandler(zones)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  protocol.TypeA, // Wrong type
				QClass: protocol.ClassIN,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	_, err := handler.HandleNOTIFY(req, clientIP)

	if err == nil {
		t.Error("Expected error for wrong QType")
	}
}

func TestIsNOTIFYRequest(t *testing.T) {
	tests := []struct {
		name     string
		opcode   uint8
		qr       bool
		expected bool
	}{
		{"NOTIFY request", protocol.OpcodeNotify, false, true},
		{"NOTIFY response", protocol.OpcodeNotify, true, false},
		{"QUERY request", protocol.OpcodeQuery, false, false},
		{"QUERY response", protocol.OpcodeQuery, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{
						Opcode: tt.opcode,
						QR:     tt.qr,
					},
				},
			}
			got := IsNOTIFYRequest(msg)
			if got != tt.expected {
				t.Errorf("IsNOTIFYRequest() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsNOTIFYResponse(t *testing.T) {
	tests := []struct {
		name     string
		opcode   uint8
		qr       bool
		expected bool
	}{
		{"NOTIFY request", protocol.OpcodeNotify, false, false},
		{"NOTIFY response", protocol.OpcodeNotify, true, true},
		{"QUERY request", protocol.OpcodeQuery, false, false},
		{"QUERY response", protocol.OpcodeQuery, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &protocol.Message{
				Header: protocol.Header{
					Flags: protocol.Flags{
						Opcode: tt.opcode,
						QR:     tt.qr,
					},
				},
			}
			got := IsNOTIFYResponse(msg)
			if got != tt.expected {
				t.Errorf("IsNOTIFYResponse() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNOTIFYSlaveHandler_SetSerialChecker(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	handler := NewNOTIFYSlaveHandler(zones)

	// Create a custom serial checker
	checkerCalled := false
	checker := func(zoneName string, serial uint32) bool {
		checkerCalled = true
		return true
	}

	handler.SetSerialChecker(checker)

	if handler.serialCheck == nil {
		t.Error("SetSerialChecker did not set the checker")
	}

	// Test that it's called during HandleNOTIFY
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Serial: 2024010101}
	zones["example.com."] = z

	origin, _ := protocol.ParseName("example.com.")
	soaData := &protocol.RDataSOA{
		MName:   origin,
		RName:   origin,
		Serial:  2024010102,
		Refresh: 3600,
	}

	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{
			{
				Name:   origin,
				QType:  protocol.TypeSOA,
				QClass: protocol.ClassIN,
			},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  origin,
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				Data:  soaData,
			},
		},
	}

	clientIP := net.ParseIP("127.0.0.1")
	handler.HandleNOTIFY(req, clientIP)

	if !checkerCalled {
		t.Error("Serial checker was not called")
	}
}
