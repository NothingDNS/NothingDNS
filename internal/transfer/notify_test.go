package transfer

import (
	"net"
	"strings"
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
	handler.AddNotifyAllowed("127.0.0.1/32")

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
	handler.AddNotifyAllowed("127.0.0.1/32")

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
	handler.AddNotifyAllowed("127.0.0.1/32")

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
	handler.AddNotifyAllowed("127.0.0.1/32")

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
	handler.AddNotifyAllowed("127.0.0.1/32")

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

// ---------------------------------------------------------------------------
// buildNOTIFYRequest - invalid zone name (label > 63 chars)
// ---------------------------------------------------------------------------

func TestNOTIFYSender_buildNOTIFYRequest_InvalidName(t *testing.T) {
	sender := NewNOTIFYSender(":53")

	longLabel := strings.Repeat("a", 70)
	_, err := sender.buildNOTIFYRequest(longLabel+".example.com.", 2024010101)
	if err == nil {
		t.Error("Expected error for zone name with label exceeding 63 chars")
	}
}

// ---------------------------------------------------------------------------
// SendNOTIFY - connection error (unreachable slave)
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_ConnectionError(t *testing.T) {
	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(100 * time.Millisecond)

	err := sender.SendNOTIFY("example.com.", 2024010101, "192.0.2.1:53")
	if err == nil {
		t.Error("Expected error for unreachable slave address")
	}
}

// ---------------------------------------------------------------------------
// SendNOTIFY - success with mock UDP server
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_Success(t *testing.T) {
	// Start a mock UDP server that responds to NOTIFY
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 65535)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		// Parse the request
		msg, err := protocol.UnpackMessage(buf[:n])
		if err != nil {
			return
		}

		// Build a proper NOTIFY response
		resp := &protocol.Message{
			Header: protocol.Header{
				ID: msg.Header.ID,
				Flags: protocol.Flags{
					QR:     true,
					Opcode: protocol.OpcodeNotify,
				},
			},
			Questions: msg.Questions,
		}

		respBuf := make([]byte, 65535)
		rn, err := resp.Pack(respBuf)
		if err != nil {
			return
		}

		serverConn.WriteToUDP(respBuf[:rn], clientAddr)
	}()

	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(2 * time.Second)

	err = sender.SendNOTIFY("example.com.", 2024010101, serverConn.LocalAddr().String())
	if err != nil {
		t.Fatalf("SendNOTIFY() error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// SendNOTIFY - server returns error RCODE
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_ServerError(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 65535)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		msg, err := protocol.UnpackMessage(buf[:n])
		if err != nil {
			return
		}

		// Respond with Refused RCODE
		resp := &protocol.Message{
			Header: protocol.Header{
				ID: msg.Header.ID,
				Flags: protocol.Flags{
					QR:     true,
					Opcode: protocol.OpcodeNotify,
					RCODE:  protocol.RcodeRefused,
				},
			},
			Questions: msg.Questions,
		}

		respBuf := make([]byte, 65535)
		rn, err := resp.Pack(respBuf)
		if err != nil {
			return
		}

		serverConn.WriteToUDP(respBuf[:rn], clientAddr)
	}()

	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(2 * time.Second)

	err = sender.SendNOTIFY("example.com.", 2024010101, serverConn.LocalAddr().String())
	if err == nil {
		t.Error("Expected error for server error RCODE")
	}
	if !strings.Contains(err.Error(), "rcode") {
		t.Errorf("Expected rcode error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SendNOTIFY - server response with QR not set
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_QRNotSet(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 65535)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		msg, err := protocol.UnpackMessage(buf[:n])
		if err != nil {
			return
		}

		// Respond with QR=0 (not set)
		resp := &protocol.Message{
			Header: protocol.Header{
				ID: msg.Header.ID,
				Flags: protocol.Flags{
					QR:     false,
					Opcode: protocol.OpcodeNotify,
				},
			},
			Questions: msg.Questions,
		}

		respBuf := make([]byte, 65535)
		rn, err := resp.Pack(respBuf)
		if err != nil {
			return
		}

		serverConn.WriteToUDP(respBuf[:rn], clientAddr)
	}()

	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(2 * time.Second)

	err = sender.SendNOTIFY("example.com.", 2024010101, serverConn.LocalAddr().String())
	if err == nil {
		t.Error("Expected error for QR not set in response")
	}
	if !strings.Contains(err.Error(), "QR") {
		t.Errorf("Expected QR error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SendNOTIFY - server response with wrong opcode
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_OpcodeMismatch(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 65535)
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		msg, err := protocol.UnpackMessage(buf[:n])
		if err != nil {
			return
		}

		// Respond with QUERY opcode instead of NOTIFY
		resp := &protocol.Message{
			Header: protocol.Header{
				ID: msg.Header.ID,
				Flags: protocol.Flags{
					QR:     true,
					Opcode: protocol.OpcodeQuery,
				},
			},
			Questions: msg.Questions,
		}

		respBuf := make([]byte, 65535)
		rn, err := resp.Pack(respBuf)
		if err != nil {
			return
		}

		serverConn.WriteToUDP(respBuf[:rn], clientAddr)
	}()

	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(2 * time.Second)

	err = sender.SendNOTIFY("example.com.", 2024010101, serverConn.LocalAddr().String())
	if err == nil {
		t.Error("Expected error for opcode mismatch")
	}
	if !strings.Contains(err.Error(), "opcode") {
		t.Errorf("Expected opcode error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// SendNOTIFY - timeout (no server response)
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_Timeout(t *testing.T) {
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer serverConn.Close()

	// Server reads but never responds
	go func() {
		buf := make([]byte, 65535)
		serverConn.ReadFromUDP(buf)
	}()

	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(100 * time.Millisecond)

	err = sender.SendNOTIFY("example.com.", 2024010101, serverConn.LocalAddr().String())
	if err == nil {
		t.Error("Expected error for timeout")
	}
}

// ---------------------------------------------------------------------------
// HandleNOTIFY - serial from Authority section (Answer has no SOA)
// ---------------------------------------------------------------------------

func TestNOTIFYSlaveHandler_HandleNOTIFY_SerialFromAuthority(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Serial: 100}
	zones["example.com."] = z

	handler := NewNOTIFYSlaveHandler(zones)
	handler.AddNotifyAllowed("127.0.0.1/32")

	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	// SOA in Authority section, not in Answer
	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data: &protocol.RDataSOA{
			MName: mname, RName: rname,
			Serial: 200, Refresh: 3600,
		},
	}

	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 1,
			NSCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeNotify},
		},
		Questions: []*protocol.Question{
			{Name: origin, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{soaRR},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY() error = %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}

	// Check notify channel received the serial from Authority
	select {
	case notifyReq := <-handler.GetNotifyChannel():
		if notifyReq.Serial != 200 {
			t.Errorf("Expected serial 200 (from Authority), got %d", notifyReq.Serial)
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for NOTIFY event")
	}
}

// ---------------------------------------------------------------------------
// HandleNOTIFY - serial from local zone (no SOA in Answer or Authority)
// ---------------------------------------------------------------------------

func TestNOTIFYSlaveHandler_HandleNOTIFY_SerialFromLocalZone(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 300,
	}
	zones["example.com."] = z

	handler := NewNOTIFYSlaveHandler(zones)
	handler.AddNotifyAllowed("127.0.0.1/32")

	origin, _ := protocol.ParseName("example.com.")

	// No SOA in Answer or Authority - should fall back to local zone SOA
	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeNotify},
		},
		Questions: []*protocol.Question{
			{Name: origin, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY() error = %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}

	// Local zone serial is 300, current zone serial is also 300, so receivedSerial <= z.SOA.Serial
	// This means needsUpdate=false, so nothing on the channel
	select {
	case <-handler.GetNotifyChannel():
		t.Error("Expected no NOTIFY event since serial didn't increase")
	default:
		// Expected - no update needed
	}
}

// ---------------------------------------------------------------------------
// HandleNOTIFY - same serial should not trigger update
// ---------------------------------------------------------------------------

func TestNOTIFYSlaveHandler_HandleNOTIFY_SameSerial_NoUpdate(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{Serial: 100}
	zones["example.com."] = z

	handler := NewNOTIFYSlaveHandler(zones)
	handler.AddNotifyAllowed("127.0.0.1/32")

	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	// Same serial as current zone
	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data: &protocol.RDataSOA{
			MName: mname, RName: rname,
			Serial: 100, Refresh: 3600, // Same serial as local zone
		},
	}

	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 1,
			ANCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeNotify},
		},
		Questions: []*protocol.Question{
			{Name: origin, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{soaRR},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY() error = %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}

	// Same serial, no update should be sent
	select {
	case <-handler.GetNotifyChannel():
		t.Error("Expected no NOTIFY event for same serial")
	default:
		// Expected
	}
}

// ---------------------------------------------------------------------------
// HandleNOTIFY - zone without SOA (nil check)
// ---------------------------------------------------------------------------

func TestNOTIFYSlaveHandler_HandleNOTIFY_ZoneWithoutSOA(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	z := zone.NewZone("example.com.")
	z.SOA = nil
	zones["example.com."] = z

	handler := NewNOTIFYSlaveHandler(zones)
	handler.AddNotifyAllowed("127.0.0.1/32")

	origin, _ := protocol.ParseName("example.com.")

	// No SOA in request, no SOA in zone
	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeNotify},
		},
		Questions: []*protocol.Question{
			{Name: origin, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY() error = %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}

	// No serial available, but serialCheck is nil and z.SOA is nil,
	// so needsUpdate stays true (serial 0 with nil SOA skips the else-if)
	select {
	case notifyReq := <-handler.GetNotifyChannel():
		if notifyReq.Serial != 0 {
			t.Errorf("Expected serial 0, got %d", notifyReq.Serial)
		}
	case <-time.After(time.Second):
		t.Error("Expected NOTIFY event since no SOA means needsUpdate=true")
	}
}

// ---------------------------------------------------------------------------
// HandleNOTIFY - zone without SOA, with serial in Answer
// ---------------------------------------------------------------------------

func TestNOTIFYSlaveHandler_HandleNOTIFY_ZoneWithoutSOA_WithSerial(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	z := zone.NewZone("example.com.")
	z.SOA = nil
	zones["example.com."] = z

	handler := NewNOTIFYSlaveHandler(zones)
	handler.AddNotifyAllowed("127.0.0.1/32")

	origin, _ := protocol.ParseName("example.com.")
	mname, _ := protocol.ParseName("ns1.example.com.")
	rname, _ := protocol.ParseName("admin.example.com.")

	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data: &protocol.RDataSOA{
			MName: mname, RName: rname,
			Serial: 500, Refresh: 3600,
		},
	}

	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 1,
			ANCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeNotify},
		},
		Questions: []*protocol.Question{
			{Name: origin, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{soaRR},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY() error = %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("Expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}

	select {
	case notifyReq := <-handler.GetNotifyChannel():
		if notifyReq.Serial != 500 {
			t.Errorf("Expected serial 500, got %d", notifyReq.Serial)
		}
	case <-time.After(time.Second):
		t.Error("Expected NOTIFY event for new serial")
	}
}
