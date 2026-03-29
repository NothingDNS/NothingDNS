package transfer

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// mustParseName5 is a test helper that parses a DNS name or panic(err)
func mustParseName5(name string) *protocol.Name {
	n, err := protocol.ParseName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// ---------------------------------------------------------------------------
// axfr.go:227 - zoneRecordToRR with invalid owner name (ParseName error)
// ---------------------------------------------------------------------------

func TestAXFRServer_zoneRecordToRR_InvalidOwner_Extra5(t *testing.T) {
	s := NewAXFRServer(make(map[string]*zone.Zone))
	longLabel := strings.Repeat("a", 70)
	_, err := s.zoneRecordToRR(longLabel+".example.com.", zone.Record{
		Name: longLabel + ".example.com.", Type: "A", TTL: 3600, RData: "1.2.3.4",
	}, "example.com.")
	if err == nil {
		t.Error("expected error for invalid owner name in zoneRecordToRR")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:153 - generateAXFRRecords with invalid RName (createSOARR error)
// ---------------------------------------------------------------------------

func TestAXFRServer_generateAXFRRecords_InvalidRName_Extra5(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.",
		RName: strings.Repeat("a", 70) + ".example.com.", // Invalid: label > 63 chars
		Serial: 42, TTL: 3600,
	}
	s := NewAXFRServer(map[string]*zone.Zone{"example.com.": z})
	_, err := s.generateAXFRRecords(z)
	if err == nil {
		t.Error("expected error for invalid RName in generateAXFRRecords")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:153 - generateAXFRRecords with invalid MName (createSOARR error)
// ---------------------------------------------------------------------------

func TestAXFRServer_generateAXFRRecords_InvalidMName_Extra5(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: strings.Repeat("a", 70) + ".example.com.", // Invalid: label > 63 chars
		RName: "admin.example.com.",
		Serial: 42, TTL: 3600,
	}
	s := NewAXFRServer(map[string]*zone.Zone{"example.com.": z})
	_, err := s.generateAXFRRecords(z)
	if err == nil {
		t.Error("expected error for invalid MName in generateAXFRRecords")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:427 - Transfer with buildAXFRRequest error
// ---------------------------------------------------------------------------

func TestAXFRClient_Transfer_BuildRequestError_Extra5(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	longLabel := strings.Repeat("a", 70)
	_, err := client.Transfer(longLabel+".example.com.", nil)
	if err == nil {
		t.Error("expected error for buildAXFRRequest failure in Transfer")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:427 - Transfer with sendMessage error (server closes after connect)
// ---------------------------------------------------------------------------

func TestAXFRClient_Transfer_SendMessageError_Extra5(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	client := NewAXFRClient(addr, WithAXFRTimeout(2*time.Second))
	_, err = client.Transfer("example.com.", nil)
	if err == nil {
		t.Error("expected error when sendMessage fails")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:512 - receiveAXFRResponse with unpack error
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_UnpackError_Extra5(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	// Valid length prefix but garbage data
	data := []byte{0x00, 0x10}
	data = append(data, make([]byte, 16)...)
	conn := &mockConn{readData: data}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("expected error for unpack failure")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:512 - receiveAXFRResponse with invalid message length (0)
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_InvalidLengthZero_Extra5(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	conn := &mockConn{readData: []byte{0x00, 0x00}}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("expected error for zero message length")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:512 - receiveAXFRResponse with soaCount >= 2 then connection error
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_SOAGe2ThenBreak_Extra5(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	origin := mustParseName5("example.com.")
	mname := mustParseName5("ns1.example.com.")
	rname := mustParseName5("admin.example.com.")

	soaRR := &protocol.ResourceRecord{
		Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 86400,
		Data: &protocol.RDataSOA{
			MName: mname, RName: rname,
			Serial: 2024010101, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
		},
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID: 0x1234, Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
		},
		Answers: []*protocol.ResourceRecord{soaRR, soaRR},
	}

	buf := make([]byte, 65535)
	n, _ := msg.Pack(buf)
	var allData []byte
	allData = append(allData, byte(n>>8), byte(n))
	allData = append(allData, buf[:n]...)

	conn := &mockConn{readData: allData}
	records, err := client.receiveAXFRResponse(conn, nil)
	if err != nil {
		t.Fatalf("receiveAXFRResponse: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("expected 2 records, got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// axfr.go:101 - HandleAXFR with TSIG key name error
// ---------------------------------------------------------------------------

func TestAXFRServer_HandleAXFR_TSIGKeyNameError_Extra5(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	ks := NewKeyStore()
	server := NewAXFRServer(zones, WithKeyStore(ks))

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 2024010101, TTL: 86400,
	}
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{ID: 1234, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name: mustParseName5("test-key."), Type: protocol.TypeTSIG,
				Class: protocol.ClassANY, TTL: 0,
				Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // Wrong data type
			},
		},
	}

	_, err := server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("expected error for TSIG key name extraction failure")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:101 - HandleAXFR TSIG key not found
// ---------------------------------------------------------------------------

func TestAXFRServer_HandleAXFR_TSIGKeyNotFound_Extra5(t *testing.T) {
	zones := make(map[string]*zone.Zone)
	ks := NewKeyStore()
	server := NewAXFRServer(zones, WithKeyStore(ks))

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 2024010101, TTL: 86400,
	}
	server.AddZone(z)

	name, _ := protocol.ParseName("example.com.")
	keyName, _ := protocol.ParseName("nonexistent-key.")

	req := &protocol.Message{
		Header: protocol.Header{ID: 1234, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name: keyName, Type: protocol.TypeTSIG, Class: protocol.ClassANY, TTL: 0,
				Data: &RDataTSIG{Raw: []byte("dummy")},
			},
		},
	}

	_, err := server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("expected error for TSIG key not found")
	}
}

// ---------------------------------------------------------------------------
// notify.go:50 - SendNOTIFY with buildNOTIFYRequest error
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_BuildError_Extra5(t *testing.T) {
	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(100 * time.Millisecond)

	longLabel := strings.Repeat("a", 70)
	err := sender.SendNOTIFY(longLabel+".example.com.", 2024010101, "127.0.0.1:0")
	if err == nil {
		t.Error("expected error for buildNOTIFYRequest failure")
	}
}

// ---------------------------------------------------------------------------
// notify.go:50 - SendNOTIFY with write error
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_WriteError_Extra5(t *testing.T) {
	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(100 * time.Millisecond)

	err := sender.SendNOTIFY("example.com.", 2024010101, "0.0.0.0:0")
	if err == nil {
		t.Error("expected error for connection/write failure")
	}
}

// ---------------------------------------------------------------------------
// notify.go:50 - SendNOTIFY with unpack response error
// ---------------------------------------------------------------------------

func TestNOTIFYSender_SendNOTIFY_UnpackResponseError_Extra5(t *testing.T) {
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
		_ = n
		serverConn.WriteToUDP([]byte{0xFF, 0xFF, 0xFF, 0xFF}, clientAddr)
	}()

	sender := NewNOTIFYSender(":0")
	sender.SetTimeout(2 * time.Second)
	err = sender.SendNOTIFY("example.com.", 2024010101, serverConn.LocalAddr().String())
	if err == nil {
		t.Error("expected error for unpack response failure")
	}
}

// ---------------------------------------------------------------------------
// ddns.go:129 - HandleUpdate with TSIG key name extraction error
// ---------------------------------------------------------------------------

func TestHandleUpdate_TSIGKeyNameError_Extra5(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1}
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})
	ks := NewKeyStore()
	handler.SetKeyStore(ks)

	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name: mustParseName5("test-key"), Type: protocol.TypeTSIG,
				Class: protocol.ClassANY, TTL: 0,
				Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}, // Wrong data type
			},
		},
	}

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleUpdate: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeNotAuth {
		t.Errorf("expected RcodeNotAuth for TSIG key not found, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// ddns.go:348 - ApplyUpdate with precondition ExistsValue (non-existent record)
// ---------------------------------------------------------------------------

func TestApplyUpdate_PreconditionExistsValue_PassThrough_Extra5(t *testing.T) {
	z := newTestZoneWithRecords()

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Prerequisites: []UpdatePrerequisite{
			{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				Condition: PrecondExistsValue,
				RData:     "99.99.99.99", // Does not exist
			},
		},
		Updates: []UpdateOperation{},
	}

	err := ApplyUpdate(z, update)
	if err == nil {
		t.Errorf("expected error for PrecondExistsValue with non-existent record")
	}
}

// ---------------------------------------------------------------------------
// ddns.go:367 - checkPrerequisiteOnZone PrecondExistsValue with empty RData (type exists)
// ---------------------------------------------------------------------------

func TestCheckPrerequisiteOnZone_ExistsValue_EmptyRData_TypeExists_Extra5(t *testing.T) {
	z := newTestZoneWithRecords()

	err := checkPrerequisiteOnZone(z, UpdatePrerequisite{
		Name:      "www.example.com.",
		Type:      protocol.TypeA,
		Condition: PrecondExistsValue,
		RData:     "", // Empty RData -> falls back to type check
	})
	if err != nil {
		t.Errorf("expected no error when RData is empty and type exists: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ddns.go:367 - checkPrerequisiteOnZone PrecondExistsValue with empty RData (type missing)
// ---------------------------------------------------------------------------

func TestCheckPrerequisiteOnZone_ExistsValue_EmptyRData_TypeMissing_Extra5(t *testing.T) {
	z := newTestZoneWithRecords()

	err := checkPrerequisiteOnZone(z, UpdatePrerequisite{
		Name:      "www.example.com.",
		Type:      protocol.TypeMX, // MX does not exist
		Condition: PrecondExistsValue,
		RData:     "",
	})
	if err == nil {
		t.Error("expected error when RData is empty and type does not exist")
	}
}

// ---------------------------------------------------------------------------
// ddns.go:348 - ApplyUpdate with precondition ExistsValue (existing record)
// Tests the success path for PrecondExistsValue.
// ---------------------------------------------------------------------------

func TestApplyUpdate_PreconditionExistsValue_Success_Extra5(t *testing.T) {
	z := newTestZoneWithRecords()

	update := &UpdateRequest{
		ZoneName: "example.com.",
		Prerequisites: []UpdatePrerequisite{
			{
				Name:      "www.example.com.",
				Type:      protocol.TypeA,
				Condition: PrecondExistsValue,
				RData:     "192.0.2.1", // Exists in test zone
			},
		},
		Updates: []UpdateOperation{},
	}

	err := ApplyUpdate(z, update)
	if err != nil {
		t.Errorf("expected no error for PrecondExistsValue with existing record: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:346 - IXFRClient.Transfer with sendMessage error (server closes)
// ---------------------------------------------------------------------------

func TestIXFRClient_Transfer_SendMessageError_Extra5(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	client := NewIXFRClient(addr, WithIXFRTimeout(2*time.Second))
	_, err = client.Transfer("example.com.", 100, nil)
	if err == nil {
		t.Error("expected error when sendMessage fails in IXFR Transfer")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:346 - IXFRClient.Transfer with buildIXFRRequest error
// ---------------------------------------------------------------------------

func TestIXFRClient_Transfer_BuildRequestError_Extra5(t *testing.T) {
	client := NewIXFRClient("ns1.example.com:53")
	longLabel := strings.Repeat("a", 70)
	_, err := client.Transfer(longLabel+".example.com.", 100, nil)
	if err == nil {
		t.Error("expected error for buildIXFRRequest failure")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:287 - changeToRR with invalid name
// ---------------------------------------------------------------------------

func TestIXFRServer_changeToRR_InvalidName_Extra5(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	longLabel := strings.Repeat("a", 70)
	_, err := server.changeToRR(zone.RecordChange{
		Name: longLabel + ".example.com.", Type: protocol.TypeA, TTL: 3600, RData: "1.2.3.4",
	}, "example.com.")
	if err == nil {
		t.Error("expected error for invalid name in changeToRR")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:287 - changeToRR with invalid RData
// ---------------------------------------------------------------------------

func TestIXFRServer_changeToRR_InvalidRData_Extra5(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	_, err := server.changeToRR(zone.RecordChange{
		Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "not-an-ip",
	}, "example.com.")
	if err == nil {
		t.Error("expected error for invalid RData in changeToRR")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:287 - changeToRR success path
// ---------------------------------------------------------------------------

func TestIXFRServer_changeToRR_Success_Extra5(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	rr, err := server.changeToRR(zone.RecordChange{
		Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "1.2.3.4",
	}, "example.com.")
	if err != nil {
		t.Fatalf("changeToRR: %v", err)
	}
	if rr.Type != protocol.TypeA {
		t.Errorf("expected TypeA, got %d", rr.Type)
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:183 - generateIncrementalIXFR with deleted records containing invalid change
// ---------------------------------------------------------------------------

func TestIXFRServer_generateIncrementalIXFR_DeletedInvalidChange_Extra5(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 2024010103, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	server.RecordChange("example.com.", 2024010101, 2024010102,
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "1.2.3.4"},
		},
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "invalid-ip"},
		},
	)
	server.RecordChange("example.com.", 2024010102, 2024010103,
		[]zone.RecordChange{},
		[]zone.RecordChange{},
	)

	records, err := server.generateIncrementalIXFR(z, 2024010101)
	if err != nil {
		t.Fatalf("generateIncrementalIXFR: %v", err)
	}
	if len(records) < 2 {
		t.Errorf("expected at least 2 records, got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:183 - generateIncrementalIXFR success with valid added records
// ---------------------------------------------------------------------------

func TestIXFRServer_generateIncrementalIXFR_ValidAdded_Extra5(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 2024010103, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400, TTL: 3600,
	}

	server.RecordChange("example.com.", 2024010101, 2024010102,
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "1.2.3.4"},
		},
		[]zone.RecordChange{},
	)
	server.RecordChange("example.com.", 2024010102, 2024010103,
		[]zone.RecordChange{},
		[]zone.RecordChange{},
	)

	records, err := server.generateIncrementalIXFR(z, 2024010101)
	if err != nil {
		t.Fatalf("generateIncrementalIXFR: %v", err)
	}
	if len(records) < 3 {
		t.Errorf("expected at least 3 records, got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// slave.go:156 - AddSlaveZone duplicate zone
// ---------------------------------------------------------------------------

func TestSlaveManager_AddSlaveZone_Duplicate_Extra5(t *testing.T) {
	sm := NewSlaveManager(nil)

	config := SlaveZoneConfig{
		ZoneName: "dup.example.com.",
		Masters:  []string{"127.0.0.1:53"},
	}
	err := sm.AddSlaveZone(config)
	if err != nil {
		t.Fatalf("first AddSlaveZone: %v", err)
	}

	err = sm.AddSlaveZone(config)
	if err == nil {
		t.Error("expected error for duplicate slave zone")
	}
}

// ---------------------------------------------------------------------------
// slave.go:156 - AddSlaveZone with TSIG key store
// ---------------------------------------------------------------------------

func TestSlaveManager_AddSlaveZone_WithTSIGKeyStore_Extra5(t *testing.T) {
	ks := NewKeyStore()
	ks.AddKey(&TSIGKey{
		Name:      "test-key.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	})
	sm := NewSlaveManager(ks)

	config := SlaveZoneConfig{
		ZoneName:     "tsigzone.example.com.",
		Masters:      []string{"127.0.0.1:53"},
		TransferType: "axfr",
		Timeout:      1 * time.Second,
		TSIGKeyName:  "test-key.",
	}
	err := sm.AddSlaveZone(config)
	if err != nil {
		t.Fatalf("AddSlaveZone with TSIG: %v", err)
	}

	sz := sm.GetSlaveZone("tsigzone.example.com.")
	if sz == nil {
		t.Error("expected slave zone to be added")
	}
}

// ---------------------------------------------------------------------------
// slave.go:199 - RemoveSlaveZone with name not ending in dot
// ---------------------------------------------------------------------------

func TestSlaveManager_RemoveSlaveZone_NoDot_Extra5(t *testing.T) {
	sm := NewSlaveManager(nil)

	config := SlaveZoneConfig{
		ZoneName: "nodot.example.com.",
		Masters:  []string{"127.0.0.1:53"},
	}
	sm.AddSlaveZone(config)

	// Remove without trailing dot
	sm.RemoveSlaveZone("nodot.example.com")

	sz := sm.GetSlaveZone("nodot.example.com.")
	if sz != nil {
		t.Error("expected slave zone to be removed")
	}
}

// ---------------------------------------------------------------------------
// slave.go:255 - notifyListener with nil request
// ---------------------------------------------------------------------------

func TestSlaveManager_notifyListener_NilRequest_Extra5(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.Start()

	// Send nil request - should be handled gracefully
	sm.GetNotifyChannel() <- nil

	time.Sleep(50 * time.Millisecond)
	sm.Stop()
}

// ---------------------------------------------------------------------------
// slave.go:255 - notifyListener with valid request then stop
// ---------------------------------------------------------------------------

func TestSlaveManager_notifyListener_ValidRequest_Extra5(t *testing.T) {
	sm := NewSlaveManager(nil)

	config := SlaveZoneConfig{
		ZoneName:      "listen.example.com.",
		Masters:       []string{"127.0.0.1:0"},
		TransferType:  "axfr",
		Timeout:       100 * time.Millisecond,
		RetryInterval: 100 * time.Millisecond,
		MaxRetries:    1,
	}
	sm.AddSlaveZone(config)

	sm.Start()
	defer sm.Stop()

	// Send valid NOTIFY for zone we manage with newer serial
	sm.GetNotifyChannel() <- &NOTIFYRequest{
		ZoneName: "listen.example.com.",
		Serial:   999,
		ClientIP: net.ParseIP("192.168.1.1"),
	}

	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// slave.go:296 - performZoneTransfer zone not found
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_NotFound_Extra5(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.performZoneTransfer("nonexistent.example.com.")
}

// ---------------------------------------------------------------------------
// slave.go:296 - performZoneTransfer with IXFR fallback to AXFR
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_IXFRFallback_Extra5(t *testing.T) {
	sm := NewSlaveManager(nil)

	config := SlaveZoneConfig{
		ZoneName:      "ixfrfb.example.com.",
		Masters:       []string{"127.0.0.1:0"},
		TransferType:  "ixfr",
		Timeout:       100 * time.Millisecond,
		RetryInterval: 100 * time.Millisecond,
		MaxRetries:    1,
	}

	slaveZone, _ := NewSlaveZone(config)
	slaveZone.UpdateZone(zone.NewZone("ixfrfb.example.com."), 100)

	sm.mu.Lock()
	sm.slaveZones["ixfrfb.example.com."] = slaveZone
	sm.clients["ixfrfb.example.com."] = NewIXFRClient("127.0.0.1:0", WithIXFRTimeout(100*time.Millisecond))
	sm.mu.Unlock()

	sm.performZoneTransfer("ixfrfb.example.com.")
}

// ---------------------------------------------------------------------------
// slave.go:347 - performAXFR with TSIG key configured
// ---------------------------------------------------------------------------

func TestSlaveManager_performAXFR_WithTSIG_Extra5(t *testing.T) {
	ks := NewKeyStore()
	ks.AddKey(&TSIGKey{
		Name:      "testkey.",
		Algorithm: HmacSHA256,
		Secret:    []byte("test-secret-key-12345678901234"),
	})
	sm := NewSlaveManager(ks)

	config := SlaveZoneConfig{
		ZoneName:     "axfrtsig.example.com.",
		Masters:      []string{"127.0.0.1:0"},
		TransferType: "axfr",
		Timeout:      100 * time.Millisecond,
		TSIGKeyName:  "testkey.",
	}

	slaveZone, _ := NewSlaveZone(config)
	sm.mu.Lock()
	sm.slaveZones["axfrtsig.example.com."] = slaveZone
	sm.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := sm.performAXFR(ctx, slaveZone)
	if err == nil {
		t.Error("expected error for AXFR with unreachable server")
	}
}

// ---------------------------------------------------------------------------
// slave.go:296 - performZoneTransfer with AXFR error and scheduleRetry path
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_AXFRError_Extra5(t *testing.T) {
	sm := NewSlaveManager(nil)

	config := SlaveZoneConfig{
		ZoneName:      "axfrerr.example.com.",
		Masters:       []string{"127.0.0.1:0"},
		TransferType:  "axfr",
		Timeout:       50 * time.Millisecond,
		RetryInterval: 50 * time.Millisecond,
		MaxRetries:    1,
	}

	slaveZone, _ := NewSlaveZone(config)
	sm.mu.Lock()
	sm.slaveZones["axfrerr.example.com."] = slaveZone
	sm.mu.Unlock()

	// performZoneTransfer will fail and schedule retry
	sm.performZoneTransfer("axfrerr.example.com.")
	// Wait for retry to complete (it will also fail)
	time.Sleep(200 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// tsig.go:289 - SignMessage success
// ---------------------------------------------------------------------------

func TestSignMessage_Success_Extra5(t *testing.T) {
	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("a-256-bit-secret-key-for-testing!"),
	}

	msg := &protocol.Message{
		Header: protocol.Header{ID: 1234, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: mustParseName5("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}

	tsigRR, err := SignMessage(msg, key, 300)
	if err != nil {
		t.Fatalf("SignMessage() error = %v", err)
	}
	if tsigRR == nil {
		t.Fatal("Expected non-nil TSIG RR")
	}
	if tsigRR.Type != protocol.TypeTSIG {
		t.Errorf("Expected TypeTSIG, got %d", tsigRR.Type)
	}
}

// ---------------------------------------------------------------------------
// tsig.go:392 - calculateMAC SHA-256 (direct coverage)
// ---------------------------------------------------------------------------

func TestCalculateMAC_SHA256_Extra5(t *testing.T) {
	mac, err := calculateMAC([]byte("key"), []byte("data"), HmacSHA256)
	if err != nil {
		t.Fatalf("calculateMAC(SHA-256) error = %v", err)
	}
	if len(mac) == 0 {
		t.Error("Expected non-empty MAC for SHA-256")
	}
}
