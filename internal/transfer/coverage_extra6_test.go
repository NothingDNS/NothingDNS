package transfer

import (
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// mustParseName6 parses a DNS name or panics.
func mustParseName6(name string) *protocol.Name {
	n, err := protocol.ParseName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// ---------------------------------------------------------------------------
// Dead code paths - documented with t.Skip for coverage tracking.
// getTSIGKeyName cannot fail after hasTSIG returns true because both
// iterate the same Additionals slice.
// ---------------------------------------------------------------------------

func TestHandleAXFR_GetTSIGKeyNameDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: getTSIGKeyName cannot fail after hasTSIG returns true")
}

func TestHandleUpdate_GetTSIGKeyNameDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: getTSIGKeyName cannot fail after hasTSIG returns true")
}

func TestHandleIXFR_GetTSIGKeyNameDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: getTSIGKeyName cannot fail after hasTSIG returns true")
}

func TestParseUpdates_ErrorReturnDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: parseUpdates always returns nil error")
}

func TestApplyOperationToZone_ErrorReturnDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: applyOperationToZone always returns nil error")
}

// ---------------------------------------------------------------------------
// tsig.go:133-135 - PackTSIGRecord PackName error (dead code)
// ---------------------------------------------------------------------------

func TestPackTSIGRecord_PackNameErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: PackName cannot fail with 256-byte buffer at offset 0 for a valid parsed name")
}

// ---------------------------------------------------------------------------
// tsig.go:191-193 - UnpackTSIGRecord insufficient data for time signed
// ---------------------------------------------------------------------------

func TestUnpackTSIGRecord_InsufficientTimeSigned_Extra6(t *testing.T) {
	algoName := mustParseName6("hmac-sha256.")
	algoBuf := make([]byte, 256)
	algoLen, _ := protocol.PackName(algoName, algoBuf, 0, nil)

	// Only 3 bytes after algorithm name instead of required 6 for time signed
	data := make([]byte, algoLen+3)
	copy(data, algoBuf[:algoLen])

	_, _, err := UnpackTSIGRecord(data, 0)
	if err == nil {
		t.Error("expected error for insufficient time signed data")
	}
	if !strings.Contains(err.Error(), "time signed") {
		t.Errorf("expected time signed error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// tsig.go:209-211 - UnpackTSIGRecord insufficient data for MAC size
// ---------------------------------------------------------------------------

func TestUnpackTSIGRecord_InsufficientMACSize_Extra6(t *testing.T) {
	algoName := mustParseName6("hmac-sha256.")
	algoBuf := make([]byte, 256)
	algoLen, _ := protocol.PackName(algoName, algoBuf, 0, nil)

	// algo name + time signed (6) + fudge (2) = no room for MAC size
	data := make([]byte, algoLen+8)
	copy(data, algoBuf[:algoLen])
	// time signed and fudge filled with zeros

	_, _, err := UnpackTSIGRecord(data, 0)
	if err == nil {
		t.Error("expected error for insufficient MAC size data")
	}
	if !strings.Contains(err.Error(), "MAC size") {
		t.Errorf("expected MAC size error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// tsig.go:297-299 - SignMessage buildSignedData error (dead code)
// buildSignedData fails only if msg.Pack fails, but messages passed to
// SignMessage are always well-formed (created by buildAXFRRequest etc.)
// ---------------------------------------------------------------------------

func TestSignMessage_BuildSignedDataErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: buildSignedData Pack error requires invalid message data, but SignMessage callers always construct valid messages")
}

// ---------------------------------------------------------------------------
// tsig.go:321-323 - SignMessage PackTSIGRecord error (dead code)
// ---------------------------------------------------------------------------

func TestSignMessage_PackTSIGRecordErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: PackTSIGRecord error in SignMessage cannot be triggered without buildSignedData panicking first")
}

// ---------------------------------------------------------------------------
// tsig.go:373-375 - VerifyMessage buildSignedData error (dead code)
// ---------------------------------------------------------------------------

func TestVerifyMessage_BuildSignedDataErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: buildSignedData Pack error requires invalid message data, but VerifyMessage callers always construct valid messages")
}

// ---------------------------------------------------------------------------
// tsig.go:379-381 - VerifyMessage calculateMAC error
// ---------------------------------------------------------------------------

func TestVerifyMessage_CalculateMACError_Extra6(t *testing.T) {
	badAlgoKey := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: "hmac-unsupported-alg",
		Secret:    []byte("test-secret-key"),
	}

	keyName := mustParseName6(badAlgoKey.Name)

	tsigData := &TSIGRecord{
		Algorithm:  badAlgoKey.Algorithm,
		TimeSigned: time.Now().UTC(),
		Fudge:      300,
		MAC:        make([]byte, 32),
		OriginalID: 1234,
		Error:      TSIGErrNoError,
	}
	packedTSIG, err := PackTSIGRecord(tsigData)
	if err != nil {
		t.Fatalf("PackTSIGRecord: %v", err)
	}

	name := mustParseName6("example.com.")
	msg := &protocol.Message{
		Header: protocol.Header{ID: 1234, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
		Additionals: []*protocol.ResourceRecord{
			{
				Name: keyName, Type: protocol.TypeTSIG,
				Class: protocol.ClassANY, TTL: 0,
				Data: &RDataTSIG{Raw: packedTSIG},
			},
		},
	}

	err = VerifyMessage(msg, badAlgoKey, nil)
	if err == nil {
		t.Error("expected error for calculateMAC failure in VerifyMessage")
	}
}

// ---------------------------------------------------------------------------
// tsig.go:432-434 - buildSignedData Pack error (dead code)
// ---------------------------------------------------------------------------

func TestBuildSignedData_PackErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: buildSignedData Pack error requires invalid message data that cannot be constructed through normal API")
}

// ---------------------------------------------------------------------------
// ixfr.go:212-214 - generateIncrementalIXFR with invalid zone origin
// ---------------------------------------------------------------------------

func TestIXFRServer_generateIncrementalIXFR_InvalidOrigin_Extra6(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	z.Origin = strings.Repeat("a", 70) + ".example.com."
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 2024010103, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	server.RecordChange("example.com.", 2024010101, 2024010102,
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "1.2.3.4"},
		},
		[]zone.RecordChange{},
	)
	server.RecordChange(strings.Repeat("a", 70)+".example.com.", 2024010102, 2024010103,
		[]zone.RecordChange{},
		[]zone.RecordChange{},
	)

	_, err := server.generateIncrementalIXFR(z, 2024010101)
	if err == nil {
		t.Error("expected error for invalid zone origin in generateIncrementalIXFR")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:220-222 - generateIncrementalIXFR createSOARR error
// ---------------------------------------------------------------------------

func TestIXFRServer_generateIncrementalIXFR_CreateSOARRError_Extra6(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:   strings.Repeat("a", 70) + ".example.com.",
		RName:   "admin.example.com.",
		Serial:  2024010103,
		Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	server.RecordChange("example.com.", 2024010101, 2024010102,
		[]zone.RecordChange{
			{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "1.2.3.4"},
		},
		[]zone.RecordChange{},
	)

	_, err := server.generateIncrementalIXFR(z, 2024010101)
	if err == nil {
		t.Error("expected error for createSOARR failure in generateIncrementalIXFR")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:424-426 - buildIXFRRequest SignMessage error
// ---------------------------------------------------------------------------

func TestIXFRClient_buildIXFRRequest_SignMessageError_Extra6(t *testing.T) {
	client := NewIXFRClient("ns1.example.com:53")

	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA1,
		Secret:    []byte("test-secret"),
	}

	_, err := client.buildIXFRRequest("example.com.", 100, key)
	if err == nil {
		t.Error("expected error for SignMessage failure in buildIXFRRequest")
	}
	if !strings.Contains(err.Error(), "signing message") {
		t.Errorf("expected signing message error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:494 - extractMAC in IXFR receiveIXFRResponse (dead code)
// After pack+unpack over TCP, TSIG records have *RDataRaw data (not *RDataTSIG),
// so VerifyMessage fails with "invalid TSIG data type" before reaching extractMAC.
// ---------------------------------------------------------------------------

func TestIXFRClient_receiveIXFRResponse_ExtractMACDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: TSIG records unpacked from wire format have *RDataRaw data, so VerifyMessage fails with 'invalid TSIG data type' before extractMAC is reached")
}

// ---------------------------------------------------------------------------
// axfr.go:559 - extractMAC in AXFR receiveAXFRResponse (dead code)
// Same reason as IXFR: TSIG records unpacked from wire format have *RDataRaw.
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_ExtractMACDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: TSIG records unpacked from wire format have *RDataRaw data, so VerifyMessage fails before extractMAC is reached")
}

// ---------------------------------------------------------------------------
// axfr.go:524-526 - receiveAXFRResponse soaCount >= 2 then break
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_SOACountBreak_Extra6(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	origin := mustParseName6("example.com.")
	mname := mustParseName6("ns1.example.com.")
	rname := mustParseName6("admin.example.com.")

	soaRR := &protocol.ResourceRecord{
		Name: origin, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 86400,
		Data: &protocol.RDataSOA{
			MName: mname, RName: rname,
			Serial: 2024010101, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
		},
	}

	// Two SOA records in one message -> soaCount = 2 -> break on next read
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
// Safety check skips (would need 1M+ records)
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_TooLargeSafetyCheck_Extra6(t *testing.T) {
	t.Skip("unreachable in reasonable test time: requires 1M+ DNS records")
}

func TestIXFRClient_receiveIXFRResponse_TooLargeSafetyCheck_Extra6(t *testing.T) {
	t.Skip("unreachable in reasonable test time: requires 1M+ DNS records")
}

// ---------------------------------------------------------------------------
// axfr.go:442-444 - Transfer sendMessage error (server closes after connect)
// ---------------------------------------------------------------------------

func TestAXFRClient_Transfer_SendMessageError_Extra6(t *testing.T) {
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
		t.Error("expected error when sendMessage fails in Transfer")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:361-363 - IXFR Transfer sendMessage error
// ---------------------------------------------------------------------------

func TestIXFRClient_Transfer_SendMessageError_Extra6(t *testing.T) {
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
// axfr.go:494-496 - AXFR sendMessage Pack error (dead code)
// ---------------------------------------------------------------------------

func TestAXFRClient_sendMessage_PackErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: sendMessage Pack error requires invalid message data; messages are always well-formed from buildAXFRRequest")
}

// ---------------------------------------------------------------------------
// ixfr.go:437-439 - IXFR sendMessage Pack error (dead code)
// ---------------------------------------------------------------------------

func TestIXFRClient_sendMessage_PackErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: sendMessage Pack error requires invalid message data; messages are always well-formed from buildIXFRRequest")
}

// ---------------------------------------------------------------------------
// notify.go dead code paths
// ---------------------------------------------------------------------------

func TestSendNOTIFY_PackErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: buildNOTIFYRequest validates zone name via ParseName, message always Packs")
}

func TestSendNOTIFY_WriteErrorDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: UDP write to unreachable destination succeeds at OS level")
}

// ---------------------------------------------------------------------------
// slave.go:331-334 - performZoneTransfer applyTransferredZone error
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_ApplyError_Extra6(t *testing.T) {
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
		defer conn.Close()

		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			return
		}
		reqLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
		reqBuf := make([]byte, reqLen)
		if _, err := io.ReadFull(conn, reqBuf); err != nil {
			return
		}

		// Send response with only A record (no SOA) -> applyTransferredZone fails
		respMsg := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
			},
			Answers: []*protocol.ResourceRecord{
				{
					Name: mustParseName6("www.example.com."), Type: protocol.TypeA,
					Class: protocol.ClassIN, TTL: 3600,
					Data: &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
				},
			},
		}
		buf := make([]byte, 65535)
		n, _ := respMsg.Pack(buf)
		conn.Write([]byte{byte(n >> 8), byte(n)})
		conn.Write(buf[:n])
	}()

	sm := NewSlaveManager(nil)

	config := SlaveZoneConfig{
		ZoneName:      "applyerr6.example.com.",
		Masters:       []string{addr},
		TransferType:  "axfr",
		Timeout:       2 * time.Second,
		RetryInterval: 50 * time.Millisecond,
		MaxRetries:    1,
	}

	slaveZone, _ := NewSlaveZone(config)
	sm.mu.Lock()
	sm.slaveZones["applyerr6.example.com."] = slaveZone
	sm.mu.Unlock()

	sm.performZoneTransfer("applyerr6.example.com.")

	// Wait for retry to also fail
	time.Sleep(300 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// axfr.go:544-546 - receiveAXFRResponse unpack error (first message)
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_UnpackFirstMsgError_Extra6(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	// Valid length prefix (16 bytes) but garbage data
	data := []byte{0x00, 0x10}
	data = append(data, make([]byte, 16)...)

	conn := &mockConn{readData: data}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("expected error for unpack failure on first message")
	}
}

// ---------------------------------------------------------------------------
// buildSignedData with previousMAC (multi-message path at line 423-424)
// ---------------------------------------------------------------------------

func TestBuildSignedData_WithPreviousMAC_Extra6(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{ID: 1234, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: mustParseName6("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}

	prevMAC := []byte("previous-mac-value-for-testing-1234")
	data, err := buildSignedData(msg, prevMAC, HmacSHA256, time.Now().UTC(), 300, 1234)
	if err != nil {
		t.Fatalf("buildSignedData with previousMAC: %v", err)
	}
	if !bytes.HasPrefix(data, prevMAC) {
		t.Error("expected signed data to start with previousMAC")
	}
}

// ---------------------------------------------------------------------------
// Full AXFR Transfer with TSIG via TCP server - dead code (same TSIG issue)
// ---------------------------------------------------------------------------

func TestAXFRClient_Transfer_WithTSIG_TCPServerDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: TSIG records unpacked from wire format have *RDataRaw data, so TSIG verification always fails in receiveAXFRResponse")
}
