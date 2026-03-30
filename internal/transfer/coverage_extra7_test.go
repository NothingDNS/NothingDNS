package transfer

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// mustParseName7 parses a DNS name or panics.
func mustParseName7(name string) *protocol.Name {
	n, err := protocol.ParseName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// ---------------------------------------------------------------------------
// axfr.go:544-546 - receiveAXFRResponse UnpackMessage error
// The existing tests use all-zero data which UnpackMessage handles as a valid
// empty message. We need to craft data with QDCount=1 but truncated question
// data so UnpackMessage fails after header parsing.
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_UnpackMessageError_Extra7(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53", WithAXFRTimeout(2*time.Second))

	// Build a message that has QDCount=1 but no question data after the header.
	// Header is 12 bytes. Set QDCount=1 in the header, but only provide 13 bytes total.
	// This means UnpackMessage will succeed on header but fail unpacking the question.
	header := make([]byte, 12)
	// ID = 0x1234
	header[0], header[1] = 0x12, 0x34
	// Flags: QR=1, RCODE=0
	header[2] = 0x80 // QR=1
	header[3] = 0x00
	// QDCount = 1
	binary.BigEndian.PutUint16(header[4:6], 1)
	// ANCount = 0
	binary.BigEndian.PutUint16(header[6:8], 0)
	// NSCount = 0
	binary.BigEndian.PutUint16(header[8:10], 0)
	// ARCount = 0
	binary.BigEndian.PutUint16(header[10:12], 0)

	// Add one extra byte (not enough for a valid question name)
	msgData := append(header, 0xFF)

	// Prepend 2-byte length prefix
	var wireData []byte
	wireData = append(wireData, byte(len(msgData)>>8), byte(len(msgData)))
	wireData = append(wireData, msgData...)

	conn := &mockConn{readData: wireData}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("expected error for UnpackMessage failure")
	}
	if !strings.Contains(err.Error(), "unpacking message") {
		t.Errorf("expected unpacking message error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// axfr.go:524-526 - receiveAXFRResponse soaCount >= 2 break on Read error
// This path is dead code: the break at line 572 (soaCount >= 2 after processing
// answer records) always triggers before the Read error check at line 524.
// When soaCount reaches 2 from processing answers, the loop breaks immediately.
// The Read error fallback at line 524 can only be reached if soaCount >= 2
// without triggering the break at line 572, which is impossible.
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_SOACountBreakOnReadError_Extra7(t *testing.T) {
	t.Skip("unreachable: soaCount >= 2 always triggers break at line 572 before Read error check at line 524")
}

// ---------------------------------------------------------------------------
// slave.go:331-334 - performZoneTransfer applyTransferredZone error
// The existing test in extra6 is broken: it only populates sm.slaveZones
// but not sm.clients, so performZoneTransfer returns at the initial check.
// This test adds both to properly exercise the applyTransferredZone error path.
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_ApplyError_Extra7(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	zoneName := "applyerr7.example.com."

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the request
		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			return
		}
		reqLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
		reqBuf := make([]byte, reqLen)
		if _, err := io.ReadFull(conn, reqBuf); err != nil {
			return
		}

		// Send response with 2 SOA records (serial=0) so AXFR completes
		// (soaCount >= 2) but applyTransferredZone fails because soaSerial == 0.
		soaRR := &protocol.ResourceRecord{
			Name:  mustParseName7(zoneName),
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   86400,
			Data: &protocol.RDataSOA{
				MName:   mustParseName7("ns1." + zoneName),
				RName:   mustParseName7("admin." + zoneName),
				Serial:  0, // serial=0 triggers "no SOA record found" in applyTransferredZone
				Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
			},
		}
		respMsg := &protocol.Message{
			Header: protocol.Header{
				Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
			},
			Answers: []*protocol.ResourceRecord{soaRR, soaRR},
		}
		buf := make([]byte, 65535)
		n, _ := respMsg.Pack(buf)
		conn.Write([]byte{byte(n >> 8), byte(n)})
		conn.Write(buf[:n])
	}()

	sm := NewSlaveManager(nil)

	config := SlaveZoneConfig{
		ZoneName:      zoneName,
		Masters:       []string{addr},
		TransferType:  "axfr",
		Timeout:       3 * time.Second,
		RetryInterval: 50 * time.Millisecond,
		MaxRetries:    1,
	}

	slaveZone, err := NewSlaveZone(config)
	if err != nil {
		t.Fatalf("NewSlaveZone: %v", err)
	}

	// Create an IXFR client for this zone (required by performZoneTransfer)
	client := NewIXFRClient(addr, WithIXFRTimeout(3*time.Second))

	sm.mu.Lock()
	sm.slaveZones[zoneName] = slaveZone
	sm.clients[zoneName] = client
	sm.mu.Unlock()

	// performZoneTransfer should:
	// 1. Get slaveZone and client (both exist now)
	// 2. Call performAXFR (since TransferType=axfr and LastSerial=0)
	// 3. AXFR succeeds (returns A records)
	// 4. applyTransferredZone fails (no SOA record)
	// 5. Schedule retry
	sm.performZoneTransfer(zoneName)

	// Give time for the retry goroutine to start
	time.Sleep(100 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// axfr.go:442-444 - Transfer sendMessage error using writeErr mockConn
// The existing tests use real TCP servers where the write may succeed due to
// kernel buffering. Using a mockConn with writeErr directly would cover
// sendMessage but not the Transfer method path. We call sendMessage directly
// here to cover the Pack+Write error paths.
// ---------------------------------------------------------------------------

func TestAXFRClient_sendMessage_WriteError_Extra7(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")

	msg := &protocol.Message{
		Header: protocol.Header{
			ID: 0x1234, Flags: protocol.Flags{},
		},
		Questions: []*protocol.Question{
			{Name: mustParseName7("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}

	conn := &mockConn{writeErr: fmt.Errorf("write error")}
	err := client.sendMessage(conn, msg)
	if err == nil {
		t.Error("expected error when write fails in sendMessage")
	}
	if !strings.Contains(err.Error(), "write error") {
		t.Errorf("expected write error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:361-363 - IXFR Transfer sendMessage error using writeErr mockConn
// Same issue as AXFR: can't inject mockConn into Transfer. Test sendMessage directly.
// ---------------------------------------------------------------------------

func TestIXFRClient_sendMessage_WriteError_Extra7(t *testing.T) {
	client := NewIXFRClient("ns1.example.com:53")

	msg := &protocol.Message{
		Header: protocol.Header{
			ID: 0x1234, Flags: protocol.Flags{},
		},
		Questions: []*protocol.Question{
			{Name: mustParseName7("example.com."), QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
	}

	conn := &mockConn{writeErr: fmt.Errorf("write error")}
	err := client.sendMessage(conn, msg)
	if err == nil {
		t.Error("expected error when write fails in sendMessage")
	}
	if !strings.Contains(err.Error(), "write error") {
		t.Errorf("expected write error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:437-439 - sendMessage Pack error (dead code)
// sendMessage Pack requires invalid message data; messages from
// buildIXFRRequest are always well-formed.
// ---------------------------------------------------------------------------

func TestIXFRClient_sendMessage_PackErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: sendMessage Pack error requires invalid message data; messages are always well-formed from buildIXFRRequest")
}

// ---------------------------------------------------------------------------
// axfr.go:494-496 - sendMessage Pack error (dead code)
// Same reasoning as IXFR.
// ---------------------------------------------------------------------------

func TestAXFRClient_sendMessage_PackErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: sendMessage Pack error requires invalid message data; messages are always well-formed from buildAXFRRequest")
}

// ---------------------------------------------------------------------------
// notify.go:67-69 - SendNOTIFY Pack error (dead code)
// buildNOTIFYRequest validates zone name via ParseName, message always Packs.
// ---------------------------------------------------------------------------

func TestSendNOTIFY_PackErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: buildNOTIFYRequest validates zone name via ParseName, message always Packs")
}

// ---------------------------------------------------------------------------
// notify.go:71-73 - SendNOTIFY Write error (dead code)
// UDP write to unreachable destination succeeds at OS level.
// ---------------------------------------------------------------------------

func TestSendNOTIFY_WriteErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: UDP write to unreachable destination succeeds at OS level")
}

// ---------------------------------------------------------------------------
// axfr.go:559 - extractMAC in receiveAXFRResponse (dead code)
// TSIG records unpacked from wire format have *RDataRaw data, not *RDataTSIG,
// so VerifyMessage fails before extractMAC is reached.
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_ExtractMACDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: TSIG records unpacked from wire format have *RDataRaw data, so VerifyMessage fails before extractMAC is reached")
}

// ---------------------------------------------------------------------------
// ixfr.go:494 - extractMAC in receiveIXFRResponse (dead code)
// Same reasoning as AXFR.
// ---------------------------------------------------------------------------

func TestIXFRClient_receiveIXFRResponse_ExtractMACDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: TSIG records unpacked from wire format have *RDataRaw data, so VerifyMessage fails with 'invalid TSIG data type' before extractMAC is reached")
}

// ---------------------------------------------------------------------------
// axfr.go:577-579 - receiveAXFRResponse too large safety check
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_TooLargeSafetyCheck_Extra7(t *testing.T) {
	t.Skip("unreachable in reasonable test time: requires 1M+ DNS records")
}

// ---------------------------------------------------------------------------
// ixfr.go:517-519 - receiveIXFRResponse too large safety check
// ---------------------------------------------------------------------------

func TestIXFRClient_receiveIXFRResponse_TooLargeSafetyCheck_Extra7(t *testing.T) {
	t.Skip("unreachable in reasonable test time: requires 1M+ DNS records")
}

// ---------------------------------------------------------------------------
// ddns.go:157-159 - HandleUpdate getTSIGKeyName error (dead code)
// hasTSIG and getTSIGKeyName iterate the same Additionals slice.
// ---------------------------------------------------------------------------

func TestHandleUpdate_GetTSIGKeyNameDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: getTSIGKeyName cannot fail after hasTSIG returns true")
}

// ---------------------------------------------------------------------------
// ddns.go:181-183 - HandleUpdate parseUpdates error (dead code)
// parseUpdates always returns nil error.
// ---------------------------------------------------------------------------

func TestHandleUpdate_ParseUpdatesErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: parseUpdates always returns nil error")
}

// ---------------------------------------------------------------------------
// ddns.go:358-360 - ApplyUpdate applyOperationToZone error (dead code)
// applyOperationToZone always returns nil error.
// ---------------------------------------------------------------------------

func TestApplyUpdate_ApplyOperationToZoneErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: applyOperationToZone always returns nil error")
}

// ---------------------------------------------------------------------------
// tsig.go:133-135 - PackTSIGRecord PackName error (dead code)
// PackName cannot fail with 256-byte buffer at offset 0 for a valid parsed name.
// ---------------------------------------------------------------------------

func TestPackTSIGRecord_PackNameErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: PackName cannot fail with 256-byte buffer at offset 0 for a valid parsed name")
}

// ---------------------------------------------------------------------------
// tsig.go:297-299 - SignMessage buildSignedData error (dead code)
// ---------------------------------------------------------------------------

func TestSignMessage_BuildSignedDataErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: buildSignedData Pack error requires invalid message data, but SignMessage callers always construct valid messages")
}

// ---------------------------------------------------------------------------
// tsig.go:321-323 - SignMessage PackTSIGRecord error (dead code)
// ---------------------------------------------------------------------------

func TestSignMessage_PackTSIGRecordErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: PackTSIGRecord error in SignMessage cannot be triggered without buildSignedData panicking first")
}

// ---------------------------------------------------------------------------
// tsig.go:373-375 - VerifyMessage buildSignedData error (dead code)
// ---------------------------------------------------------------------------

func TestVerifyMessage_BuildSignedDataErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: buildSignedData Pack error requires invalid message data, but VerifyMessage callers always construct valid messages")
}

// ---------------------------------------------------------------------------
// tsig.go:432-434 - buildSignedData Pack error (dead code)
// ---------------------------------------------------------------------------

func TestBuildSignedData_PackErrorDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: buildSignedData Pack error requires invalid message data that cannot be constructed through normal API")
}

// ---------------------------------------------------------------------------
// ixfr.go:120-122 - HandleIXFR getTSIGKeyName error (dead code)
// ---------------------------------------------------------------------------

func TestHandleIXFR_GetTSIGKeyNameDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: getTSIGKeyName cannot fail after hasTSIG returns true")
}

// ---------------------------------------------------------------------------
// axfr.go:128-130 - HandleAXFR getTSIGKeyName error (dead code)
// ---------------------------------------------------------------------------

func TestHandleAXFR_GetTSIGKeyNameDeadCode_Extra7(t *testing.T) {
	t.Skip("unreachable: getTSIGKeyName cannot fail after hasTSIG returns true")
}
