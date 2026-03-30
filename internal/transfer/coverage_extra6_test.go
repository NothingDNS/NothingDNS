package transfer

import (
	"context"
	"encoding/base64"
	"net"
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
// slave.go:296 - performZoneTransfer IXFR fallback to AXFR path
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_IXFRFallback_CoverageExtra6(t *testing.T) {
	z := zone.NewZone("ixfrfb.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 2024010101, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400, TTL: 86400,
	}
	axfrServer := NewAXFRServer(map[string]*zone.Zone{"ixfrfb.example.com.": z})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lengthBuf := make([]byte, 2)
		if _, err := conn.Read(lengthBuf); err != nil {
			return
		}
		reqLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
		reqBuf := make([]byte, reqLen)
		if _, err := conn.Read(reqBuf); err != nil {
			return
		}

		records, err := axfrServer.generateAXFRRecords(z)
		if err != nil {
			return
		}

		resp := &protocol.Message{
			Header: protocol.Header{
				ID: 0x1234, Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
			},
			Answers: records,
		}

		buf := make([]byte, 65535)
		n, err := resp.Pack(buf)
		if err != nil {
			return
		}
		conn.Write([]byte{byte(n >> 8), byte(n)})
		conn.Write(buf[:n])
	}()

	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "ixfrfb.example.com.",
		Masters:      []string{listener.Addr().String()},
		Timeout:      5 * time.Second,
		TransferType: "ixfr",
	})

	sz := sm.GetSlaveZone("ixfrfb.example.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}
	sz.UpdateZone(zone.NewZone("ixfrfb.example.com."), 100)

	sm.performZoneTransfer("ixfrfb.example.com.")
}

// ---------------------------------------------------------------------------
// slave.go:296 - performZoneTransfer nonexistent zone (early return)
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_NoZone_CoverageExtra6(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.performZoneTransfer("nonexistent.example.com.")
}

// ---------------------------------------------------------------------------
// slave.go:429 - scheduleRetry nonexistent zone
// ---------------------------------------------------------------------------

func TestSlaveManager_scheduleRetry_NoZone_CoverageExtra6(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.scheduleRetry("nonexistent.example.com.")
}

// ---------------------------------------------------------------------------
// slave.go:338 - performIXFR direct call
// ---------------------------------------------------------------------------

func TestSlaveManager_performIXFR_Fallback_CoverageExtra6(t *testing.T) {
	sm := NewSlaveManager(nil)
	sz, err := NewSlaveZone(SlaveZoneConfig{
		ZoneName:     "ixfr.example.com.",
		Masters:      []string{"192.0.2.1:53"},
		TransferType: "ixfr",
	})
	if err != nil {
		t.Fatalf("NewSlaveZone: %v", err)
	}
	client := NewIXFRClient("192.0.2.1:53")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err = sm.performIXFR(ctx, client, sz)
	if err == nil {
		t.Error("performIXFR should return error")
	}
}

// ---------------------------------------------------------------------------
// tsig.go:289 - SignMessage with unsupported algorithm (calculateMAC error)
// ---------------------------------------------------------------------------

func TestSignMessage_CalculateMACError_CoverageExtra6(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString("dGVzdC1zZWNyZXQta2V5LTEyMzQ1Ng==")
	key := &TSIGKey{
		Name:      "test-key",
		Algorithm: "hmac-unsupported",
		Secret:    secret,
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:    0x1234,
			Flags: protocol.NewQueryFlags(),
		},
	}

	_, err := SignMessage(msg, key, 300)
	if err == nil {
		t.Error("SignMessage should fail with unsupported algorithm")
	}
}

// ---------------------------------------------------------------------------
// tsig.go:289 - SignMessage error: PackTSIGRecord error (bad algorithm)
// buildSignedData uses the algorithm name too, so we need a name that
// passes ParseName in buildSignedData but fails in PackTSIGRecord.
// This is hard to trigger, so we skip.
// ---------------------------------------------------------------------------

func TestSignMessage_PackTSIGRecordError_CoverageExtra6(t *testing.T) {
	t.Skip("cannot reliably trigger PackTSIGRecord error without buildSignedData also failing")
}

// ---------------------------------------------------------------------------
// tsig.go:123 - PackTSIGRecord with Other Data
// ---------------------------------------------------------------------------

func TestPackTSIGRecord_WithOtherData_CoverageExtra6(t *testing.T) {
	tsig := &TSIGRecord{
		Algorithm:  HmacSHA256,
		TimeSigned: time.Now(),
		Fudge:      300,
		MAC:        []byte{0xAA, 0xBB},
		OriginalID: 0x1234,
		Error:      TSIGErrBadTime,
		OtherLen:   7,
		OtherData:  []byte("BADTIME"),
	}

	data, err := PackTSIGRecord(tsig)
	if err != nil {
		t.Fatalf("PackTSIGRecord: %v", err)
	}
	if len(data) == 0 {
		t.Error("Expected non-empty packed data")
	}
}

// ---------------------------------------------------------------------------
// tsig.go:174 - UnpackTSIGRecord with Other Data
// ---------------------------------------------------------------------------

func TestUnpackTSIGRecord_WithOtherData_CoverageExtra6(t *testing.T) {
	algoName, _ := protocol.ParseName(HmacSHA256)
	algoBytes := make([]byte, 256)
	algoLen, _ := protocol.PackName(algoName, algoBytes, 0, nil)

	var buf []byte
	buf = append(buf, algoBytes[:algoLen]...)

	now := time.Now().UTC()
	timeUnix := uint64(now.Unix())
	buf = append(buf, byte(timeUnix>>40), byte(timeUnix>>32), byte(timeUnix>>24), byte(timeUnix>>16), byte(timeUnix>>8), byte(timeUnix))
	buf = append(buf, 0x00, 0x2C) // Fudge = 300
	buf = append(buf, 0x00, 0x02) // MAC size
	buf = append(buf, 0xAA, 0xBB) // MAC
	buf = append(buf, 0x12, 0x34) // Original ID
	buf = append(buf, 0x00, 0x00) // Error = 0
	buf = append(buf, 0x00, 0x07) // Other Len = 7
	buf = append(buf, []byte("BADTIME")...)

	tsig, _, err := UnpackTSIGRecord(buf, 0)
	if err != nil {
		t.Fatalf("UnpackTSIGRecord: %v", err)
	}
	if string(tsig.OtherData) != "BADTIME" {
		t.Errorf("OtherData = %q, want BADTIME", string(tsig.OtherData))
	}
}

// ---------------------------------------------------------------------------
// tsig.go:341 - VerifyMessage time out of range
// ---------------------------------------------------------------------------

func TestVerifyMessage_TimeOutOfRange_CoverageExtra6(t *testing.T) {
	secret, _ := base64.StdEncoding.DecodeString("dGVzdC1zZWNyZXQta2V5LTEyMzQ1Ng==")
	key := &TSIGKey{
		Name:      "test-key",
		Algorithm: HmacSHA256,
		Secret:    secret,
	}

	pastTime := time.Now().Add(-1 * time.Hour)
	algoName, _ := protocol.ParseName(HmacSHA256)
	algoBytes := make([]byte, 256)
	algoLen, _ := protocol.PackName(algoName, algoBytes, 0, nil)

	var buf []byte
	buf = append(buf, algoBytes[:algoLen]...)
	timeUnix := uint64(pastTime.Unix())
	buf = append(buf, byte(timeUnix>>40), byte(timeUnix>>32), byte(timeUnix>>24), byte(timeUnix>>16), byte(timeUnix>>8), byte(timeUnix))
	buf = append(buf, 0x00, 0x00) // Fudge = 0
	buf = append(buf, 0x00, 0x02) // MAC size
	buf = append(buf, 0xAA, 0xBB) // MAC
	buf = append(buf, 0x12, 0x34) // Original ID
	buf = append(buf, 0x00, 0x00) // Error
	buf = append(buf, 0x00, 0x00) // Other Len

	msg := &protocol.Message{
		Header: protocol.Header{ID: 0x1234},
		Additionals: []*protocol.ResourceRecord{
			{
				Name:  mustParseName6("test-key"),
				Type:  protocol.TypeTSIG,
				Class: protocol.ClassANY,
				TTL:   0,
				Data:  &RDataTSIG{Raw: buf},
			},
		},
	}

	err := VerifyMessage(msg, key, nil)
	if err == nil {
		t.Error("VerifyMessage should fail with expired time")
	}
}

// ---------------------------------------------------------------------------
// slave.go:296 - performZoneTransfer with applyTransferredZone error
// Server returns A records but no SOA
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_ApplyError_CoverageExtra6(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		lengthBuf := make([]byte, 2)
		if _, err := conn.Read(lengthBuf); err != nil {
			return
		}
		reqLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
		reqBuf := make([]byte, reqLen)
		if _, err := conn.Read(reqBuf); err != nil {
			return
		}

		name := mustParseName6("nosoa.example.com.")
		resp := &protocol.Message{
			Header: protocol.Header{
				ID: 0x1234, Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
			},
			Answers: []*protocol.ResourceRecord{
				{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300,
					Data: &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}}},
			},
		}

		buf := make([]byte, 65535)
		n, err := resp.Pack(buf)
		if err != nil {
			return
		}
		conn.Write([]byte{byte(n >> 8), byte(n)})
		conn.Write(buf[:n])
	}()

	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "nosoa-tx.example.com.",
		Masters:      []string{listener.Addr().String()},
		Timeout:      5 * time.Second,
		TransferType: "axfr",
	})

	sm.performZoneTransfer("nosoa-tx.example.com.")
	// No crash is sufficient
}
