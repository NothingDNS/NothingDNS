package transfer

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// mustParseName4 is a test helper that parses a DNS name or panics.
func mustParseName4(name string) *protocol.Name {
	n, err := protocol.ParseName(name)
	if err != nil {
		panic(err)
	}
	return n
}

// ---------------------------------------------------------------------------
// slave.go:162 - AddSlaveZone with zone name needing dot normalization
// Tests the path where the zone name gets a trailing dot appended.
// ---------------------------------------------------------------------------

func TestSlaveManager_AddSlaveZone_DotNormalization_CoverageExtra4(t *testing.T) {
	sm := NewSlaveManager(nil)
	// Zone name without trailing dot - should be normalized internally
	err := sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName: "dotnorm.example.com",
		Masters:  []string{"192.168.1.1:53"},
	})
	if err != nil {
		t.Fatalf("AddSlaveZone: %v", err)
	}
	if sz := sm.GetSlaveZone("dotnorm.example.com."); sz == nil {
		t.Error("expected zone to be stored with trailing dot")
	}
}

// ---------------------------------------------------------------------------
// slave.go:171 - AddSlaveZone with NewSlaveZone error (bad config)
// Tests the error path when NewSlaveZone fails inside AddSlaveZone.
// ---------------------------------------------------------------------------

func TestSlaveManager_AddSlaveZone_NewSlaveZoneError_CoverageExtra4(t *testing.T) {
	sm := NewSlaveManager(nil)
	err := sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "badzone.example.com.",
		Masters:      []string{"192.168.1.1:53"},
		TransferType: "invalid",
	})
	if err == nil {
		t.Error("expected error for invalid transfer type in AddSlaveZone")
	}
}

// ---------------------------------------------------------------------------
// slave.go:204 - RemoveSlaveZone with name needing dot normalization
// Tests that RemoveSlaveZone normalizes the zone name by adding trailing dot.
// ---------------------------------------------------------------------------

func TestSlaveManager_RemoveSlaveZone_DotNormalization_CoverageExtra4(t *testing.T) {
	sm := NewSlaveManager(nil)
	err := sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName: "rmdot.example.com.",
		Masters:  []string{"192.168.1.1:53"},
	})
	if err != nil {
		t.Fatalf("AddSlaveZone: %v", err)
	}
	if sm.GetSlaveZone("rmdot.example.com.") == nil {
		t.Fatal("zone should exist before removal")
	}

	// Remove without trailing dot - should still find and remove
	sm.RemoveSlaveZone("rmdot.example.com")
	if sm.GetSlaveZone("rmdot.example.com.") != nil {
		t.Error("zone should have been removed after normalization")
	}
}

// ---------------------------------------------------------------------------
// slave.go:266 - notifyListener with nil notifyReq
// Tests the nil check path in notifyListener.
// ---------------------------------------------------------------------------

func TestSlaveManager_notifyListener_NilNotify_CoverageExtra4(t *testing.T) {
	sm := NewSlaveManager(nil)

	// Start the listener
	sm.wg.Add(1)
	go sm.notifyListener()

	// Send a nil request - should be handled gracefully
	sm.notifyChan <- nil

	// Give it time to process
	time.Sleep(50 * time.Millisecond)
	sm.Stop()
}

// ---------------------------------------------------------------------------
// slave.go:331 - applyTransferredZone error (empty records)
// Tests the path where zone transfer records are applied but fail.
// ---------------------------------------------------------------------------

func TestSlaveManager_applyTransferredZone_EmptyRecords_CoverageExtra4(t *testing.T) {
	sm := NewSlaveManager(nil)
	sz, err := NewSlaveZone(SlaveZoneConfig{
		ZoneName: "empty.example.com.",
		Masters:  []string{"192.0.2.1:53"},
	})
	if err != nil {
		t.Fatalf("NewSlaveZone: %v", err)
	}
	sm.mu.Lock()
	sm.slaveZones["empty.example.com."] = sz
	sm.mu.Unlock()

	err = sm.applyTransferredZone(sz, []*protocol.ResourceRecord{})
	if err == nil {
		t.Error("expected error for empty records in applyTransferredZone")
	}
}

// ---------------------------------------------------------------------------
// slave.go:331 - applyTransferredZone error (no SOA record)
// Tests the path where transferred records have no SOA.
// ---------------------------------------------------------------------------

func TestSlaveManager_applyTransferredZone_NoSOARecord_CoverageExtra4(t *testing.T) {
	sm := NewSlaveManager(nil)
	sz, err := NewSlaveZone(SlaveZoneConfig{
		ZoneName: "nosoa.example.com.",
		Masters:  []string{"192.0.2.1:53"},
	})
	if err != nil {
		t.Fatalf("NewSlaveZone: %v", err)
	}
	sm.mu.Lock()
	sm.slaveZones["nosoa.example.com."] = sz
	sm.mu.Unlock()

	// Records without SOA
	records := []*protocol.ResourceRecord{
		{
			Name:  mustParseName4("www.nosoa.example.com."),
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data:  &protocol.RDataA{Address: [4]byte{1, 2, 3, 4}},
		},
	}

	err = sm.applyTransferredZone(sz, records)
	if err == nil {
		t.Error("expected error for no SOA record in applyTransferredZone")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:159 - generateAXFRRecords with invalid zone origin (ParseName error)
// Tests the error path where the zone origin can't be parsed.
// ---------------------------------------------------------------------------

func TestAXFRServer_generateAXFRRecords_InvalidOrigin_CoverageExtra4(t *testing.T) {
	longLabel := strings.Repeat("a", 70)
	z := zone.NewZone(longLabel + ".com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 42, TTL: 3600,
	}
	s := NewAXFRServer(map[string]*zone.Zone{longLabel + ".com.": z})
	_, err := s.generateAXFRRecords(z)
	if err == nil {
		t.Error("expected error for invalid zone origin in generateAXFRRecords")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:165 - generateAXFRRecords with createSOARR error (invalid MName)
// Tests the error path where creating the SOA RR fails.
// ---------------------------------------------------------------------------

func TestAXFRServer_generateAXFRRecords_InvalidSOAMName_CoverageExtra4(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: strings.Repeat("a", 70) + ".example.com.", // Invalid label
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
// axfr.go:229 - zoneRecordToRR with invalid record name (ParseName error)
// Tests the error path where the record name can't be parsed.
// ---------------------------------------------------------------------------

func TestAXFRServer_zoneRecordToRR_InvalidRecordName_CoverageExtra4(t *testing.T) {
	s := NewAXFRServer(make(map[string]*zone.Zone))
	longLabel := strings.Repeat("a", 70)
	_, err := s.zoneRecordToRR(longLabel+".example.com.", zone.Record{
		Name: longLabel + ".example.com.", Type: "A", TTL: 3600, RData: "1.2.3.4",
	}, "example.com.")
	if err == nil {
		t.Error("expected error for invalid record name in zoneRecordToRR")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:494 - sendMessage with Pack error (nil question Name)
// Tests the error path where msg.Pack fails.
// ---------------------------------------------------------------------------

func TestAXFRClient_sendMessage_PackError_CoverageExtra4(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	// Message with QDCount=1 but no questions will cause Pack to fail
	msg := &protocol.Message{
		Header: protocol.Header{ID: 0x1234, QDCount: 1},
	}
	// Use a closed connection - Pack error should happen before write
	clientConn, serverConn := net.Pipe()
	clientConn.Close()
	serverConn.Close()

	err := client.sendMessage(clientConn, msg)
	if err == nil {
		t.Error("expected error for Pack failure in sendMessage")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:544 - receiveAXFRResponse with unpack error
// Tests the error path where UnpackMessage fails on response data.
// ---------------------------------------------------------------------------

func TestAXFRClient_receiveAXFRResponse_UnpackError_CoverageExtra4(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	// Valid length prefix but garbage data that can't be unpacked
	data := []byte{0x00, 0x10}
	data = append(data, make([]byte, 16)...)
	conn := &mockConn{readData: data}
	_, err := client.receiveAXFRResponse(conn, nil)
	if err == nil {
		t.Error("expected error for unpack failure in receiveAXFRResponse")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:200 - generateIncrementalIXFR with client serial not found
// Tests the startIdx == -1 path.
// ---------------------------------------------------------------------------

func TestIXFRServer_generateIncrementalIXFR_SerialNotInRange_CoverageExtra4(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 100, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	// Client serial is higher than all journal entries
	server.RecordChange("example.com.", 50, 60,
		[]zone.RecordChange{{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "1.2.3.4"}},
		[]zone.RecordChange{},
	)

	_, err := server.generateIncrementalIXFR(z, 200)
	if err == nil {
		t.Error("expected error for client serial not in journal range")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:206 - generateIncrementalIXFR with journal gap (serial mismatch)
// Tests startIdx > 0 with serial mismatch.
// ---------------------------------------------------------------------------

func TestIXFRServer_generateIncrementalIXFR_JournalGap_CoverageExtra4(t *testing.T) {
	axfrServer := NewAXFRServer(make(map[string]*zone.Zone))
	server := NewIXFRServer(axfrServer)

	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 100, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	// Create journal entries with a gap
	server.RecordChange("example.com.", 50, 60,
		[]zone.RecordChange{{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "1.2.3.4"}},
		[]zone.RecordChange{},
	)
	server.RecordChange("example.com.", 80, 90,
		[]zone.RecordChange{{Name: "mail.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "5.6.7.8"}},
		[]zone.RecordChange{},
	)

	// Client serial 65 falls between journal entries
	_, err := server.generateIncrementalIXFR(z, 65)
	if err == nil {
		t.Error("expected error for journal gap (serial not covered)")
	}
}

// ---------------------------------------------------------------------------
// slave.go:368 - performAXFR success return path
// Tests the success path by setting up a real TCP server that serves AXFR.
// ---------------------------------------------------------------------------

func TestSlaveManager_performAXFR_Success_CoverageExtra4(t *testing.T) {
	// This test can be flaky under load due to TCP timing; skip in short mode
	if testing.Short() {
		t.Skip("skipping flaky integration test in short mode")
	}
	// Set up a real AXFR server with a zone
	z := zone.NewZone("axfrsuccess.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 2024010101, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400, TTL: 86400,
	}
	axfrServer := NewAXFRServer(map[string]*zone.Zone{"axfrsuccess.example.com.": z})

	// Start a TCP listener for the AXFR server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	// Signal when server has accepted connection and is ready to respond
	var serverReady sync.Once
	var serverErr error

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("server accept error: %v", err)
			return
		}
		defer conn.Close()

		// Signal that we have a connection
		serverReady.Do(func() {})

		// Read the request using io.ReadFull for reliable TCP reads
		lengthBuf := make([]byte, 2)
		if _, err := io.ReadFull(conn, lengthBuf); err != nil {
			t.Logf("server read length error: %v", err)
			return
		}
		reqLen := int(lengthBuf[0])<<8 | int(lengthBuf[1])
		reqBuf := make([]byte, reqLen)
		if _, err := io.ReadFull(conn, reqBuf); err != nil {
			t.Logf("server read body error: %v", err)
			return
		}

		// Generate AXFR response records
		records, err := axfrServer.generateAXFRRecords(z)
		if err != nil {
			t.Logf("server generateAXFRRecords error: %v", err)
			return
		}

		// Build and send response
		resp := &protocol.Message{
			Header: protocol.Header{
				ID: 0x1234, Flags: protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
			},
			Answers: records,
		}

		buf := make([]byte, 65535)
		n, err := resp.Pack(buf)
		if err != nil {
			t.Logf("server pack error: %v", err)
			return
		}
		// Single atomic write: length prefix + message body
		sendBuf := make([]byte, 2+n)
		sendBuf[0] = byte(n >> 8)
		sendBuf[1] = byte(n)
		copy(sendBuf[2:], buf[:n])
		if _, err := conn.Write(sendBuf); err != nil {
			t.Logf("server write error: %v", err)
			return
		}
		t.Logf("server sent %d records, %d bytes", len(records), n)
	}()

	// Give the server goroutine a moment to start and accept
	time.Sleep(10 * time.Millisecond)

	// Create SlaveManager with the test server
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "axfrsuccess.example.com.",
		Masters:      []string{listener.Addr().String()},
		Timeout:      5 * time.Second,
		TransferType: "axfr",
	})

	sz := sm.GetSlaveZone("axfrsuccess.example.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := sm.performAXFR(ctx, sz)
	if err != nil {
		t.Fatalf("performAXFR: %v", err)
	}
	if len(records) == 0 {
		t.Error("expected non-empty records from performAXFR")
	}
	_ = serverErr
}
