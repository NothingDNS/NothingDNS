package transfer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestSlaveZoneConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  SlaveZoneConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: SlaveZoneConfig{
				ZoneName:     "example.com.",
				Masters:      []string{"192.168.1.1:53"},
				TransferType: "ixfr",
				Timeout:      30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "missing zone name",
			config: SlaveZoneConfig{
				Masters: []string{"192.168.1.1:53"},
			},
			wantErr: true,
		},
		{
			name: "missing masters",
			config: SlaveZoneConfig{
				ZoneName: "example.com.",
			},
			wantErr: true,
		},
		{
			name: "invalid transfer type",
			config: SlaveZoneConfig{
				ZoneName:     "example.com.",
				Masters:      []string{"192.168.1.1:53"},
				TransferType: "invalid",
			},
			wantErr: true,
		},
		{
			name: "invalid master address",
			config: SlaveZoneConfig{
				ZoneName: "example.com.",
				Masters:  []string{"not-a-valid-address"},
			},
			wantErr: true,
		},
		{
			name: "zone name without trailing dot",
			config: SlaveZoneConfig{
				ZoneName: "example.com",
				Masters:  []string{"192.168.1.1:53"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewSlaveZone(t *testing.T) {
	config := SlaveZoneConfig{
		ZoneName:     "example.com.",
		Masters:      []string{"192.168.1.1:53"},
		TransferType: "ixfr",
		Timeout:      30 * time.Second,
	}

	slaveZone, err := NewSlaveZone(config)
	if err != nil {
		t.Fatalf("NewSlaveZone() error = %v", err)
	}

	if slaveZone == nil {
		t.Fatal("NewSlaveZone() returned nil")
	}

	if slaveZone.Config.ZoneName != "example.com." {
		t.Errorf("Expected zone name example.com., got %s", slaveZone.Config.ZoneName)
	}

	if slaveZone.Zone == nil {
		t.Error("Zone not initialized")
	}

	if slaveZone.GetLastSerial() != 0 {
		t.Errorf("Expected initial serial 0, got %d", slaveZone.GetLastSerial())
	}
}

func TestSlaveZone_UpdateAndGet(t *testing.T) {
	config := SlaveZoneConfig{
		ZoneName: "example.com.",
		Masters:  []string{"192.168.1.1:53"},
	}

	slaveZone, _ := NewSlaveZone(config)

	// Create a new zone to update
	newZone := zone.NewZone("example.com.")
	newZone.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", TTL: 3600, RData: "192.0.2.1"},
	}

	// Update the zone
	slaveZone.UpdateZone(newZone, 2024010101)

	// Check the update
	if slaveZone.GetLastSerial() != 2024010101 {
		t.Errorf("Expected serial 2024010101, got %d", slaveZone.GetLastSerial())
	}

	// Get the zone and verify
	gotZone := slaveZone.GetZone()
	if gotZone == nil {
		t.Fatal("GetZone() returned nil")
	}

	records := gotZone.Records["www.example.com."]
	if len(records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(records))
	}
}

func TestNewSlaveManager(t *testing.T) {
	ks := NewKeyStore()
	sm := NewSlaveManager(ks)

	if sm == nil {
		t.Fatal("NewSlaveManager() returned nil")
	}

	if sm.slaveZones == nil {
		t.Error("slaveZones map not initialized")
	}

	if sm.clients == nil {
		t.Error("clients map not initialized")
	}

	if sm.notifyChan == nil {
		t.Error("notifyChan not initialized")
	}

	if sm.stopChan == nil {
		t.Error("stopChan not initialized")
	}
}

func TestSlaveManager_AddSlaveZone(t *testing.T) {
	ks := NewKeyStore()
	sm := NewSlaveManager(ks)

	config := SlaveZoneConfig{
		ZoneName:     "example.com.",
		Masters:      []string{"192.168.1.1:53"},
		TransferType: "ixfr",
		Timeout:      30 * time.Second,
	}

	err := sm.AddSlaveZone(config)
	if err != nil {
		t.Fatalf("AddSlaveZone() error = %v", err)
	}

	// Check the zone was added
	slaveZone := sm.GetSlaveZone("example.com.")
	if slaveZone == nil {
		t.Error("GetSlaveZone() returned nil after AddSlaveZone")
	}

	// Check all zones
	allZones := sm.GetAllSlaveZones()
	if len(allZones) != 1 {
		t.Errorf("Expected 1 slave zone, got %d", len(allZones))
	}
}

func TestSlaveManager_AddSlaveZone_Duplicate(t *testing.T) {
	ks := NewKeyStore()
	sm := NewSlaveManager(ks)

	config := SlaveZoneConfig{
		ZoneName: "example.com.",
		Masters:  []string{"192.168.1.1:53"},
	}

	// Add first time
	err := sm.AddSlaveZone(config)
	if err != nil {
		t.Fatalf("First AddSlaveZone() error = %v", err)
	}

	// Add duplicate
	err = sm.AddSlaveZone(config)
	if err == nil {
		t.Error("Expected error for duplicate zone, got nil")
	}
}

func TestSlaveManager_RemoveSlaveZone(t *testing.T) {
	ks := NewKeyStore()
	sm := NewSlaveManager(ks)

	config := SlaveZoneConfig{
		ZoneName: "example.com.",
		Masters:  []string{"192.168.1.1:53"},
	}

	sm.AddSlaveZone(config)

	// Verify zone exists
	if sm.GetSlaveZone("example.com.") == nil {
		t.Fatal("Zone not added")
	}

	// Remove zone
	sm.RemoveSlaveZone("example.com.")

	// Verify zone removed
	if sm.GetSlaveZone("example.com.") != nil {
		t.Error("Zone still exists after RemoveSlaveZone")
	}
}

func TestSlaveManager_StartStop(t *testing.T) {
	ks := NewKeyStore()
	sm := NewSlaveManager(ks)

	// Start the manager
	sm.Start()

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Stop the manager
	sm.Stop()

	// Verify stopChan is closed by checking we can receive from it
	select {
	case <-sm.stopChan:
		// Expected
	default:
		t.Error("stopChan not closed after Stop()")
	}
}

func TestSlaveManager_GetNotifyChannel(t *testing.T) {
	ks := NewKeyStore()
	sm := NewSlaveManager(ks)

	ch := sm.GetNotifyChannel()
	if ch == nil {
		t.Error("GetNotifyChannel() returned nil")
	}
}

// ---------------------------------------------------------------------------
// handleNotify - non-existent zone
// ---------------------------------------------------------------------------

func TestSlaveManager_handleNotify_NonexistentZone(t *testing.T) {
	sm := NewSlaveManager(nil)
	req := &NOTIFYRequest{
		ZoneName: "nonexistent.com.",
		Serial:  999,
		ClientIP: net.ParseIP("10.0.0.1"),
	}
	sm.handleNotify(req)
	// Should return early, no panic
}

// ---------------------------------------------------------------------------
// handleNotify - serial not newer than current
// ---------------------------------------------------------------------------

func TestSlaveManager_handleNotify_OldSerial(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName: "test.com.",
		Masters:  []string{"192.168.1.1:53"},
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}
	sz.UpdateZone(zone.NewZone("test.com."), 200)

	req := &NOTIFYRequest{
		ZoneName: "test.com.",
		Serial:  100, // Old serial
		ClientIP: net.ParseIP("10.0.0.1"),
	}
	sm.handleNotify(req)
	// Serial should not change
	if sz.GetLastSerial() != 200 {
		t.Errorf("Expected serial to remain 200, got %d", sz.GetLastSerial())
	}
}

// ---------------------------------------------------------------------------
// handleNotify - newer serial triggers zone transfer
// ---------------------------------------------------------------------------

func TestSlaveManager_handleNotify_NewerSerial(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:      "test.com.",
		Masters:       []string{"192.0.2.1:53"},
		Timeout:       1 * time.Second,
		RetryInterval: 10 * time.Millisecond,
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}
	sz.UpdateZone(zone.NewZone("test.com."), 100)

	req := &NOTIFYRequest{
		ZoneName: "test.com.",
		Serial:  200, // Newer serial
		ClientIP: net.ParseIP("10.0.0.1"),
	}
	sm.handleNotify(req)
	// Just verify it doesn't panic. The transfer will fail because the master is unreachable.
	time.Sleep(50 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// performZoneTransfer - non-existent zone
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_NonexistentZone(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.performZoneTransfer("nonexistent.com.")
	// Should return early
}

// ---------------------------------------------------------------------------
// performZoneTransfer - AXFR type (no previous serial)
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_AXFRType(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "test.com.",
		Masters:      []string{"192.0.2.1:53"},
		Timeout:      1 * time.Millisecond,
		TransferType: "axfr",
	})
	sm.performZoneTransfer("test.com.")
	time.Sleep(20 * time.Millisecond)
	// Should not panic; transfer will fail since master is unreachable
}

// ---------------------------------------------------------------------------
// performZoneTransfer - IXFR type with previous serial
// ---------------------------------------------------------------------------

func TestSlaveManager_performZoneTransfer_IXFRType(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "test.com.",
		Masters:      []string{"192.0.2.1:53"},
		Timeout:      1 * time.Millisecond,
		TransferType: "ixfr",
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}
	sz.UpdateZone(zone.NewZone("test.com."), 100) // Set a serial so IXFR is attempted

	sm.performZoneTransfer("test.com.")
	time.Sleep(20 * time.Millisecond)
	// Should not panic; transfer will fail since master is unreachable
}

// ---------------------------------------------------------------------------
// performIXFR - always falls back to AXFR
// ---------------------------------------------------------------------------

func TestSlaveManager_performIXFR_AlwaysFallback(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "test.com.",
		Masters:      []string{"192.0.2.1:53"},
		Timeout:      1 * time.Millisecond,
		TransferType: "ixfr",
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}
	sz.UpdateZone(zone.NewZone("test.com."), 100)

	client := sm.clients["test.com."]
	ctx := context.Background()
	_, err := sm.performIXFR(ctx, client, sz)
	if err == nil {
		t.Error("Expected IXFR to return fallback error")
	}
}

// ---------------------------------------------------------------------------
// performAXFR - unreachable master
// ---------------------------------------------------------------------------

func TestSlaveManager_performAXFR_UnreachableMaster(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "test.com.",
		Masters:      []string{"192.0.2.1:53"},
		Timeout:      1 * time.Millisecond,
		TransferType: "axfr",
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}

	ctx := context.Background()
	_, err := sm.performAXFR(ctx, sz)
	if err == nil {
		t.Error("Expected AXFR to fail with unreachable master")
	}
}

// ---------------------------------------------------------------------------
// performAXFR - with TSIG key configured
// ---------------------------------------------------------------------------

func TestSlaveManager_performAXFR_WithTSIGKey(t *testing.T) {
	ks := NewKeyStore()
	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("a-256-bit-secret-key-for-testing!"),
	}
	ks.AddKey(key)

	sm := NewSlaveManager(ks)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "test.com.",
		Masters:      []string{"192.0.2.1:53"},
		Timeout:      1 * time.Millisecond,
		TSIGKeyName: "test-key.example.com.",
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}

	ctx := context.Background()
	_, err := sm.performAXFR(ctx, sz)
	if err == nil {
		t.Error("Expected AXFR to fail with unreachable master")
	}
}

// ---------------------------------------------------------------------------
// applyTransferredZone - empty records
// ---------------------------------------------------------------------------

func TestSlaveManager_applyTransferredZone_EmptyRecords(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName: "test.com.",
		Masters:  []string{"192.168.1.1:53"},
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}

	err := sm.applyTransferredZone(sz, []*protocol.ResourceRecord{})
	if err == nil {
		t.Error("Expected error for empty records")
	}
}

// ---------------------------------------------------------------------------
// applyTransferredZone - no SOA record
// ---------------------------------------------------------------------------

func TestSlaveManager_applyTransferredZone_NoSOA(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName: "test.com.",
		Masters:  []string{"192.168.1.1:53"},
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}

	// Only A record, no SOA
	records := []*protocol.ResourceRecord{
		{
			Name:  mustParseName("www.test.com."),
			Type:  protocol.TypeA,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
		},
	}

	err := sm.applyTransferredZone(sz, records)
	if err == nil {
		t.Error("Expected error for records without SOA")
	}
}

// ---------------------------------------------------------------------------
// applyTransferredZone - success
// ---------------------------------------------------------------------------

func TestSlaveManager_applyTransferredZone_Success(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName: "test.com.",
		Masters:  []string{"192.168.1.1:53"},
	})
	sz := sm.GetSlaveZone("test.com.")
	if sz == nil {
		t.Fatal("slave zone not found")
	}

	origin, _ := protocol.ParseName("test.com.")
	mname, _ := protocol.ParseName("ns1.test.com.")
	rname, _ := protocol.ParseName("admin.test.com.")

	soaRR := &protocol.ResourceRecord{
		Name:  origin,
		Type:  protocol.TypeSOA,
		Class: protocol.ClassIN,
		TTL:   86400,
		Data: &protocol.RDataSOA{
			MName:   mname,
			RName:   rname,
			Serial:  200,
			Refresh: 3600,
			Retry:   600,
			Expire:  604800,
			Minimum: 86400,
		},
	}
	aRR := &protocol.ResourceRecord{
		Name:  mustParseName("www.test.com."),
		Type:  protocol.TypeA,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  &protocol.RDataA{Address: [4]byte{192, 0, 2, 1}},
	}
	nsRR := &protocol.ResourceRecord{
		Name:  mustParseName("ns1.test.com."),
		Type:  protocol.TypeNS,
		Class: protocol.ClassIN,
		TTL:   3600,
		Data:  &protocol.RDataNS{NSDName: mname},
	}

	err := sm.applyTransferredZone(sz, []*protocol.ResourceRecord{soaRR, aRR, nsRR})
	if err != nil {
		t.Fatalf("applyTransferredZone() error = %v", err)
	}

	if sz.Zone.SOA == nil {
		t.Fatal("Expected SOA to be set")
	}
	if sz.Zone.SOA.Serial != 200 {
		t.Errorf("Expected serial 200, got %d", sz.Zone.SOA.Serial)
	}
	if sz.LastSerial != 200 {
		t.Errorf("Expected lastSerial 200, got %d", sz.LastSerial)
	}
	if len(sz.Zone.Records["www.test.com."]) != 1 {
		t.Errorf("Expected 1 record at www.test.com., got %d", len(sz.Zone.Records["www.test.com."]))
	}
	if len(sz.Zone.Records["ns1.test.com."]) != 1 {
		t.Errorf("Expected 1 record at ns1.test.com., got %d", len(sz.Zone.Records["ns1.test.com."]))
	}
}

// ---------------------------------------------------------------------------
// scheduleRetry - non-existent zone
// ---------------------------------------------------------------------------

func TestSlaveManager_scheduleRetry_NonexistentZone(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.scheduleRetry("nonexistent.com.")
	// Should return early without panic
}

// ---------------------------------------------------------------------------
// scheduleRetry - existing zone (short retry interval)
// ---------------------------------------------------------------------------

func TestSlaveManager_scheduleRetry_ExistingZone(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:      "test.com.",
		Masters:       []string{"192.0.2.1:53"},
		Timeout:       1 * time.Millisecond,
		RetryInterval: 10 * time.Millisecond,
		TransferType:  "axfr",
	})

	// scheduleRetry runs in background and calls performZoneTransfer after retryInterval
	sm.scheduleRetry("test.com.")
	time.Sleep(50 * time.Millisecond) // Should not panic
}

// ---------------------------------------------------------------------------
// notifyListener - stop channel closes
// ---------------------------------------------------------------------------

func TestSlaveManager_notifyListener_StopChannel(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.wg.Add(1)
	close(sm.stopChan)
	sm.notifyListener()
	// Should exit cleanly
}

// ---------------------------------------------------------------------------
// notifyListener - nil message on channel
// ---------------------------------------------------------------------------

func TestSlaveManager_notifyListener_NilMessage(t *testing.T) {
	sm := NewSlaveManager(nil)
	done := make(chan struct{})
	sm.wg.Add(1)
	go func() {
		sm.notifyChan <- nil
		close(sm.stopChan)
		sm.notifyListener()
		close(done)
	}()

	select {
	case <-done:
		// Clean exit
	case <-time.After(2 * time.Second):
		t.Error("notifyListener did not exit cleanly")
	}
}

// ---------------------------------------------------------------------------
// AddSlaveZone - with TSIG key in store
// ---------------------------------------------------------------------------

func TestSlaveManager_AddSlaveZone_WithTSIGKey(t *testing.T) {
	ks := NewKeyStore()
	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("a-256-bit-secret-key-for-testing!"),
	}
	ks.AddKey(key)

	sm := NewSlaveManager(ks)
	err := sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "test.com.",
		Masters:      []string{"192.168.1.1:53"},
		Timeout:      5 * time.Second,
		TSIGKeyName: "test-key.example.com.",
	})
	if err != nil {
		t.Fatalf("AddSlaveZone() error = %v", err)
	}

	client, ok := sm.clients["test.com."]
	if !ok {
		t.Fatal("IXFR client not created")
	}
	_ = client
}

// ---------------------------------------------------------------------------
// AddSlaveZone - with TSIG key name not in store
// ---------------------------------------------------------------------------

func TestSlaveManager_AddSlaveZone_WithMissingTSIGKey(t *testing.T) {
	ks := NewKeyStore()

	sm := NewSlaveManager(ks)
	err := sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName:     "test.com.",
		Masters:      []string{"192.168.1.1:53"},
		Timeout:      5 * time.Second,
		TSIGKeyName: "missing-key.example.com.",
	})
	if err != nil {
		t.Fatalf("AddSlaveZone() error = %v", err)
	}

	// Client should still be created (without key store option)
	_, ok := sm.clients["test.com."]
	if !ok {
		t.Fatal("IXFR client not created")
	}
}

// ---------------------------------------------------------------------------
// GetSlaveZone - without trailing dot normalization
// ---------------------------------------------------------------------------

func TestSlaveManager_GetSlaveZone_WithoutTrailingDot(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.AddSlaveZone(SlaveZoneConfig{
		ZoneName: "test.com.",
		Masters:  []string{"192.168.1.1:53"},
	})

	sz := sm.GetSlaveZone("test.com") // Without trailing dot
	if sz == nil {
		t.Error("GetSlaveZone() should normalize name without trailing dot")
	}
}
