package transfer

import (
	"testing"
	"time"

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
