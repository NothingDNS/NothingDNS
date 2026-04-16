package transfer

import (
	"net"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/zone"
)

// ---------------------------------------------------------------------------
// ddns.go: HandleUpdate - successful channel send (select case branch)
// Exercises lines 200-201 where update request is sent to channel.
// ---------------------------------------------------------------------------

func TestHandleUpdate_UpdateChannelSend_Observable(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})

	// Add TSIG key so that HandleUpdate doesn't refuse
	ks := NewKeyStore()
	secret := []byte("test-secret-key-1234567890abcdef")
	ks.AddKey(&TSIGKey{
		Name:      "testkey.",
		Algorithm: HmacSHA256,
		Secret:    secret,
	})
	handler.SetKeyStore(ks)

	// Build a valid UPDATE request with TSIG
	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			QDCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeUpdate,
			},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	// Sign the message so HandleUpdate accepts it
	tsigRR, err := SignMessage(req, &TSIGKey{
		Name:      "testkey.",
		Algorithm: HmacSHA256,
		Secret:    secret,
	}, 300)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	req.Additionals = append(req.Additionals, tsigRR)

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleUpdate: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}

	// Verify update was sent to channel
	ch := handler.GetUpdateChannel()
	select {
	case updateReq := <-ch:
		if updateReq.ZoneName != "example.com." {
			t.Errorf("expected zone example.com., got %s", updateReq.ZoneName)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for update request on channel")
	}
}

// ---------------------------------------------------------------------------
// ddns.go: HandleUpdate - channel full (default branch of select)
// Exercises lines 202-203 where channel is full.
// ---------------------------------------------------------------------------

func TestHandleUpdate_UpdateChannelFull_Observable(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{"example.com.": z})

	ks := NewKeyStore()
	secret := []byte("test-secret-key-1234567890abcdef")
	ks.AddKey(&TSIGKey{
		Name:      "testkey.",
		Algorithm: HmacSHA256,
		Secret:    secret,
	})
	handler.SetKeyStore(ks)

	// Fill the channel
	for i := 0; i < 100; i++ {
		handler.updateChan <- &UpdateRequest{ZoneName: "filler"}
	}

	// Now send another update - should succeed but hit default branch
	name, _ := protocol.ParseName("example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0x5678,
			QDCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeUpdate,
			},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	tsigRR, _ := SignMessage(req, &TSIGKey{
		Name:      "testkey.",
		Algorithm: HmacSHA256,
		Secret:    secret,
	}, 300)
	req.Additionals = append(req.Additionals, tsigRR)

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleUpdate: %v", err)
	}
	// Update is applied synchronously; channel notification is non-blocking (V-06 fix)
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// notify.go: HandleNOTIFY - successful channel send
// ---------------------------------------------------------------------------

func TestHandleNOTIFY_NotifyChannelSend_Observable(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	handler := NewNOTIFYSlaveHandler(map[string]*zone.Zone{"example.com.": z})
	handler.SetSerialChecker(func(zoneName string, serial uint32) bool {
		return true // always needs update
	})
	handler.AddNotifyAllowed("192.168.1.1/32")

	name, _ := protocol.ParseName("example.com.")
	soaName, _ := protocol.ParseName("ns1.example.com.")
	rName, _ := protocol.ParseName("admin.example.com.")

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0xAAAA,
			QDCount: 1,
			ANCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data: &protocol.RDataSOA{
					MName:   soaName,
					RName:   rName,
					Serial:  2024010200,
					Refresh: 3600,
					Retry:   600,
					Expire:  604800,
					Minimum: 86400,
				},
			},
		},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", resp.Header.Flags.RCODE)
	}

	// Verify notify was sent to channel
	ch := handler.GetNotifyChannel()
	select {
	case notifyReq := <-ch:
		if notifyReq.ZoneName != "example.com." {
			t.Errorf("expected zone example.com., got %s", notifyReq.ZoneName)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for notify request on channel")
	}
}

// ---------------------------------------------------------------------------
// notify.go: HandleNOTIFY - channel full (default branch)
// ---------------------------------------------------------------------------

func TestHandleNOTIFY_NotifyChannelFull_Observable(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 2024010101,
	}
	handler := NewNOTIFYSlaveHandler(map[string]*zone.Zone{"example.com.": z})
	handler.SetSerialChecker(func(zoneName string, serial uint32) bool {
		return true
	})
	handler.AddNotifyAllowed("127.0.0.1/32")

	// Fill the channel
	for i := 0; i < 100; i++ {
		handler.notifyChan <- &NOTIFYRequest{ZoneName: "filler"}
	}

	name, _ := protocol.ParseName("example.com.")
	soaName, _ := protocol.ParseName("ns1.example.com.")
	rName, _ := protocol.ParseName("admin.example.com.")

	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0xBBBB,
			QDCount: 1,
			ANCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Answers: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data: &protocol.RDataSOA{
					MName:   soaName,
					RName:   rName,
					Serial:  2024010200,
					Refresh: 3600,
					Retry:   600,
					Expire:  604800,
					Minimum: 86400,
				},
			},
		},
	}

	// Should not block even with full channel
	resp, err := handler.HandleNOTIFY(req, net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY: %v", err)
	}
	if resp == nil {
		t.Error("expected non-nil response even with full channel")
	}
}

// ---------------------------------------------------------------------------
// notify.go: HandleNOTIFY - serial from Authority section
// ---------------------------------------------------------------------------

func TestHandleNOTIFY_SerialFromAuthority(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 100,
	}
	handler := NewNOTIFYSlaveHandler(map[string]*zone.Zone{"example.com.": z})
	handler.SetSerialChecker(func(zoneName string, serial uint32) bool {
		return true
	})
	handler.AddNotifyAllowed("192.168.1.1/32")

	name, _ := protocol.ParseName("example.com.")
	soaName, _ := protocol.ParseName("ns1.example.com.")
	rName, _ := protocol.ParseName("admin.example.com.")

	// Put SOA in Authority section instead of Answer
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0xCCCC,
			QDCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeNotify,
			},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeSOA,
				Class: protocol.ClassIN,
				TTL:   3600,
				Data: &protocol.RDataSOA{
					MName:   soaName,
					RName:   rName,
					Serial:  200,
					Refresh: 3600,
					Retry:   600,
					Expire:  604800,
					Minimum: 86400,
				},
			},
		},
	}

	resp, err := handler.HandleNOTIFY(req, net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("HandleNOTIFY: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeSuccess {
		t.Errorf("expected success, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// slave.go: SlaveManager.notifyListener stops on stopChan
// ---------------------------------------------------------------------------

func TestSlaveManager_notifyListener_Stop(t *testing.T) {
	sm := NewSlaveManager(nil)
	sm.Start()
	time.Sleep(20 * time.Millisecond)
	sm.Stop()
	// Should return without hanging
}

// ---------------------------------------------------------------------------
// slave.go: SlaveManager.handleNotify with stale serial
// ---------------------------------------------------------------------------

func TestSlaveManager_handleNotify_StaleSerial(t *testing.T) {
	sm := NewSlaveManager(nil)
	sz := &SlaveZone{
		Config: SlaveZoneConfig{
			ZoneName:      "stale.example.com.",
			Masters:       []string{"127.0.0.1:53"},
			TransferType:  "axfr",
			Timeout:       1 * time.Second,
			RetryInterval: 1 * time.Second,
		},
		LastSerial: 100,
	}
	sm.slaveZones["stale.example.com."] = sz

	// Notify with old serial should be ignored (no zone transfer triggered)
	sm.handleNotify(&NOTIFYRequest{
		ZoneName: "stale.example.com.",
		Serial:   50, // older than current
	})
	// Should not panic or start goroutines that fail
}

// ---------------------------------------------------------------------------
// slave.go: NewSlaveZone with invalid config - no masters
// ---------------------------------------------------------------------------

func TestNewSlaveZone_InvalidConfig_NoMasters(t *testing.T) {
	_, err := NewSlaveZone(SlaveZoneConfig{
		ZoneName: "nomaster.example.com.",
		Masters:  []string{},
	})
	if err == nil {
		t.Error("expected error for no masters")
	}
}

// ---------------------------------------------------------------------------
// slave.go: NewSlaveZone with invalid config - bad transfer type
// ---------------------------------------------------------------------------

func TestNewSlaveZone_InvalidConfig_BadTransferType(t *testing.T) {
	_, err := NewSlaveZone(SlaveZoneConfig{
		ZoneName:     "badtype.example.com.",
		Masters:      []string{"127.0.0.1:53"},
		TransferType: "invalid",
	})
	if err == nil {
		t.Error("expected error for invalid transfer type")
	}
}

// ---------------------------------------------------------------------------
// slave.go: SlaveZone thread-safe access
// ---------------------------------------------------------------------------

func TestSlaveZone_ThreadSafeAccess(t *testing.T) {
	sz, err := NewSlaveZone(SlaveZoneConfig{
		ZoneName: "threadsafe.example.com.",
		Masters:  []string{"127.0.0.1:53"},
	})
	if err != nil {
		t.Fatalf("NewSlaveZone: %v", err)
	}

	newZone := zone.NewZone("threadsafe.example.com.")
	newZone.SOA = &zone.SOARecord{Serial: 999}
	sz.UpdateZone(newZone, 999)

	if sz.GetLastSerial() != 999 {
		t.Errorf("expected serial 999, got %d", sz.GetLastSerial())
	}
	got := sz.GetZone()
	if got == nil || got.SOA == nil || got.SOA.Serial != 999 {
		t.Error("GetZone did not return updated zone")
	}
}

// ---------------------------------------------------------------------------
// slave.go: SlaveManager.RemoveSlaveZone - nonexistent
// ---------------------------------------------------------------------------

func TestSlaveManager_RemoveSlaveZone_Nonexistent(t *testing.T) {
	sm := NewSlaveManager(nil)
	// Should not panic
	sm.RemoveSlaveZone("nonexistent.example.com.")
}

// ---------------------------------------------------------------------------
// axfr.go: AXFRServer.generateAXFRRecords - zone without SOA
// ---------------------------------------------------------------------------

func TestAXFRServer_generateAXFRRecords_NoSOA(t *testing.T) {
	z := zone.NewZone("nosoa.example.com.")
	// No SOA set
	s := NewAXFRServer(map[string]*zone.Zone{"nosoa.example.com.": z}, WithAllowList([]string{"127.0.0.0/8"}))
	_, err := s.generateAXFRRecords(z)
	if err == nil {
		t.Error("expected error for zone without SOA")
	}
}

// ---------------------------------------------------------------------------
// axfr.go: AXFRServer.generateAXFRRecords - with zone records
// ---------------------------------------------------------------------------

func TestAXFRServer_generateAXFRRecords_WithRecords(t *testing.T) {
	z := zone.NewZone("withrecs.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 42, TTL: 3600,
	}
	z.Records["withrecs.example.com."] = []zone.Record{
		{Name: "withrecs.example.com.", Type: "A", TTL: 300, RData: "1.2.3.4"},
	}
	s := NewAXFRServer(map[string]*zone.Zone{"withrecs.example.com.": z}, WithAllowList([]string{"127.0.0.0/8"}))
	records, err := s.generateAXFRRecords(z)
	if err != nil {
		t.Fatalf("generateAXFRRecords: %v", err)
	}
	// Should have SOA + A record + SOA = 3 records
	if len(records) < 3 {
		t.Errorf("expected at least 3 records, got %d", len(records))
	}
	// First and last should be SOA
	if records[0].Type != protocol.TypeSOA {
		t.Error("first record should be SOA")
	}
	if records[len(records)-1].Type != protocol.TypeSOA {
		t.Error("last record should be SOA")
	}
}

// ---------------------------------------------------------------------------
// axfr.go: AXFRServer.HandleAXFR - ACL refused
// ---------------------------------------------------------------------------

func TestAXFRServer_HandleAXFR_ACLRefused(t *testing.T) {
	z := zone.NewZone("acl.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1,
	}
	s := NewAXFRServer(map[string]*zone.Zone{"acl.example.com.": z},
		WithAllowList([]string{"10.0.0.0/8"}),
	)

	name, _ := protocol.ParseName("acl.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{ID: 1, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeAXFR, QClass: protocol.ClassIN},
		},
	}

	_, _, err := s.HandleAXFR(req, net.ParseIP("192.168.1.1"))
	if err == nil {
		t.Error("expected error for ACL refused")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go: IXFRServer.HandleIXFR - TSIG key not found
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_TSIGKeyNotFound_Extra(t *testing.T) {
	z := zone.NewZone("tsig.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1,
	}
	axfrServer := NewAXFRServer(map[string]*zone.Zone{"tsig.example.com.": z}, WithAllowList([]string{"127.0.0.0/8"}))
	ks := NewKeyStore()
	axfrServer.keyStore = ks

	ixfrServer := NewIXFRServer(axfrServer)

	name, _ := protocol.ParseName("tsig.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{ID: 1, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
	}

	// Add a TSIG record referencing a non-existent key
	keyName, _ := protocol.ParseName("missing-key.")
	tsigData := &RDataTSIG{Raw: []byte{}}
	req.Additionals = append(req.Additionals, &protocol.ResourceRecord{
		Name: keyName, Type: protocol.TypeTSIG, Class: protocol.ClassANY,
		TTL: 0, Data: tsigData,
	})

	_, err := ixfrServer.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("expected error for missing TSIG key")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go: IXFRServer.generateSingleSOA - with valid zone
// ---------------------------------------------------------------------------

func TestIXFRServer_generateSingleSOA_ValidZone_Extra(t *testing.T) {
	z := zone.NewZone("singleSOA.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 10, TTL: 3600,
	}
	axfrServer := NewAXFRServer(map[string]*zone.Zone{"singleSOA.example.com.": z}, WithAllowList([]string{"127.0.0.0/8"}))
	ixfrServer := NewIXFRServer(axfrServer)

	records, err := ixfrServer.generateSingleSOA(z)
	if err != nil {
		t.Fatalf("generateSingleSOA: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Type != protocol.TypeSOA {
		t.Error("expected SOA record type")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go: IXFRServer.HandleIXFR - client up to date (single SOA response)
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_ClientUpToDate_Extra(t *testing.T) {
	z := zone.NewZone("uptodate.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 100, TTL: 3600,
	}
	axfrServer := NewAXFRServer(map[string]*zone.Zone{"uptodate.example.com.": z}, WithAllowList([]string{"127.0.0.0/8"}))
	ixfrServer := NewIXFRServer(axfrServer)

	name, _ := protocol.ParseName("uptodate.example.com.")
	soaName, _ := protocol.ParseName("ns1.uptodate.example.com.")
	rName, _ := protocol.ParseName("admin.uptodate.example.com.")

	req := &protocol.Message{
		Header: protocol.Header{ID: 1, QDCount: 1, NSCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{
			{
				Name: name, Type: protocol.TypeSOA, Class: protocol.ClassIN, TTL: 3600,
				Data: &protocol.RDataSOA{
					MName: soaName, RName: rName, Serial: 100,
				},
			},
		},
	}

	records, err := ixfrServer.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleIXFR: %v", err)
	}
	// Client serial >= server serial → single SOA response
	if len(records) != 1 {
		t.Errorf("expected 1 record (single SOA), got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// ixfr.go: IXFRServer.HandleIXFR - not authorized
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_NotAuthorized_Extra(t *testing.T) {
	z := zone.NewZone("auth.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1,
	}
	axfrServer := NewAXFRServer(map[string]*zone.Zone{"auth.example.com.": z},
		WithAllowList([]string{"10.0.0.0/8"}),
	)
	ixfrServer := NewIXFRServer(axfrServer)

	name, _ := protocol.ParseName("auth.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{ID: 1, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
	}

	_, err := ixfrServer.HandleIXFR(req, net.ParseIP("192.168.1.1"))
	if err == nil {
		t.Error("expected error for unauthorized IXFR")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go: IXFRServer.HandleIXFR - TSIG verification fail
// ---------------------------------------------------------------------------

func TestIXFRServer_HandleIXFR_TSIGVerificationFail_Extra(t *testing.T) {
	z := zone.NewZone("tsigfail.example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1,
	}
	axfrServer := NewAXFRServer(map[string]*zone.Zone{"tsigfail.example.com.": z}, WithAllowList([]string{"127.0.0.0/8"}))
	ks := NewKeyStore()
	ks.AddKey(&TSIGKey{
		Name:      "testkey.",
		Algorithm: HmacSHA256,
		Secret:    []byte("correct-secret-key-data-here!!"),
	})
	axfrServer.keyStore = ks

	ixfrServer := NewIXFRServer(axfrServer)

	name, _ := protocol.ParseName("tsigfail.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{ID: 1, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
	}

	// Sign with a different key to cause verification failure
	wrongKey := &TSIGKey{
		Name:      "testkey.",
		Algorithm: HmacSHA256,
		Secret:    []byte("wrong-secret-key-for-verification"),
	}
	tsigRR, err := SignMessage(req, wrongKey, 300)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	req.Additionals = append(req.Additionals, tsigRR)

	_, err = ixfrServer.HandleIXFR(req, net.ParseIP("127.0.0.1"))
	if err == nil {
		t.Error("expected error for TSIG verification failure")
	}
}

// ---------------------------------------------------------------------------
// ddns.go: HandleUpdate - no TSIG (refused)
// ---------------------------------------------------------------------------

func TestHandleUpdate_NoTSIG_Refused(t *testing.T) {
	z := zone.NewZone("notsig.example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 1,
	}
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{"notsig.example.com.": z})

	name, _ := protocol.ParseName("notsig.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1111,
			QDCount: 1,
			Flags: protocol.Flags{
				Opcode: protocol.OpcodeUpdate,
			},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}

	resp, err := handler.HandleUpdate(req, net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("HandleUpdate: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected RcodeRefused for no TSIG, got %d", resp.Header.Flags.RCODE)
	}
}

// ---------------------------------------------------------------------------
// ddns.go: HandleUpdate - ACL denied
// ---------------------------------------------------------------------------

func TestHandleUpdate_ACLDenied(t *testing.T) {
	z := zone.NewZone("acldeny.example.com.")
	z.SOA = &zone.SOARecord{
		MName:  "ns1.example.com.",
		RName:  "admin.example.com.",
		Serial: 1,
	}
	handler := NewDynamicDNSHandler(map[string]*zone.Zone{"acldeny.example.com.": z})
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/8")
	handler.AddACL("acldeny.example.com.", ipNet)

	ks := NewKeyStore()
	secret := []byte("test-secret-key-1234567890abcdef")
	ks.AddKey(&TSIGKey{Name: "testkey.", Algorithm: HmacSHA256, Secret: secret})
	handler.SetKeyStore(ks)

	name, _ := protocol.ParseName("acldeny.example.com.")
	req := &protocol.Message{
		Header: protocol.Header{
			ID:      0x2222,
			QDCount: 1,
			Flags:   protocol.Flags{Opcode: protocol.OpcodeUpdate},
		},
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeSOA, QClass: protocol.ClassIN},
		},
	}
	tsigRR, _ := SignMessage(req, &TSIGKey{
		Name: "testkey.", Algorithm: HmacSHA256, Secret: secret,
	}, 300)
	req.Additionals = append(req.Additionals, tsigRR)

	// Use an IP outside the ACL range
	resp, err := handler.HandleUpdate(req, net.ParseIP("192.168.1.1"))
	if err != nil {
		t.Fatalf("HandleUpdate: %v", err)
	}
	if resp.Header.Flags.RCODE != protocol.RcodeRefused {
		t.Errorf("expected RcodeRefused for ACL denied, got %d", resp.Header.Flags.RCODE)
	}
}
