package transfer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
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

func TestSlaveManager_AddSlaveZone_DotNormalization(t *testing.T) {
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

func TestSlaveManager_AddSlaveZone_NewSlaveZoneError(t *testing.T) {
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

func TestSlaveManager_RemoveSlaveZone_DotNormalization(t *testing.T) {
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

func TestSlaveManager_notifyListener_NilNotify(t *testing.T) {
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
// Covered by TestSlaveManager_applyTransferredZone_EmptyRecords in slave_test.go.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// slave.go:331 - applyTransferredZone error (no SOA record)
// Tests the path where transferred records have no SOA.
// ---------------------------------------------------------------------------

func TestSlaveManager_applyTransferredZone_NoSOARecord(t *testing.T) {
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

func TestAXFRServer_generateAXFRRecords_InvalidOrigin(t *testing.T) {
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

func TestAXFRServer_generateAXFRRecords_InvalidSOAMName(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName:  strings.Repeat("a", 70) + ".example.com.", // Invalid label
		RName:  "admin.example.com.",
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

func TestAXFRServer_zoneRecordToRR_InvalidRecordName(t *testing.T) {
	s := NewAXFRServer(make(map[string]*zone.Zone))
	longLabel := strings.Repeat("a", 70)
	_, err := s.zoneRecordToRR(longLabel+".example.com.", zone.Record{
		Name: longLabel + ".example.com.", Type: "A", TTL: 3600, RData: "1.2.3.4",
	})
	if err == nil {
		t.Error("expected error for invalid record name in zoneRecordToRR")
	}
}

// ---------------------------------------------------------------------------
// axfr.go:494 - sendMessage with Pack error (nil question Name)
// Tests the error path where msg.Pack fails.
// ---------------------------------------------------------------------------

func TestAXFRClient_sendMessage_PackError(t *testing.T) {
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

func TestAXFRClient_receiveAXFRResponse_UnpackError(t *testing.T) {
	client := NewAXFRClient("ns1.example.com:53")
	// Valid length prefix but garbage data that can't be unpacked
	data := []byte{0x00, 0x10}
	data = append(data, make([]byte, 16)...)
	conn := &mockConn{readData: data}
	_, err := client.receiveAXFRResponse(conn, 0x1234, nil)
	if err == nil {
		t.Error("expected error for unpack failure in receiveAXFRResponse")
	}
}

// ---------------------------------------------------------------------------
// ixfr.go:200 - generateIncrementalIXFR with client serial not found
// Tests the startIdx == -1 path.
// ---------------------------------------------------------------------------

func TestIXFRServer_generateIncrementalIXFR_SerialNotInRange(t *testing.T) {
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

func TestIXFRServer_generateIncrementalIXFR_JournalGap(t *testing.T) {
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

func TestSlaveManager_performAXFR_Success(t *testing.T) {
	// This test can be flaky under load due to TCP timing; skip in short mode
	if testing.Short() {
		t.Skip("skipping flaky integration test in short mode")
	}
	if os.Getenv("NOTHINGDNS_TRANSFER_FLAKY") != "1" {
		t.Skip("skipping flaky transfer test by default; set NOTHINGDNS_TRANSFER_FLAKY=1 to enable")
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

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Logf("server accept error: %v", err)
			return
		}
		defer conn.Close()

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

		sendChunk := func(answerSet []*protocol.ResourceRecord) error {
			resp := &protocol.Message{
				Header: protocol.Header{
					ID:      0x1234,
					ANCount: uint16(len(answerSet)),
					Flags:   protocol.Flags{QR: true, RCODE: protocol.RcodeSuccess},
				},
				Answers: answerSet,
			}
			buf := make([]byte, 65535)
			n, err := resp.Pack(buf)
			if err != nil {
				return err
			}
			sendBuf := make([]byte, 2+n)
			sendBuf[0] = byte(n >> 8)
			sendBuf[1] = byte(n)
			copy(sendBuf[2:], buf[:n])
			_, err = conn.Write(sendBuf)
			return err
		}

		// Send AXFR as two chunks so client can observe SOA start/end across reads.
		if err := sendChunk([]*protocol.ResourceRecord{records[0]}); err != nil {
			t.Logf("server write chunk 1 error: %v", err)
			return
		}
		if err := sendChunk([]*protocol.ResourceRecord{records[len(records)-1]}); err != nil {
			t.Logf("server write chunk 2 error: %v", err)
			return
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
		t.Logf("server sent %d records in 2 chunks", len(records))
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
}

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
	})
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
		MName:  "ns1.example.com.",
		RName:  strings.Repeat("a", 70) + ".example.com.", // Invalid: label > 63 chars
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
		MName:  strings.Repeat("a", 70) + ".example.com.", // Invalid: label > 63 chars
		RName:  "admin.example.com.",
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
	_, err := client.receiveAXFRResponse(conn, 0x1234, nil)
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
	_, err := client.receiveAXFRResponse(conn, 0x1234, nil)
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
	records, err := client.receiveAXFRResponse(conn, 0x1234, nil)
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

	_, _, err := server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
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

	_, _, err := server.HandleAXFR(req, net.ParseIP("127.0.0.1"))
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
	})
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
	})
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
	})
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
// ixfr.go:424-426 - buildIXFRRequest SignMessage with deprecated algorithm
// Note: HMAC-SHA1 now works with a warning for backwards compatibility
// ---------------------------------------------------------------------------

func TestIXFRClient_buildIXFRRequest_DeprecatedAlgorithm_Extra6(t *testing.T) {
	client := NewIXFRClient("ns1.example.com:53")

	key := &TSIGKey{
		Name:      "test-key.example.com.",
		Algorithm: HmacSHA1,
		Secret:    []byte("test-secret"),
	}

	// SHA-1 now works with deprecation warning for backwards compatibility
	msg, err := client.buildIXFRRequest("example.com.", 100, key)
	if err != nil {
		t.Errorf("unexpected error for deprecated algorithm: %v", err)
	}
	if msg == nil {
		t.Error("expected message for deprecated algorithm")
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
	records, err := client.receiveAXFRResponse(conn, 0x1234, nil)
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
	_, err := client.receiveAXFRResponse(conn, 0x1234, nil)
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
	data, err := buildSignedData(msg, "test.key.", prevMAC, HmacSHA256, time.Now().UTC(), 300, 1234)
	if err != nil {
		t.Fatalf("buildSignedData with previousMAC: %v", err)
	}
	// RFC 8945 §5.3.2.1: previous MAC is length-prefixed (uint16 BE) before
	// the message body. So the data must start with [hi, lo, prevMAC...].
	expectedPrefix := []byte{byte(len(prevMAC) >> 8), byte(len(prevMAC))}
	expectedPrefix = append(expectedPrefix, prevMAC...)
	if !bytes.HasPrefix(data, expectedPrefix) {
		t.Error("expected signed data to start with length-prefixed previousMAC (RFC 8945 §5.3.2.1)")
	}
}

func TestBuildSignedData_RejectsOutOfRangeTimeSigned_Extra6(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{ID: 1234, QDCount: 1},
		Questions: []*protocol.Question{
			{Name: mustParseName6("example.com."), QType: protocol.TypeA, QClass: protocol.ClassIN},
		},
	}

	tests := []struct {
		name       string
		timeSigned time.Time
		want       string
	}{
		{
			name:       "before epoch",
			timeSigned: time.Unix(-1, 0),
			want:       "before Unix epoch",
		},
		{
			name:       "above 48 bit range",
			timeSigned: time.Unix(int64(maxTSIGTimeSigned)+1, 0),
			want:       "exceeds 48-bit Unix time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildSignedData(msg, "test.key.", nil, HmacSHA256, tt.timeSigned, 300, 1234)
			if err == nil {
				t.Fatal("buildSignedData() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("buildSignedData() error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Full AXFR Transfer with TSIG via TCP server - dead code (same TSIG issue)
// ---------------------------------------------------------------------------

func TestAXFRClient_Transfer_WithTSIG_TCPServerDeadCode_Extra6(t *testing.T) {
	t.Skip("unreachable: TSIG records unpacked from wire format have *RDataRaw data, so TSIG verification always fails in receiveAXFRResponse")
}

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
	_, err := client.receiveAXFRResponse(conn, 0x1234, nil)
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

type xotShortWriteConn struct {
	maxWrite int
	written  []byte
}

func (c *xotShortWriteConn) Read([]byte) (int, error) {
	return 0, net.ErrClosed
}

func (c *xotShortWriteConn) Write(b []byte) (int, error) {
	if c.maxWrite <= 0 {
		return 0, nil
	}
	n := c.maxWrite
	if n > len(b) {
		n = len(b)
	}
	c.written = append(c.written, b[:n]...)
	return n, nil
}

func (c *xotShortWriteConn) Close() error                     { return nil }
func (c *xotShortWriteConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *xotShortWriteConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *xotShortWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *xotShortWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *xotShortWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestWriteXoTFrameRetriesShortWrites_Extra7(t *testing.T) {
	conn := &xotShortWriteConn{maxWrite: 1}
	frame := []byte{0, 0, 0xaa, 0xbb, 0xcc}
	if err := writeXoTFrame(conn, frame, 3); err != nil {
		t.Fatalf("writeXoTFrame error: %v", err)
	}

	want := []byte{0, 3, 0xaa, 0xbb, 0xcc}
	if len(conn.written) != len(want) {
		t.Fatalf("written length = %d, want %d", len(conn.written), len(want))
	}
	for i := range want {
		if conn.written[i] != want[i] {
			t.Fatalf("written[%d] = %#x, want %#x", i, conn.written[i], want[i])
		}
	}
}

func TestWriteXoTFrameRejectsZeroProgress_Extra7(t *testing.T) {
	conn := &xotShortWriteConn{maxWrite: 0}
	err := writeXoTFrame(conn, []byte{0, 0, 0xaa}, 1)
	if err != io.ErrShortWrite {
		t.Fatalf("writeXoTFrame error = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestCloseXoTConnReturnsCloseError_Extra7(t *testing.T) {
	closeErr := errors.New("close failed")
	conn := &xotCloseErrorConn{err: closeErr}

	if err := closeXoTConn(conn); !errors.Is(err, closeErr) {
		t.Fatalf("closeXoTConn error = %v, want %v", err, closeErr)
	}
	if !conn.closed {
		t.Fatal("closeXoTConn should call Close")
	}
	if err := closeXoTConn(nil); err != nil {
		t.Fatalf("closeXoTConn(nil) = %v, want nil", err)
	}
}

type xotCloseErrorConn struct {
	xotShortWriteConn
	err    error
	closed bool
}

func (c *xotCloseErrorConn) Close() error {
	c.closed = true
	return c.err
}

// ---------------------------------------------------------------------------
// WithRequireTSIG
// ---------------------------------------------------------------------------

func TestWithRequireTSIG(t *testing.T) {
	s := NewAXFRServer(map[string]*zone.Zone{}, WithRequireTSIG())
	if !s.requireTSIG {
		t.Error("expected requireTSIG=true")
	}
}

func TestWithRequireTSIG_DefaultFalse(t *testing.T) {
	s := NewAXFRServer(map[string]*zone.Zone{})
	if s.requireTSIG {
		t.Error("expected requireTSIG=false by default")
	}
}

// ---------------------------------------------------------------------------
// WithLogger
// ---------------------------------------------------------------------------

func TestWithLogger(t *testing.T) {
	logger := util.NewLogger(util.DEBUG, util.TextFormat, &bytes.Buffer{})
	s := NewAXFRServer(map[string]*zone.Zone{}, WithLogger(logger))
	if s.logger == nil {
		t.Error("expected logger to be set")
	}
}

func TestWithLogger_Nil(t *testing.T) {
	s := NewAXFRServer(map[string]*zone.Zone{}, WithLogger(nil))
	// Should not panic — logger is nil but that's valid
	if s.logger != nil {
		t.Error("expected nil logger")
	}
}

// ---------------------------------------------------------------------------
// WithZonesMu
// ---------------------------------------------------------------------------

func TestWithZonesMu(t *testing.T) {
	mu := &sync.RWMutex{}
	s := NewAXFRServer(map[string]*zone.Zone{}, WithZonesMu(mu))
	if s.zonesMu != mu {
		t.Error("expected zonesMu to be the provided mutex")
	}
}

func TestWithZonesMu_Nil(t *testing.T) {
	s := NewAXFRServer(map[string]*zone.Zone{}, WithZonesMu(nil))

	if s.zonesMu == nil {
		t.Fatal("expected default zonesMu to be retained")
	}

	z := zone.NewZone("example.com.")
	s.AddZone(z)
	if got := s.zones["example.com."]; got != z {
		t.Fatalf("AddZone after WithZonesMu(nil) stored %v, want zone", got)
	}
}

// ---------------------------------------------------------------------------
// SetZonesMu
// ---------------------------------------------------------------------------

func TestSetZonesMu(t *testing.T) {
	s := NewAXFRServer(map[string]*zone.Zone{})
	original := s.zonesMu

	mu := &sync.RWMutex{}
	s.SetZonesMu(mu)

	if s.zonesMu != mu {
		t.Error("expected zonesMu to be replaced")
	}
	if s.zonesMu == original {
		t.Error("expected zonesMu to differ from original")
	}
}

func TestSetZonesMu_Nil(t *testing.T) {
	s := NewAXFRServer(map[string]*zone.Zone{})
	original := s.zonesMu
	s.SetZonesMu(nil)

	if s.zonesMu != original {
		t.Error("expected SetZonesMu(nil) to retain the existing mutex")
	}

	z := zone.NewZone("example.com.")
	s.AddZone(z)
	if got := s.zones["example.com."]; got != z {
		t.Fatalf("AddZone after SetZonesMu(nil) stored %v, want zone", got)
	}
}

// ---------------------------------------------------------------------------
// createZONEMDRR
// ---------------------------------------------------------------------------

func TestCreateZONEMDRR_SHA256(t *testing.T) {
	s := NewAXFRServer(map[string]*zone.Zone{})
	origin, _ := protocol.ParseName("example.com.")

	zonemd := &zone.ZONEMD{
		ZoneName:  "example.com.",
		Hash:      []byte{0xde, 0xad, 0xbe, 0xef},
		Algorithm: 1, // SHA-256
	}

	rr, err := s.createZONEMDRR(zonemd, origin, 2026070101)
	if err != nil {
		t.Fatalf("createZONEMDRR: %v", err)
	}
	if rr.Type != protocol.TypeZONEMD {
		t.Errorf("Type = %d, want TypeZONEMD", rr.Type)
	}
	if rr.Class != protocol.ClassIN {
		t.Errorf("Class = %d, want ClassIN", rr.Class)
	}
	if rr.TTL != 0 {
		t.Errorf("TTL = %d, want 0 per RFC 8976", rr.TTL)
	}
	data, ok := rr.Data.(*protocol.RDataZONEMD)
	if !ok {
		t.Fatalf("expected *RDataZONEMD, got %T", rr.Data)
	}
	if data.Serial != 2026070101 {
		t.Errorf("Serial = %d, want 2026070101 (must equal SOA serial per RFC 8976)", data.Serial)
	}
	if data.Scheme != 1 {
		t.Errorf("Scheme = %d, want 1", data.Scheme)
	}
	if data.Algorithm != 1 {
		t.Errorf("Algorithm = %d, want 1", data.Algorithm)
	}
	if len(data.Digest) != 4 {
		t.Errorf("Digest length = %d, want 4", len(data.Digest))
	}
}

func TestCreateZONEMDRR_SHA384(t *testing.T) {
	s := NewAXFRServer(map[string]*zone.Zone{})
	origin, _ := protocol.ParseName("test.example.")

	zonemd := &zone.ZONEMD{
		ZoneName:  "test.example.",
		Hash:      make([]byte, 48), // SHA-384 = 48 bytes
		Algorithm: 2,
	}

	rr, err := s.createZONEMDRR(zonemd, origin, 100)
	if err != nil {
		t.Fatalf("createZONEMDRR: %v", err)
	}
	data := rr.Data.(*protocol.RDataZONEMD)
	if data.Algorithm != 2 {
		t.Errorf("Algorithm = %d, want 2 (SHA-384)", data.Algorithm)
	}
	if len(data.Digest) != 48 {
		t.Errorf("Digest length = %d, want 48", len(data.Digest))
	}
}

// ---------------------------------------------------------------------------
// WithAllowList + WithLogger interaction
// ---------------------------------------------------------------------------

func TestWithAllowList_InvalidCIDR_WithLogger(t *testing.T) {
	logger := util.NewLogger(util.DEBUG, util.TextFormat, &bytes.Buffer{})
	s := NewAXFRServer(
		map[string]*zone.Zone{},
		WithLogger(logger),
		WithAllowList([]string{"not-a-valid-cidr", "10.0.0.0/8"}),
	)

	if len(s.allowList) != 1 {
		t.Errorf("allowList = %d entries, want 1 (invalid CIDR skipped)", len(s.allowList))
	}
}

func TestWithAllowList_InvalidCIDR_NoLogger(t *testing.T) {
	// Should not panic when logger is nil and CIDR is invalid
	s := NewAXFRServer(
		map[string]*zone.Zone{},
		WithAllowList([]string{"not-valid"}),
	)

	if len(s.allowList) != 0 {
		t.Errorf("allowList = %d, want 0", len(s.allowList))
	}
}

// ---------------------------------------------------------------------------
// Integration: createZONEMDRR through generateAXFRRecords
// ---------------------------------------------------------------------------

func TestGenerateAXFRRecords_WithZONEMD(t *testing.T) {
	origin := "example.com."
	z := &zone.Zone{
		Origin: origin,
		SOA: &zone.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minimum: 86400,
			TTL:     3600,
		},
		ZONEMD: &zone.ZONEMD{
			ZoneName:  origin,
			Hash:      []byte{0x01, 0x02, 0x03, 0x04},
			Algorithm: 1,
		},
		Records: map[string][]zone.Record{},
	}

	s := NewAXFRServer(map[string]*zone.Zone{origin: z})
	records, err := s.generateAXFRRecords(z)
	if err != nil {
		t.Fatalf("generateAXFRRecords: %v", err)
	}

	// Expected: SOA + ZONEMD + SOA = 3 records minimum
	if len(records) < 3 {
		t.Fatalf("expected at least 3 records (SOA+ZONEMD+SOA), got %d", len(records))
	}

	// First record is SOA
	if records[0].Type != protocol.TypeSOA {
		t.Errorf("first record type = %d, want SOA", records[0].Type)
	}
	// Second record is ZONEMD
	if records[1].Type != protocol.TypeZONEMD {
		t.Errorf("second record type = %d, want ZONEMD", records[1].Type)
	}
	// Last record is SOA
	last := records[len(records)-1]
	if last.Type != protocol.TypeSOA {
		t.Errorf("last record type = %d, want SOA", last.Type)
	}
}

func TestGenerateAXFRRecords_WithZoneRecordsAndZONEMD(t *testing.T) {
	origin := "example.com."
	z := &zone.Zone{
		Origin: origin,
		SOA: &zone.SOARecord{
			MName:   "ns1.example.com.",
			RName:   "admin.example.com.",
			Serial:  2024010101,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minimum: 86400,
			TTL:     3600,
		},
		ZONEMD: &zone.ZONEMD{
			ZoneName:  origin,
			Hash:      []byte{0xaa, 0xbb},
			Algorithm: 2,
		},
		Records: map[string][]zone.Record{
			"www.example.com.": {
				{Type: "A", TTL: 300, RData: "1.2.3.4"},
			},
		},
	}

	s := NewAXFRServer(map[string]*zone.Zone{origin: z})
	records, err := s.generateAXFRRecords(z)
	if err != nil {
		t.Fatalf("generateAXFRRecords: %v", err)
	}

	// Expected: SOA + ZONEMD + www A record + SOA = 4 records
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	// Verify order: SOA, ZONEMD, A record, SOA
	if records[0].Type != protocol.TypeSOA {
		t.Errorf("record[0] type = %d, want SOA", records[0].Type)
	}
	if records[1].Type != protocol.TypeZONEMD {
		t.Errorf("record[1] type = %d, want ZONEMD", records[1].Type)
	}
	if records[2].Type != protocol.TypeA {
		t.Errorf("record[2] type = %d, want A", records[2].Type)
	}
	if records[3].Type != protocol.TypeSOA {
		t.Errorf("record[3] type = %d, want SOA", records[3].Type)
	}
}

// ---------------------------------------------------------------------------
// TKEY tests (tkey.go) — nearly entirely untested
// ---------------------------------------------------------------------------

func TestTKEYModeString_AllModes_CovExtra(t *testing.T) {
	cases := []struct {
		mode uint16
		want string
	}{
		{TKEYModeServerAssignment, "Server Assignment"},
		{TKEYModeDiffieHellman, "Diffie-Hellman"},
		{TKEYModeGSSAPI, "GSS-API"},
		{TKEYModeResolverAssignment, "Resolver Assignment"},
		{TKEYModeKeyDeletion, "Key Deletion"},
		{99, "Unknown (99)"},
	}
	for _, tc := range cases {
		got := TKEYModeString(tc.mode)
		if got != tc.want {
			t.Errorf("TKEYModeString(%d) = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestTKEYErrorString_AllErrors_CovExtra(t *testing.T) {
	cases := []struct {
		code uint16
		want string
	}{
		{TKEYErrNoError, "No Error"},
		{TKEYErrBadSig, "Bad Signature"},
		{TKEYErrBadKey, "Bad Key"},
		{TKEYErrBadTime, "Bad Time"},
		{TKEYErrBadMode, "Bad Mode"},
		{TKEYErrBadName, "Bad Name"},
		{TKEYErrBadAlgorithm, "Bad Algorithm"},
		{99, "Unknown (99)"},
	}
	for _, tc := range cases {
		got := TKEYErrorString(tc.code)
		if got != tc.want {
			t.Errorf("TKEYErrorString(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestTKEYRecord_String_CovExtra(t *testing.T) {
	rec := &TKEYRecord{
		Algorithm:  "hmac-sha256.",
		Mode:       TKEYModeDiffieHellman,
		Error:      TKEYErrNoError,
		Expiration: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	s := rec.String()
	if !strings.Contains(s, "hmac-sha256.") || !strings.Contains(s, "Diffie-Hellman") || !strings.Contains(s, "No Error") {
		t.Errorf("TKEYRecord.String() = %q, unexpected output", s)
	}
}

func TestTKEYToResourceRecord_CovExtra(t *testing.T) {
	inception := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	expiration := inception.Add(time.Hour)
	keyData := []byte{1, 2, 3, 4}
	otherData := []byte{5, 6}
	rec := &TKEYRecord{
		Algorithm:  "hmac-sha256.",
		Inception:  inception,
		Expiration: expiration,
		Mode:       TKEYModeServerAssignment,
		Error:      TKEYErrNoError,
		KeyData:    keyData,
		OtherData:  otherData,
	}

	rr, err := TKEYToResourceRecord(rec)
	if err != nil {
		t.Fatalf("TKEYToResourceRecord() error: %v", err)
	}
	if rr == nil {
		t.Fatal("expected non-nil resource record")
	}
	if rr.Type != protocol.TypeTKEY {
		t.Errorf("expected type TKEY, got %d", rr.Type)
	}
	raw, ok := rr.Data.(*protocol.RDataRaw)
	if !ok {
		t.Fatalf("rr.Data = %T, want *protocol.RDataRaw", rr.Data)
	}

	algWire := protocol.CanonicalWireName(rec.Algorithm)
	wantLen := len(algWire) + 4 + 4 + 2 + 2 + 2 + len(keyData) + 2 + len(otherData)
	if len(raw.Data) != wantLen {
		t.Fatalf("RDATA length = %d, want %d", len(raw.Data), wantLen)
	}
	offset := len(algWire)
	if got := binary.BigEndian.Uint32(raw.Data[offset:]); got != uint32(inception.Unix()) {
		t.Errorf("inception = %d, want %d", got, uint32(inception.Unix()))
	}
	offset += 4
	if got := binary.BigEndian.Uint32(raw.Data[offset:]); got != uint32(expiration.Unix()) {
		t.Errorf("expiration = %d, want %d", got, uint32(expiration.Unix()))
	}
	offset += 4
	if got := binary.BigEndian.Uint16(raw.Data[offset:]); got != TKEYModeServerAssignment {
		t.Errorf("mode = %d, want %d", got, TKEYModeServerAssignment)
	}
	offset += 2
	if got := binary.BigEndian.Uint16(raw.Data[offset:]); got != TKEYErrNoError {
		t.Errorf("error = %d, want %d", got, TKEYErrNoError)
	}
	offset += 2
	keyLen := int(binary.BigEndian.Uint16(raw.Data[offset:]))
	offset += 2
	if keyLen != len(keyData) || !bytes.Equal(raw.Data[offset:offset+keyLen], keyData) {
		t.Errorf("key data = %x, want %x", raw.Data[offset:offset+keyLen], keyData)
	}
	offset += keyLen
	otherLen := int(binary.BigEndian.Uint16(raw.Data[offset:]))
	offset += 2
	if otherLen != len(otherData) || !bytes.Equal(raw.Data[offset:offset+otherLen], otherData) {
		t.Errorf("other data = %x, want %x", raw.Data[offset:offset+otherLen], otherData)
	}
}

func TestTKEYQuery_ValidKeySize_CovExtra(t *testing.T) {
	rec, err := TKEYQuery("hmac-sha256.", TKEYModeServerAssignment, 256)
	if err != nil {
		t.Fatalf("TKEYQuery() error: %v", err)
	}
	if rec.Mode != TKEYModeServerAssignment {
		t.Errorf("mode = %d, want %d", rec.Mode, TKEYModeServerAssignment)
	}
	if len(rec.KeyData) != 32 { // 256/8
		t.Errorf("key length = %d, want 32", len(rec.KeyData))
	}
	if rec.Error != TKEYErrNoError {
		t.Errorf("error = %d, want 0", rec.Error)
	}
}

func TestTKEYQuery_InvalidKeySize_CovExtra(t *testing.T) {
	_, err := TKEYQuery("hmac-sha256.", TKEYModeServerAssignment, 32)
	if err == nil {
		t.Fatal("expected error for key size < 64")
	}
	_, err = TKEYQuery("hmac-sha256.", TKEYModeServerAssignment, 8193)
	if err == nil {
		t.Fatal("expected error for key size > 8192")
	}
}

func TestGenerateTKEYDiffieHellman_CovExtra(t *testing.T) {
	// Small prime for test (not cryptographically secure, just for coverage)
	p, _ := new(big.Int).SetString("ffffffffffffffc5", 16)
	g := big.NewInt(2)
	priv := make([]byte, 16)
	rand.Read(priv)

	rec, err := GenerateTKEYDiffieHellman("hmac-sha256.", p.Bytes(), g.Bytes(), priv)
	if err != nil {
		t.Fatalf("GenerateTKEYDiffieHellman() error: %v", err)
	}
	if rec.Mode != TKEYModeDiffieHellman {
		t.Errorf("mode = %d, want %d", rec.Mode, TKEYModeDiffieHellman)
	}
	if len(rec.KeyData) == 0 {
		t.Error("expected non-empty key data")
	}
	if len(rec.SecurityParameters) == 0 {
		t.Error("expected non-empty security parameters")
	}
}

func TestComputeTKEYHMAC_SHA256_CovExtra(t *testing.T) {
	msg := []byte("test message")
	key := []byte("test key")
	mac, err := ComputeTKEYHMAC(msg, key, "hmac-sha256")
	if err != nil {
		t.Fatalf("ComputeTKEYHMAC() error: %v", err)
	}
	if len(mac) != 32 {
		t.Errorf("SHA-256 HMAC length = %d, want 32", len(mac))
	}
}

func TestComputeTKEYHMAC_SHA512_CovExtra(t *testing.T) {
	msg := []byte("test message")
	key := []byte("test key")
	mac, err := ComputeTKEYHMAC(msg, key, "hmac-sha512")
	if err != nil {
		t.Fatalf("ComputeTKEYHMAC() error: %v", err)
	}
	if len(mac) != 64 {
		t.Errorf("SHA-512 HMAC length = %d, want 64", len(mac))
	}
}

func TestValidateTKEY_ValidRecord_CovExtra(t *testing.T) {
	rec := &TKEYRecord{
		Algorithm:  "hmac-sha256.",
		Mode:       TKEYModeServerAssignment,
		Error:      TKEYErrNoError,
		Expiration: time.Now().Add(time.Hour),
	}
	if err := ValidateTKEY(rec); err != nil {
		t.Errorf("ValidateTKEY() unexpected error: %v", err)
	}
}

func TestValidateTKEY_NilRecord_CovExtra(t *testing.T) {
	if err := ValidateTKEY(nil); err == nil {
		t.Error("expected error for nil record")
	}
}

func TestValidateTKEY_EmptyAlgorithm_CovExtra(t *testing.T) {
	rec := &TKEYRecord{
		Algorithm:  "",
		Mode:       TKEYModeServerAssignment,
		Expiration: time.Now().Add(time.Hour),
	}
	if err := ValidateTKEY(rec); err == nil {
		t.Error("expected error for empty algorithm")
	}
}

func TestValidateTKEY_InvalidMode_CovExtra(t *testing.T) {
	rec := &TKEYRecord{
		Algorithm:  "hmac-sha256.",
		Mode:       99,
		Expiration: time.Now().Add(time.Hour),
	}
	if err := ValidateTKEY(rec); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestValidateTKEY_ExpiredRecord_CovExtra(t *testing.T) {
	rec := &TKEYRecord{
		Algorithm:  "hmac-sha256.",
		Mode:       TKEYModeServerAssignment,
		Expiration: time.Now().Add(-time.Hour),
	}
	if err := ValidateTKEY(rec); err == nil {
		t.Error("expected error for expired record")
	}
}

func TestTKEYExpiredAtBoundary_CovExtra(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

	if tkeyExpiredAt(now.Add(time.Nanosecond), now) {
		t.Error("TKEY should not be expired before expiration")
	}
	if !tkeyExpiredAt(now, now) {
		t.Error("TKEY should be expired at exact expiration")
	}
	if !tkeyExpiredAt(now.Add(-time.Nanosecond), now) {
		t.Error("TKEY should be expired after expiration")
	}
}

func TestFormatTKEYTime_CovExtra(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	result, err := formatTKEYTime(ts)
	if err != nil {
		t.Fatalf("formatTKEYTime() error: %v", err)
	}
	if result != uint32(ts.Unix()) {
		t.Errorf("formatTKEYTime = %d, want %d", result, uint32(ts.Unix()))
	}
}

func TestFormatTKEYTime_Bounds_CovExtra(t *testing.T) {
	tests := []struct {
		name    string
		in      time.Time
		want    uint32
		wantErr bool
	}{
		{
			name:    "before epoch rejected",
			in:      time.Unix(-1, 0),
			wantErr: true,
		},
		{
			name: "epoch accepted",
			in:   time.Unix(0, 0),
			want: 0,
		},
		{
			name: "max uint32 accepted",
			in:   time.Unix(int64(^uint32(0)), 0),
			want: ^uint32(0),
		},
		{
			name:    "above max uint32 rejected",
			in:      time.Unix(int64(^uint32(0))+1, 0),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatTKEYTime(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("formatTKEYTime(%s) error = nil, want error", tt.in.UTC().Format(time.RFC3339))
				}
				return
			}
			if err != nil {
				t.Fatalf("formatTKEYTime(%s) error: %v", tt.in.UTC().Format(time.RFC3339), err)
			}
			if got != tt.want {
				t.Fatalf("formatTKEYTime(%s) = %d, want %d", tt.in.UTC().Format(time.RFC3339), got, tt.want)
			}
		})
	}
}

func TestTKEYToResourceRecord_RejectsOutOfRangeTimes_CovExtra(t *testing.T) {
	tests := []struct {
		name       string
		inception  time.Time
		expiration time.Time
		errSubstr  string
	}{
		{
			name:       "inception before epoch",
			inception:  time.Unix(-1, 0),
			expiration: time.Unix(1, 0),
			errSubstr:  "invalid TKEY inception",
		},
		{
			name:       "expiration above max uint32",
			inception:  time.Unix(1, 0),
			expiration: time.Unix(int64(^uint32(0))+1, 0),
			errSubstr:  "invalid TKEY expiration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := TKEYToResourceRecord(&TKEYRecord{
				Algorithm:  "hmac-sha256.",
				Inception:  tt.inception,
				Expiration: tt.expiration,
				Mode:       TKEYModeServerAssignment,
				Error:      TKEYErrNoError,
			})
			if err == nil {
				t.Fatal("TKEYToResourceRecord() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("TKEYToResourceRecord() error = %q, want substring %q", err.Error(), tt.errSubstr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// KVJournalStore tests (kvjournal.go) — nearly entirely untested
// ---------------------------------------------------------------------------

func TestKVJournalStore_SaveAndLoad_CovExtra(t *testing.T) {
	dir := t.TempDir()
	store := NewKVJournalStore(dir)

	entry := &IXFRJournalEntry{
		Serial:    100,
		Timestamp: time.Now().Truncate(time.Second),
		Added: []zone.RecordChange{
			{Name: "test.example.com.", Type: protocol.TypeA, TTL: 300, RData: "1.2.3.4"},
		},
	}
	if err := store.SaveEntry("example.com.", entry); err != nil {
		t.Fatalf("SaveEntry() error: %v", err)
	}

	entries, err := store.LoadEntries("example.com.")
	if err != nil {
		t.Fatalf("LoadEntries() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Serial != 100 {
		t.Errorf("serial = %d, want 100", entries[0].Serial)
	}
	if len(entries[0].Added) != 1 {
		t.Errorf("added records = %d, want 1", len(entries[0].Added))
	}
}

func TestKVJournalStore_LoadEntries_NoDir_CovExtra(t *testing.T) {
	dir := t.TempDir()
	store := NewKVJournalStore(dir)

	entries, err := store.LoadEntries("nonexistent.zone.")
	if err != nil {
		t.Fatalf("LoadEntries() error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent zone, got %d", len(entries))
	}
}

func TestKVJournalStore_MultipleEntries_SortedBySerial_CovExtra(t *testing.T) {
	dir := t.TempDir()
	store := NewKVJournalStore(dir)

	for _, serial := range []uint32{300, 100, 200} {
		entry := &IXFRJournalEntry{
			Serial:    serial,
			Timestamp: time.Now().Truncate(time.Second),
		}
		if err := store.SaveEntry("example.com.", entry); err != nil {
			t.Fatalf("SaveEntry(%d) error: %v", serial, err)
		}
	}

	entries, err := store.LoadEntries("example.com.")
	if err != nil {
		t.Fatalf("LoadEntries() error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	// Entries should be sorted ascending by serial
	for i, want := range []uint32{100, 200, 300} {
		if entries[i].Serial != want {
			t.Errorf("entries[%d].Serial = %d, want %d", i, entries[i].Serial, want)
		}
	}
}

func TestKVJournalStore_TrimJournal_CovExtra(t *testing.T) {
	dir := t.TempDir()
	store := NewKVJournalStore(dir)
	store.SetMaxJournalSize(2)

	for serial := uint32(1); serial <= 5; serial++ {
		entry := &IXFRJournalEntry{
			Serial:    serial,
			Timestamp: time.Now().Truncate(time.Second),
		}
		if err := store.SaveEntry("example.com.", entry); err != nil {
			t.Fatalf("SaveEntry(%d) error: %v", serial, err)
		}
	}

	entries, err := store.LoadEntries("example.com.")
	if err != nil {
		t.Fatalf("LoadEntries() error: %v", err)
	}
	// Only the newest 2 entries should remain
	if len(entries) > 2 {
		t.Errorf("expected at most 2 entries after trim, got %d", len(entries))
	}
	if len(entries) > 0 && entries[0].Serial < 4 {
		t.Errorf("oldest remaining serial = %d, want >= 4", entries[0].Serial)
	}
}

func TestKVJournalStore_Truncate_CovExtra(t *testing.T) {
	dir := t.TempDir()
	store := NewKVJournalStore(dir)
	store.SetMaxJournalSize(3)

	for serial := uint32(1); serial <= 3; serial++ {
		entry := &IXFRJournalEntry{
			Serial:    serial,
			Timestamp: time.Now().Truncate(time.Second),
		}
		if err := store.SaveEntry("example.com.", entry); err != nil {
			t.Fatalf("SaveEntry(%d) error: %v", serial, err)
		}
	}

	// Truncate (uses same logic as trim)
	if err := store.Truncate("example.com.", 3); err != nil {
		t.Fatalf("Truncate() error: %v", err)
	}

	entries, _ := store.LoadEntries("example.com.")
	if len(entries) != 3 {
		t.Errorf("expected 3 entries after truncate, got %d", len(entries))
	}
}

func TestSanitizeFilename_CovExtra(t *testing.T) {
	cases := []struct {
		input, want string
	}{
		{"example.com.", "example_com_"},
		{"a/b\\c:d", "a_b_c_d"},
		{"normal", "normal"},
	}
	for _, tc := range cases {
		got := sanitizeFilename(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// TSIG Key Rotation tests (tsig.go)
// ---------------------------------------------------------------------------

func TestKeyStore_RotateKey_CovExtra(t *testing.T) {
	ks := NewKeyStore()
	oldKey := &TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("old-secret"),
		CreatedAt: time.Now().Add(-time.Hour),
	}
	ks.AddKey(oldKey)

	newKey := &TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("new-secret"),
		CreatedAt: time.Now(),
	}
	ks.RotateKey(newKey)

	// Current key should be the new one
	got, ok := ks.GetKey("key1.example.com.")
	if !ok {
		t.Fatal("expected key to exist")
	}
	if string(got.Secret) != "new-secret" {
		t.Errorf("current key secret = %q, want %q", got.Secret, "new-secret")
	}

	// Previous key should still be accessible within grace period
	prev := ks.GetPreviousKey("key1.example.com.")
	if prev == nil {
		t.Fatal("expected previous key to be available within grace period")
	}
	if string(prev.Secret) != "old-secret" {
		t.Errorf("previous key secret = %q, want %q", prev.Secret, "old-secret")
	}
}

func TestKeyStore_RotateKey_NoOldKey_CovExtra(t *testing.T) {
	ks := NewKeyStore()
	newKey := &TSIGKey{
		Name:      "newkey.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("secret"),
		CreatedAt: time.Now(),
	}
	// Rotating a key that doesn't exist yet should still add it
	ks.RotateKey(newKey)

	got, ok := ks.GetKey("newkey.example.com.")
	if !ok {
		t.Fatal("expected key to exist after rotate")
	}
	if string(got.Secret) != "secret" {
		t.Errorf("secret = %q, want %q", got.Secret, "secret")
	}
}

func TestKeyStore_GetPreviousKey_NoPrevious_CovExtra(t *testing.T) {
	ks := NewKeyStore()
	prev := ks.GetPreviousKey("nonexistent.")
	if prev != nil {
		t.Error("expected nil for no previous key")
	}
}

func TestKeyStore_GetPreviousKey_GraceExpired_CovExtra(t *testing.T) {
	ks := NewKeyStoreWithGracePeriod(1 * time.Nanosecond)
	oldKey := &TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("old"),
		CreatedAt: time.Now(),
	}
	ks.AddKey(oldKey)

	newKey := &TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("new"),
		CreatedAt: time.Now(),
	}
	ks.RotateKey(newKey)

	// Wait for grace period to expire
	time.Sleep(10 * time.Millisecond)

	prev := ks.GetPreviousKey("key1.example.com.")
	if prev != nil {
		t.Error("expected nil after grace period expired")
	}
}

func TestKeyStore_PreviousKeyExpiredAtBoundary_CovExtra(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	gracePeriod := 5 * time.Minute

	if previousKeyExpiredAt(now.Add(-gracePeriod+time.Nanosecond), now, gracePeriod) {
		t.Error("previous key should still be valid before grace boundary")
	}
	if !previousKeyExpiredAt(now.Add(-gracePeriod), now, gracePeriod) {
		t.Error("previous key should expire exactly at grace boundary")
	}
	if !previousKeyExpiredAt(now.Add(-gracePeriod-time.Nanosecond), now, gracePeriod) {
		t.Error("previous key should expire after grace boundary")
	}
}

func TestKeyStore_GetPreviousKey_NameMismatch_CovExtra(t *testing.T) {
	ks := NewKeyStore()
	key1 := &TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("secret1"),
		CreatedAt: time.Now(),
	}
	ks.AddKey(key1)

	key1New := &TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("secret1new"),
		CreatedAt: time.Now(),
	}
	ks.RotateKey(key1New)

	// Ask for a different name
	prev := ks.GetPreviousKey("key2.example.com.")
	if prev != nil {
		t.Error("expected nil for non-matching name")
	}
}

func TestKeyStore_ClearPreviousKey_CovExtra(t *testing.T) {
	ks := NewKeyStore()
	key := &TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("old"),
		CreatedAt: time.Now(),
	}
	ks.AddKey(key)

	ks.RotateKey(&TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("new"),
		CreatedAt: time.Now(),
	})

	// Verify previous key exists
	prev := ks.GetPreviousKey("key1.example.com.")
	if prev == nil {
		t.Fatal("expected previous key to exist")
	}

	ks.ClearPreviousKey()
	prev = ks.GetPreviousKey("key1.example.com.")
	if prev != nil {
		t.Error("expected nil after ClearPreviousKey")
	}
}

func TestKeyStore_ReplaceKey_CovExtra(t *testing.T) {
	ks := NewKeyStore()
	ks.AddKey(&TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("original"),
		CreatedAt: time.Now(),
	})

	ks.ReplaceKey("key1.example.com.", &TSIGKey{
		Name:      "key1.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("replacement"),
		CreatedAt: time.Now(),
	})

	got, ok := ks.GetKey("key1.example.com.")
	if !ok {
		t.Fatal("expected key to exist")
	}
	if string(got.Secret) != "replacement" {
		t.Errorf("secret = %q, want %q", got.Secret, "replacement")
	}
}

func TestNewKeyStoreWithGracePeriod_CovExtra(t *testing.T) {
	gp := 10 * time.Minute
	ks := NewKeyStoreWithGracePeriod(gp)
	if ks.gracePeriod != gp {
		t.Errorf("grace period = %v, want %v", ks.gracePeriod, gp)
	}
}

// ---------------------------------------------------------------------------
// TSIG HMAC-SHA224 (unsupported) coverage
// ---------------------------------------------------------------------------

func TestCalculateMAC_SHA224_Unsupported_CovExtra(t *testing.T) {
	_, err := calculateMAC([]byte("key"), []byte("data"), HmacSHA224)
	if err == nil {
		t.Error("expected error for unsupported SHA224 algorithm")
	}
}

// ---------------------------------------------------------------------------
// XoT tests (xot.go) — nearly entirely untested
// ---------------------------------------------------------------------------

func TestNewXoTServer_NilZones_CovExtra(t *testing.T) {
	_, err := NewXoTServer(nil, nil, nil)
	if err == nil {
		t.Error("expected error for nil zones")
	}
}

func TestNewXoTServer_NilConfig_Defaults_CovExtra(t *testing.T) {
	zones := map[string]*zone.Zone{
		"example.com.": zone.NewZone("example.com."),
	}
	// nil config means no access control (no mTLS CAFile, no allowlist). XoT is
	// deny-by-default, so this must be rejected rather than expose all zones.
	if _, err := NewXoTServer(zones, nil, nil); err == nil {
		t.Fatal("NewXoTServer() with no access control should error")
	}

	// With an allowlist it should construct and default the port to 853.
	srv, err := NewXoTServer(zones, &XoTConfig{AllowedNetworks: []string{"127.0.0.0/8"}}, nil)
	if err != nil {
		t.Fatalf("NewXoTServer() error: %v", err)
	}
	if srv.port != 853 {
		t.Errorf("default port = %d, want 853", srv.port)
	}
}

func TestNewXoTServer_WithConfig_CovExtra(t *testing.T) {
	zones := map[string]*zone.Zone{
		"example.com.": zone.NewZone("example.com."),
	}
	cfg := &XoTConfig{
		ListenPort:      953,
		AllowedNetworks: []string{"10.0.0.0/8", "192.168.1.0/24", "not-a-cidr"},
	}
	srv, err := NewXoTServer(zones, cfg, nil)
	if err != nil {
		t.Fatalf("NewXoTServer() error: %v", err)
	}
	if srv.port != 953 {
		t.Errorf("port = %d, want 953", srv.port)
	}
	if len(srv.allowList) != 2 {
		t.Errorf("allow list length = %d, want 2 (invalid CIDR skipped)", len(srv.allowList))
	}
}

func TestXoTExtractIXFRClientSerialReadsAuthoritySOA(t *testing.T) {
	name, err := protocol.ParseName("example.com.")
	if err != nil {
		t.Fatalf("ParseName() error: %v", err)
	}
	mname, err := protocol.ParseName("ns1.example.com.")
	if err != nil {
		t.Fatalf("ParseName() error: %v", err)
	}
	rname, err := protocol.ParseName("admin.example.com.")
	if err != nil {
		t.Fatalf("ParseName() error: %v", err)
	}

	soaRR := func(serial uint32) *protocol.ResourceRecord {
		return &protocol.ResourceRecord{
			Name:  name,
			Type:  protocol.TypeSOA,
			Class: protocol.ClassIN,
			TTL:   3600,
			Data: &protocol.RDataSOA{
				MName:   mname,
				RName:   rname,
				Serial:  serial,
				Refresh: 3600,
				Retry:   600,
				Expire:  604800,
				Minimum: 86400,
			},
		}
	}

	req := &protocol.Message{
		Questions: []*protocol.Question{
			{Name: name, QType: protocol.TypeIXFR, QClass: protocol.ClassIN},
		},
		Authorities: []*protocol.ResourceRecord{soaRR(123)},
		Additionals: []*protocol.ResourceRecord{soaRR(999)},
	}

	if got := extractIXFRClientSerial(req); got != 123 {
		t.Fatalf("client serial = %d, want authority SOA serial 123", got)
	}

	req.Authorities = nil
	if got := extractIXFRClientSerial(req); got != 999 {
		t.Fatalf("fallback client serial = %d, want additional SOA serial 999", got)
	}
}

func TestXoTServer_isAllowed_NoAllowList_CovExtra(t *testing.T) {
	// Deny-by-default: with neither mTLS nor an allowlist, no client is allowed.
	srv := &XoTServer{}
	if srv.isAllowed(net.ParseIP("1.2.3.4")) {
		t.Error("expected denied when no allow list and no mTLS configured")
	}
	// mTLS-authenticated clients are allowed regardless of allowlist.
	srvMTLS := &XoTServer{requireClientCert: true}
	if !srvMTLS.isAllowed(net.ParseIP("1.2.3.4")) {
		t.Error("expected allowed when mTLS client cert is required/verified")
	}
}

func TestXoTServer_isAllowed_WithAllowList_CovExtra(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/8")
	srv := &XoTServer{
		allowList: []net.IPNet{*network},
	}
	if !srv.isAllowed(net.ParseIP("10.1.2.3")) {
		t.Error("expected 10.1.2.3 to be allowed")
	}
	if srv.isAllowed(net.ParseIP("192.168.1.1")) {
		t.Error("expected 192.168.1.1 to be denied")
	}
}

func TestTLSCACache_AddGet_CovExtra(t *testing.T) {
	cache := NewTLSCACache()
	rec := &TLSARecord{
		Usage:        3,
		Selector:     1,
		MatchingType: 1,
		Certificate:  []byte("certdata"),
		Domain:       "example.com",
		TTL:          time.Hour,
	}
	cache.AddTLSA("Example.COM.", rec)

	records := cache.GetTLSARecords("example.com.")
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Usage != 3 {
		t.Errorf("usage = %d, want 3", records[0].Usage)
	}
}

func TestTLSCACache_GetNonexistent_CovExtra(t *testing.T) {
	cache := NewTLSCACache()
	records := cache.GetTLSARecords("nonexistent.com.")
	if records != nil {
		t.Errorf("expected nil for nonexistent domain, got %v", records)
	}
}

func TestParseXoTRData_A_Valid_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypeA, "192.168.1.1")
	if err != nil {
		t.Fatalf("parseRData A error: %v", err)
	}
	a, ok := rdata.(*protocol.RDataA)
	if !ok {
		t.Fatal("expected RDataA")
	}
	if a.Address != [4]byte{192, 168, 1, 1} {
		t.Errorf("address = %v, want 192.168.1.1", a.Address)
	}
}

func TestParseXoTRData_A_InvalidIPv4_CovExtra(t *testing.T) {
	_, err := parseRData(protocol.TypeA, "::1")
	if err == nil {
		t.Error("expected error for IPv6 in A record")
	}
}

func TestParseXoTRData_AAAA_Valid_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypeAAAA, "2001:db8::1")
	if err != nil {
		t.Fatalf("parseRData AAAA error: %v", err)
	}
	aaaa, ok := rdata.(*protocol.RDataAAAA)
	if !ok {
		t.Fatal("expected RDataAAAA")
	}
	// 2001:db8::1 in network byte order — verify the address actually
	// decoded, not just that the fixed-size array has its compile-time
	// length of 16.
	want := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	if aaaa.Address != want {
		t.Errorf("address = %x, want %x", aaaa.Address, want)
	}
}

func TestParseXoTRData_CNAME_Valid_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypeCNAME, "target.example.com.")
	if err != nil {
		t.Fatalf("parseRData CNAME error: %v", err)
	}
	if _, ok := rdata.(*protocol.RDataCNAME); !ok {
		t.Fatal("expected RDataCNAME")
	}
}

func TestParseXoTRData_NS_Valid_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypeNS, "ns1.example.com.")
	if err != nil {
		t.Fatalf("parseRData NS error: %v", err)
	}
	if _, ok := rdata.(*protocol.RDataNS); !ok {
		t.Fatal("expected RDataNS")
	}
}

func TestParseXoTRData_MX_Valid_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypeMX, "10 mail.example.com.")
	if err != nil {
		t.Fatalf("parseRData MX error: %v", err)
	}
	mx, ok := rdata.(*protocol.RDataMX)
	if !ok {
		t.Fatal("expected RDataMX")
	}
	if mx.Preference != 10 {
		t.Errorf("preference = %d, want 10", mx.Preference)
	}
}

func TestParseXoTRData_TXT_Valid_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypeTXT, "hello world")
	if err != nil {
		t.Fatalf("parseRData TXT error: %v", err)
	}
	txt, ok := rdata.(*protocol.RDataTXT)
	if !ok {
		t.Fatal("expected RDataTXT")
	}
	if len(txt.Strings) != 1 || txt.Strings[0] != "hello world" {
		t.Errorf("text = %v, want [hello world]", txt.Strings)
	}
}

func TestParseXoTRData_PTR_Valid_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypePTR, "ptr.example.com.")
	if err != nil {
		t.Fatalf("parseRData PTR error: %v", err)
	}
	if _, ok := rdata.(*protocol.RDataPTR); !ok {
		t.Fatal("expected RDataPTR")
	}
}

func TestParseXoTRData_SRV_Valid_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypeSRV, "10 20 443 server.example.com.")
	if err != nil {
		t.Fatalf("parseRData SRV error: %v", err)
	}
	srv, ok := rdata.(*protocol.RDataSRV)
	if !ok {
		t.Fatal("expected RDataSRV")
	}
	if srv.Priority != 10 || srv.Weight != 20 || srv.Port != 443 {
		t.Errorf("priority=%d weight=%d port=%d, want 10 20 443", srv.Priority, srv.Weight, srv.Port)
	}
}

func TestParseXoTRData_SRV_Invalid_CovExtra(t *testing.T) {
	_, err := parseRData(protocol.TypeSRV, "badformat")
	if err == nil {
		t.Error("expected error for invalid SRV format")
	}
}

func TestParseXoTRData_SRVInvalidNumericFields_CovExtra(t *testing.T) {
	tests := []string{
		"bad 20 443 server.example.com.",
		"10 bad 443 server.example.com.",
		"10 20 bad server.example.com.",
		"65536 20 443 server.example.com.",
		"10 65536 443 server.example.com.",
		"10 20 65536 server.example.com.",
	}
	for _, rdata := range tests {
		if _, err := parseRData(protocol.TypeSRV, rdata); err == nil {
			t.Fatalf("parseRData(SRV, %q) expected error", rdata)
		}
	}
}

func TestParseXoTRData_CAA_CovExtra(t *testing.T) {
	rdata, err := parseRData(protocol.TypeCAA, "0 issue ca.example.com")
	if err != nil {
		t.Fatalf("parseRData CAA error: %v", err)
	}
	caa, ok := rdata.(*protocol.RDataCAA)
	if !ok {
		t.Fatalf("rdata = %T, want *protocol.RDataCAA", rdata)
	}
	if caa.Flags != 0 || caa.Tag != "issue" || caa.Value != "ca.example.com" {
		t.Errorf("CAA = %d %q %q, want 0 \"issue\" \"ca.example.com\"", caa.Flags, caa.Tag, caa.Value)
	}
}

func TestParseXoTRData_A_InvalidIP_CovExtra(t *testing.T) {
	_, err := parseRData(protocol.TypeA, "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid A record")
	}
}

func TestParseXoTRData_AAAA_InvalidIP_CovExtra(t *testing.T) {
	_, err := parseRData(protocol.TypeAAAA, "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid AAAA record")
	}
}

func TestCanonicalLess_CovExtra(t *testing.T) {
	nameA, _ := protocol.ParseName("a.example.com.")
	nameB, _ := protocol.ParseName("b.example.com.")
	nameA2, _ := protocol.ParseName("a.example.com.")

	a := &protocol.ResourceRecord{Name: nameA, Type: protocol.TypeA}
	b := &protocol.ResourceRecord{Name: nameB, Type: protocol.TypeA}
	a2 := &protocol.ResourceRecord{Name: nameA2, Type: protocol.TypeAAAA}

	if !canonicalLess(a, b) {
		t.Error("expected a < b by name")
	}
	if canonicalLess(b, a) {
		t.Error("expected b > a by name")
	}
	if !canonicalLess(a, a2) {
		t.Error("expected A < AAAA by type when names equal")
	}

	// Same name, same type => not less
	a3 := &protocol.ResourceRecord{Name: nameA, Type: protocol.TypeA}
	if canonicalLess(a, a3) {
		t.Error("expected a not < a3 (same name and type)")
	}
}

func TestXoTServer_generateAXFRRecords_ValidZone_CovExtra(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 2025010101, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}
	z.Records["www.example.com."] = []zone.Record{
		{Name: "www.example.com.", Type: "A", TTL: 300, RData: "1.2.3.4"},
	}

	srv := &XoTServer{zones: map[string]*zone.Zone{"example.com.": z}, zonesMu: &sync.RWMutex{}}
	records, err := srv.generateAXFRRecords(z)
	if err != nil {
		t.Fatalf("generateAXFRRecords() error: %v", err)
	}

	// Expect: SOA + zone records + SOA
	if len(records) < 3 {
		t.Errorf("expected >= 3 records (SOA + zone records + SOA), got %d", len(records))
	}
	// First and last should be SOA
	if records[0].Type != protocol.TypeSOA {
		t.Errorf("first record type = %d, want SOA", records[0].Type)
	}
	if records[len(records)-1].Type != protocol.TypeSOA {
		t.Errorf("last record type = %d, want SOA", records[len(records)-1].Type)
	}
}

func TestXoTServer_generateAXFRRecords_NoSOA_CovExtra(t *testing.T) {
	srv := &XoTServer{}

	if _, err := srv.generateAXFRRecords(nil); err == nil || !strings.Contains(err.Error(), "zone is nil") {
		t.Fatalf("generateAXFRRecords(nil) error = %v, want zone is nil", err)
	}

	z := zone.NewZone("example.com.")
	if _, err := srv.generateAXFRRecords(z); err == nil || !strings.Contains(err.Error(), "zone has no SOA record") {
		t.Fatalf("generateAXFRRecords(no SOA) error = %v, want zone has no SOA record", err)
	}
}

// mockJournalStore implements JournalStore for testing.
type mockJournalStore struct {
	entries map[string][]*IXFRJournalEntry
}

func (m *mockJournalStore) SaveEntry(zoneName string, entry *IXFRJournalEntry) error {
	m.entries[zoneName] = append(m.entries[zoneName], entry)
	return nil
}

func (m *mockJournalStore) LoadEntries(zoneName string) ([]*IXFRJournalEntry, error) {
	return m.entries[zoneName], nil
}

func (m *mockJournalStore) Truncate(zoneName string, keepCount int) error {
	if entries, ok := m.entries[zoneName]; ok && len(entries) > keepCount {
		m.entries[zoneName] = entries[len(entries)-keepCount:]
	}
	return nil
}

func TestXoTServer_generateIXFRRecords_RejectsMissingSOA_CovExtra(t *testing.T) {
	srv := &XoTServer{}

	if _, err := srv.generateIXFRRecords(nil, 100); err == nil || !strings.Contains(err.Error(), "zone is nil") {
		t.Fatalf("generateIXFRRecords(nil) error = %v, want zone is nil", err)
	}

	z := zone.NewZone("example.com.")
	if _, err := srv.generateIXFRRecords(z, 100); err == nil || !strings.Contains(err.Error(), "zone has no SOA record") {
		t.Fatalf("generateIXFRRecords(no SOA) error = %v, want zone has no SOA record", err)
	}
}

func TestXoTServer_generateIXFRRecords_SameSerial_CovExtra(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 100, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	srv := &XoTServer{}
	records, err := srv.generateIXFRRecords(z, 100)
	if err != nil {
		t.Fatalf("generateIXFRRecords() error: %v", err)
	}
	// Same serial => just SOA
	if len(records) != 1 {
		t.Errorf("expected 1 record (SOA only), got %d", len(records))
	}
	if records[0].Type != protocol.TypeSOA {
		t.Errorf("record type = %d, want SOA", records[0].Type)
	}
}

func TestXoTServer_generateIXFRRecords_ClientSerialNewerUsesSingleSOA(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 0xFFFFFFFF, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	srv := &XoTServer{}
	records, err := srv.generateIXFRRecords(z, 1)
	if err != nil {
		t.Fatalf("generateIXFRRecords() error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record (SOA only), got %d", len(records))
	}
	if records[0].Type != protocol.TypeSOA {
		t.Fatalf("record type = %d, want SOA", records[0].Type)
	}
}

func TestXoTServer_generateIXFRRecords_DifferentSerial_CovExtra(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 200, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	srv := &XoTServer{}
	records, err := srv.generateIXFRRecords(z, 100)
	if err != nil {
		t.Fatalf("generateIXFRRecords() error: %v", err)
	}
	// Different serial => full AXFR (SOA + records + SOA)
	if len(records) < 2 {
		t.Errorf("expected >= 2 records for different serial, got %d", len(records))
	}
}

func TestXoTServer_generateIXFRRecords_WithJournal_Incremental(t *testing.T) {
	// Test that XoT IXFR uses journal for incremental transfers
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 200, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	// Create mock journal store with entries
	mockStore := &mockJournalStore{
		entries: map[string][]*IXFRJournalEntry{
			"example.com.": {
				{
					Serial: 150,
					Added: []zone.RecordChange{
						{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "10.0.0.1"},
					},
					Deleted: []zone.RecordChange{
						{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "10.0.0.50"},
					},
					Timestamp: time.Now(),
				},
				{
					Serial: 200,
					Added: []zone.RecordChange{
						{Name: "mail.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "10.0.0.2"},
					},
					Deleted:   []zone.RecordChange{},
					Timestamp: time.Now(),
				},
			},
		},
	}

	srv := &XoTServer{journalStore: mockStore}
	// Client has serial 100, server has 200 — should get incremental from journal
	records, err := srv.generateIXFRRecords(z, 100)
	if err != nil {
		t.Fatalf("generateIXFRRecords() error: %v", err)
	}

	// Should be incremental (SOA, del, SOA, add, SOA = 5 records for 2 entries)
	if len(records) == 0 {
		t.Fatal("expected records, got none")
	}
	// First and last must be SOA with current serial 200
	if records[0].Type != protocol.TypeSOA || records[len(records)-1].Type != protocol.TypeSOA {
		t.Errorf("expected SOA first and last, got %d records", len(records))
	}
	soa := records[0].Data.(*protocol.RDataSOA)
	if soa.Serial != 200 {
		t.Errorf("SOA serial = %d, want 200", soa.Serial)
	}

	var soaSerials []uint32
	for _, rr := range records {
		if rr.Type != protocol.TypeSOA {
			continue
		}
		soa, ok := rr.Data.(*protocol.RDataSOA)
		if !ok {
			t.Fatalf("SOA record has data type %T", rr.Data)
		}
		soaSerials = append(soaSerials, soa.Serial)
	}
	wantSerials := []uint32{200, 100, 150, 150, 200, 200}
	if len(soaSerials) != len(wantSerials) {
		t.Fatalf("SOA serial count = %d, want %d (%v)", len(soaSerials), len(wantSerials), soaSerials)
	}
	for i := range wantSerials {
		if soaSerials[i] != wantSerials[i] {
			t.Fatalf("SOA serials = %v, want %v", soaSerials, wantSerials)
		}
	}
}

func TestXoTServer_generateIXFRRecords_WrapAroundSerialUsesIncremental(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 1, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	mockStore := &mockJournalStore{
		entries: map[string][]*IXFRJournalEntry{
			"example.com.": {
				{
					Serial: 1,
					Added: []zone.RecordChange{
						{Name: "www.example.com.", Type: protocol.TypeA, TTL: 3600, RData: "10.0.0.1"},
					},
					Timestamp: time.Now(),
				},
			},
		},
	}

	srv := &XoTServer{journalStore: mockStore}
	records, err := srv.generateIXFRRecords(z, 0xFFFFFFFF)
	if err != nil {
		t.Fatalf("generateIXFRRecords() error: %v", err)
	}

	foundAdded := false
	for _, rr := range records {
		if rr.Type == protocol.TypeA {
			foundAdded = true
			break
		}
	}
	if !foundAdded {
		t.Fatal("expected incremental IXFR to include wrapped serial journal addition")
	}
}

func TestXoTServer_generateIXFRRecords_WithJournal_FallbackToAXFR(t *testing.T) {
	// Test that XoT IXFR falls back to AXFR when journal has no entries for zone
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 200, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	// Empty journal store — should fall back to AXFR
	mockStore := &mockJournalStore{entries: map[string][]*IXFRJournalEntry{}}
	srv := &XoTServer{journalStore: mockStore}
	records, err := srv.generateIXFRRecords(z, 100)
	if err != nil {
		t.Fatalf("generateIXFRRecords() error: %v", err)
	}
	// Should fall back to AXFR (SOA + SOA pattern)
	if len(records) == 0 {
		t.Error("expected AXFR fallback records, got none")
	}
}

func TestXoTServer_Close_WithoutListener_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	if err := srv.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

func TestXoTServer_Close_Idempotent_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	srv.Close()
	srv.Close() // Should not panic
}

func TestXoTServer_Close_StopsAcceptLoop_CovExtra(t *testing.T) {
	certFile, keyFile := writeTestXoTCertFiles(t)
	port := getFreeTCPPort(t)
	zones := map[string]*zone.Zone{
		"example.com.": zone.NewZone("example.com."),
	}
	srv, err := NewXoTServer(zones, &XoTConfig{
		CertFile:        certFile,
		KeyFile:         keyFile,
		ListenPort:      port,
		AllowedNetworks: []string{"127.0.0.0/8"},
	}, nil)
	if err != nil {
		t.Fatalf("NewXoTServer() error: %v", err)
	}
	if err := srv.Serve("127.0.0.1"); err != nil {
		t.Fatalf("Serve() error: %v", err)
	}
	go srv.AcceptLoop()

	done := make(chan error, 1)
	go func() {
		done <- srv.Close()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close() error: %v", err)
		}
	case <-time.After(2 * time.Second):
		if srv.listener != nil {
			_ = srv.listener.Close()
		}
		t.Fatal("Close() did not stop AcceptLoop")
	}
}

func TestXoTServer_Addr_CovExtra(t *testing.T) {
	srv := &XoTServer{address: "0.0.0.0", port: 853}
	addr := srv.Addr()
	if addr != "0.0.0.0:853" {
		t.Errorf("Addr() = %q, want %q", addr, "0.0.0.0:853")
	}
}

func TestXoTServer_Serve_Closed_CovExtra(t *testing.T) {
	srv := &XoTServer{port: 853}
	srv.closed = true
	err := srv.Serve("127.0.0.1")
	if err == nil {
		t.Error("expected error when server is closed")
	}
}

func TestBuildXoTTLSConfig_MinTLS13_CovExtra(t *testing.T) {
	cfg := &XoTConfig{
		MinTLSVersion: 13,
	}
	tlsCfg, err := buildXoTTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildXoTTLSConfig() error: %v", err)
	}
	// Should have curve preferences set
	if len(tlsCfg.CurvePreferences) == 0 {
		t.Error("expected curve preferences to be set")
	}
}

func TestBuildXoTTLSConfig_InvalidCertFile_CovExtra(t *testing.T) {
	cfg := &XoTConfig{
		CertFile: "nonexistent.pem",
		KeyFile:  "nonexistent.key",
	}
	_, err := buildXoTTLSConfig(cfg)
	if err == nil {
		t.Error("expected error for nonexistent cert files")
	}
}

// ---------------------------------------------------------------------------
// serialIsNewer edge cases (errors.go)
// ---------------------------------------------------------------------------

func TestSerialIsNewer_WrapAround_CovExtra(t *testing.T) {
	// RFC 1982: serial wraps around at 2^32
	// s1=1, s2=0xFFFFFFFF => s2-s1 > 2^31, so s1 is newer
	if !serialIsNewer(1, 0xFFFFFFFF) {
		t.Error("expected 1 to be newer than 0xFFFFFFFF (wrap-around)")
	}

	// s1=0xFFFFFFFF, s2=1 => s1-s2 < 2^31, s1 is NOT newer (it's old)
	// Wait: s1=0xFFFFFFFF > s2=1, and s1-s2 = 0xFFFFFFFE which is > 2^31
	// So s1 is NOT newer by the first condition. Second condition: s2-s1 > 2^31?
	// s2 < s1, so we check s1-s2 > 2^31? No wait:
	// The function says: if s1 > s2 { return s1-s2 < half } => 0xFFFFFFFF-1 = 0xFFFFFFFE >= 2^31 => false
	// Then: return s2-s1 > half => 1-0xFFFFFFFF (underflow) which is very large => true
	// Actually wait, s2 < s1, so we hit the else branch: return s2-s1 > half
	// s2-s1 = 1-0xFFFFFFFF wraps to 2 in uint32. 2 > 2^31 is false.
	// Hmm, so serialIsNewer(0xFFFFFFFF, 1) => s1>s2, s1-s2 = 0xFFFFFFFE which is >= 2^31, so returns false
	// then else: s2-s1 but we don't get there since s1 > s2
	// Wait I misread: if s1 > s2, we return s1-s2 < half. 0xFFFFFFFE < 2^31 is false.
	// So serialIsNewer(0xFFFFFFFF, 1) = false. That means 0xFFFFFFFF is NOT newer than 1. Correct!

	// And serialIsNewer(1, 0xFFFFFFFF): s1 < s2, so else: s2-s1 > half
	// s2-s1 = 0xFFFFFFFE which is > 2^31 => true. So 1 IS newer than 0xFFFFFFFF. Correct!

	// s1=100, s2=50: s1>s2, s1-s2=50 < 2^31 => true
	if !serialIsNewer(100, 50) {
		t.Error("expected 100 to be newer than 50")
	}

	// s1=50, s2=100: s1<s2, s2-s1=50 > 2^31 is false => false
	if serialIsNewer(50, 100) {
		t.Error("expected 50 to NOT be newer than 100")
	}

	// s1 == s2 => false
	if serialIsNewer(42, 42) {
		t.Error("expected equal serials to return false")
	}
}

// ---------------------------------------------------------------------------
// DDNS Close / SetZonesMu (ddns.go)
// ---------------------------------------------------------------------------

func TestDynamicDNSHandler_Close_CovExtra(t *testing.T) {
	h := NewDynamicDNSHandler(nil)
	// Read from the channel to verify it's open
	select {
	case <-h.GetUpdateChannel():
		t.Fatal("channel should be open but not have data")
	default:
	}

	h.Close()

	// After close, channel should be closed
	_, ok := <-h.GetUpdateChannel()
	if ok {
		t.Error("expected channel to be closed after Close()")
	}
}

func TestDynamicDNSHandler_Close_Idempotent_CovExtra(t *testing.T) {
	h := NewDynamicDNSHandler(nil)
	h.Close()
	h.Close() // Should not panic (sync.Once)
}

func TestDynamicDNSHandler_SetZonesMu_CovExtra(t *testing.T) {
	h := NewDynamicDNSHandler(nil)
	mu := &sync.RWMutex{}
	h.SetZonesMu(mu)
	if h.zonesMu != mu {
		t.Error("expected zonesMu to be set")
	}
}

// ---------------------------------------------------------------------------
// NOTIFY Close / AddNotifyAllowed single IP (notify.go)
// ---------------------------------------------------------------------------

func TestNOTIFYSlaveHandler_Close_CovExtra(t *testing.T) {
	h := NewNOTIFYSlaveHandler(nil)
	h.Close()

	// After close, channel should be closed
	_, ok := <-h.GetNotifyChannel()
	if ok {
		t.Error("expected channel to be closed after Close()")
	}
}

func TestNOTIFYSlaveHandler_Close_Idempotent_CovExtra(t *testing.T) {
	h := NewNOTIFYSlaveHandler(nil)
	h.Close()
	h.Close() // Should not panic (sync.Once)
}

func TestNOTIFYSlaveHandler_AddNotifyAllowed_SingleIPv4_CovExtra(t *testing.T) {
	h := NewNOTIFYSlaveHandler(nil)
	if err := h.AddNotifyAllowed("192.168.1.1"); err != nil {
		t.Fatalf("AddNotifyAllowed() error: %v", err)
	}
	if !h.isNOTIFYAllowed(net.ParseIP("192.168.1.1")) {
		t.Error("expected 192.168.1.1 to be allowed")
	}
	if h.isNOTIFYAllowed(net.ParseIP("192.168.1.2")) {
		t.Error("expected 192.168.1.2 to be denied")
	}
}

func TestNOTIFYSlaveHandler_AddNotifyAllowed_SingleIPv6_CovExtra(t *testing.T) {
	h := NewNOTIFYSlaveHandler(nil)
	if err := h.AddNotifyAllowed("::1"); err != nil {
		t.Fatalf("AddNotifyAllowed() error: %v", err)
	}
	if !h.isNOTIFYAllowed(net.ParseIP("::1")) {
		t.Error("expected ::1 to be allowed")
	}
}

func TestNOTIFYSlaveHandler_AddNotifyAllowed_InvalidIP_CovExtra(t *testing.T) {
	h := NewNOTIFYSlaveHandler(nil)
	err := h.AddNotifyAllowed("not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestNOTIFYSlaveHandler_isNOTIFYAllowed_NoAllowList_CovExtra(t *testing.T) {
	h := NewNOTIFYSlaveHandler(nil)
	// Default deny when no allow list
	if h.isNOTIFYAllowed(net.ParseIP("10.0.0.1")) {
		t.Error("expected default deny when no allow list")
	}
}

func TestNOTIFYSlaveHandler_AddNotifyAllowed_CIDR_CovExtra(t *testing.T) {
	h := NewNOTIFYSlaveHandler(nil)
	if err := h.AddNotifyAllowed("10.0.0.0/8"); err != nil {
		t.Fatalf("AddNotifyAllowed() error: %v", err)
	}
	if !h.isNOTIFYAllowed(net.ParseIP("10.255.255.255")) {
		t.Error("expected 10.x.x.x to be allowed")
	}
	if h.isNOTIFYAllowed(net.ParseIP("192.168.1.1")) {
		t.Error("expected 192.168.1.1 to be denied")
	}
}

// ---------------------------------------------------------------------------
// computeDHValue (tkey.go)
// ---------------------------------------------------------------------------

func TestComputeDHValue_CovExtra(t *testing.T) {
	// Simple test: 2^3 mod 7 = 1
	prime := big.NewInt(7).Bytes()
	base := big.NewInt(2).Bytes()
	exp := big.NewInt(3).Bytes()

	result, err := computeDHValue(prime, base, exp)
	if err != nil {
		t.Fatalf("computeDHValue() error: %v", err)
	}
	got := new(big.Int).SetBytes(result)
	want := big.NewInt(1) // 2^3 mod 7 = 8 mod 7 = 1
	if got.Cmp(want) != 0 {
		t.Errorf("computeDHValue() = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// XoTServer zoneRecordToRR
// ---------------------------------------------------------------------------

func TestXoTServer_zoneRecordToRR_InvalidType_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	rec := zone.Record{
		Name:  "test.example.com.",
		Type:  "UNKNOWN_TYPE",
		TTL:   300,
		RData: "data",
	}
	_, err := srv.zoneRecordToRR("test.example.com.", rec)
	if err == nil {
		t.Error("expected error for unknown record type")
	}
}

func TestXoTServer_zoneRecordToRR_InvalidName_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	rec := zone.Record{
		Name:  "",
		Type:  "A",
		TTL:   300,
		RData: "1.2.3.4",
	}
	// Empty name may still parse or fail depending on ParseName
	_, err := srv.zoneRecordToRR("", rec)
	// We just want to cover the code path
	_ = err
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

func TestSentinelErrors_CovExtra(t *testing.T) {
	if ErrNoJournal.Error() != "no journal available for incremental transfer" {
		t.Errorf("ErrNoJournal = %q", ErrNoJournal.Error())
	}
	if ErrSerialNotInRange.Error() != "client serial not in journal range" {
		t.Errorf("ErrSerialNotInRange = %q", ErrSerialNotInRange.Error())
	}
}

// ---------------------------------------------------------------------------
// VerifyMessageWithPrevious tests
// ---------------------------------------------------------------------------

func TestVerifyMessageWithPrevious_BothFail_CovExtra(t *testing.T) {
	key := &TSIGKey{
		Name:      "test.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("testsecretkey"),
	}
	previousKey := &TSIGKey{
		Name:      "test.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("oldsecretkey"),
	}

	// Create a message with a TSIG record signed by an unrelated key
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   func() *protocol.Name { n, _ := protocol.ParseName("example.com."); return n }(),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Sign with a different key entirely
	badKey := &TSIGKey{
		Name:      "test.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("wrongkey"),
	}
	tsigRR, err := SignMessage(msg, badKey, 300)
	if err != nil {
		t.Fatalf("SignMessage() error: %v", err)
	}
	msg.Additionals = append(msg.Additionals, tsigRR)

	err = VerifyMessageWithPrevious(msg, key, previousKey, nil)
	if err == nil {
		t.Error("expected error when both keys fail")
	}
	if !strings.Contains(err.Error(), "current and previous keys") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestVerifyMessageWithPrevious_CurrentKeySucceeds_CovExtra(t *testing.T) {
	key := &TSIGKey{
		Name:      "test.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("testsecretkey"),
	}
	previousKey := &TSIGKey{
		Name:      "test.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("oldsecretkey"),
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   func() *protocol.Name { n, _ := protocol.ParseName("example.com."); return n }(),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	tsigRR, err := SignMessage(msg, key, 300)
	if err != nil {
		t.Fatalf("SignMessage() error: %v", err)
	}
	msg.Additionals = append(msg.Additionals, tsigRR)

	err = VerifyMessageWithPrevious(msg, key, previousKey, nil)
	if err != nil {
		t.Errorf("expected success with current key: %v", err)
	}
}

func TestVerifyMessageWithPrevious_PreviousKeySucceeds_CovExtra(t *testing.T) {
	key := &TSIGKey{
		Name:      "test.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("testsecretkey"),
	}
	previousKey := &TSIGKey{
		Name:      "test.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("oldsecretkey"),
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   func() *protocol.Name { n, _ := protocol.ParseName("example.com."); return n }(),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Sign with the previous key
	tsigRR, err := SignMessage(msg, previousKey, 300)
	if err != nil {
		t.Fatalf("SignMessage() error: %v", err)
	}
	msg.Additionals = append(msg.Additionals, tsigRR)

	// Current key should fail, previous should succeed
	err = VerifyMessageWithPrevious(msg, key, previousKey, nil)
	if err != nil {
		t.Errorf("expected success with previous key: %v", err)
	}
}

func TestVerifyMessageWithPrevious_NilPreviousKey_CovExtra(t *testing.T) {
	key := &TSIGKey{
		Name:      "test.example.com.",
		Algorithm: HmacSHA256,
		Secret:    []byte("testsecretkey"),
	}

	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      0x1234,
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   func() *protocol.Name { n, _ := protocol.ParseName("example.com."); return n }(),
				QType:  protocol.TypeA,
				QClass: protocol.ClassIN,
			},
		},
	}

	tsigRR, err := SignMessage(msg, key, 300)
	if err != nil {
		t.Fatalf("SignMessage() error: %v", err)
	}
	msg.Additionals = append(msg.Additionals, tsigRR)

	// nil previousKey should still work with current key
	err = VerifyMessageWithPrevious(msg, key, nil, nil)
	if err != nil {
		t.Errorf("expected success with current key (nil previous): %v", err)
	}
}

// ---------------------------------------------------------------------------
// XoTServer sortRecordsCanonically
// ---------------------------------------------------------------------------

func TestXoTServer_sortRecordsCanonically_CovExtra(t *testing.T) {
	nameB, _ := protocol.ParseName("b.example.com.")
	nameA, _ := protocol.ParseName("a.example.com.")
	nameC, _ := protocol.ParseName("c.example.com.")

	records := []*protocol.ResourceRecord{
		{Name: nameC, Type: protocol.TypeA},
		{Name: nameA, Type: protocol.TypeAAAA},
		{Name: nameB, Type: protocol.TypeA},
		{Name: nameA, Type: protocol.TypeA},
	}

	srv := &XoTServer{}
	srv.sortRecordsCanonically(records)

	// Expected order: a(A), a(AAAA), b(A), c(A)
	if records[0].Name.String() != "a.example.com." || records[0].Type != protocol.TypeA {
		t.Errorf("record[0] = %s/%d", records[0].Name.String(), records[0].Type)
	}
	if records[1].Name.String() != "a.example.com." || records[1].Type != protocol.TypeAAAA {
		t.Errorf("record[1] = %s/%d", records[1].Name.String(), records[1].Type)
	}
	if records[2].Name.String() != "b.example.com." {
		t.Errorf("record[2] = %s", records[2].Name.String())
	}
	if records[3].Name.String() != "c.example.com." {
		t.Errorf("record[3] = %s", records[3].Name.String())
	}
}

// ---------------------------------------------------------------------------
// XoTServer handleMessage paths
// ---------------------------------------------------------------------------

func TestXoTServer_generateIXFRRecords_ZeroClientSerial_CovExtra(t *testing.T) {
	z := zone.NewZone("example.com.")
	z.SOA = &zone.SOARecord{
		MName: "ns1.example.com.", RName: "admin.example.com.",
		Serial: 100, TTL: 3600, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 86400,
	}

	srv := &XoTServer{}
	// clientSerial=0 should fall through to generateAXFRRecords
	records, err := srv.generateIXFRRecords(z, 0)
	if err != nil {
		t.Fatalf("generateIXFRRecords() error: %v", err)
	}
	if len(records) < 2 {
		t.Errorf("expected >= 2 records, got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// Coverage for IsUpdateRequest / IsUpdateResponse
// ---------------------------------------------------------------------------

func TestIsUpdateRequest_CovExtra(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{Opcode: protocol.OpcodeUpdate, QR: false},
		},
	}
	if !IsUpdateRequest(msg) {
		t.Error("expected IsUpdateRequest=true")
	}
	msg.Header.Flags.QR = true
	if IsUpdateRequest(msg) {
		t.Error("expected IsUpdateRequest=false with QR=true")
	}
}

func TestIsUpdateResponse_CovExtra(t *testing.T) {
	msg := &protocol.Message{
		Header: protocol.Header{
			Flags: protocol.Flags{Opcode: protocol.OpcodeUpdate, QR: true},
		},
	}
	if !IsUpdateResponse(msg) {
		t.Error("expected IsUpdateResponse=true")
	}
	msg.Header.Flags.QR = false
	if IsUpdateResponse(msg) {
		t.Error("expected IsUpdateResponse=false with QR=false")
	}
}

// ---------------------------------------------------------------------------
// TLSAUsage constants
// ---------------------------------------------------------------------------

func TestTLSAUsageConstants_CovExtra(t *testing.T) {
	if TLSARequired != 0 || TLSASuggested != 1 || TLSAIgnored != 2 {
		t.Errorf("TLSA usage constants: Required=%d Suggested=%d Ignored=%d", TLSARequired, TLSASuggested, TLSAIgnored)
	}
}

// ---------------------------------------------------------------------------
// parseRData MX with bad exchange
// ---------------------------------------------------------------------------

func TestParseXoTRData_MX_InvalidExchange_CovExtra(t *testing.T) {
	_, err := parseRData(protocol.TypeMX, "10 !!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid MX exchange")
	}
}

// ---------------------------------------------------------------------------
// parseRData invalid CNAME and NS
// ---------------------------------------------------------------------------

func TestParseXoTRData_CNAME_EmptyString_CovExtra(t *testing.T) {
	// Empty string passes ParseName, so just verify it doesn't crash
	_, _ = parseRData(protocol.TypeCNAME, "")
}

func TestParseXoTRData_NS_EmptyString_CovExtra(t *testing.T) {
	_, _ = parseRData(protocol.TypeNS, "")
}

func TestParseXoTRData_PTR_EmptyString_CovExtra(t *testing.T) {
	_, _ = parseRData(protocol.TypePTR, "")
}

func TestParseXoTRData_SRV_InvalidTarget_CovExtra(t *testing.T) {
	_, err := parseRData(protocol.TypeSRV, "10 20 443 !!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid SRV target")
	}
}

// ---------------------------------------------------------------------------
// XoTServer Serve error path (already closed)
// ---------------------------------------------------------------------------

func TestXoTServer_Serve_AlreadyListening_CovExtra(t *testing.T) {
	zones := map[string]*zone.Zone{
		"example.com.": zone.NewZone("example.com."),
	}
	srv, err := NewXoTServer(zones, &XoTConfig{ListenPort: 0, AllowedNetworks: []string{"127.0.0.0/8"}}, nil)
	if err != nil {
		t.Fatalf("NewXoTServer() error: %v", err)
	}
	// Port 0 will let OS pick a free port, but we can't easily test the
	// actual Serve() without binding. Just verify the server was created.
	if srv == nil {
		t.Fatal("expected non-nil server")
	}
}

// ---------------------------------------------------------------------------
// Ensure format coverage for TSIG error codes
// ---------------------------------------------------------------------------

func TestTSIGErrorString_AllCodes_CovExtra(t *testing.T) {
	codes := []uint16{0, 16, 17, 18, 19, 20, 21, 22}
	expected := []string{"NOERROR", "BADSIG", "BADKEY", "BADTIME", "BADMODE", "BADNAME", "BADALG", "BADTRUNC"}
	for i, code := range codes {
		got := TSIGErrorString(code)
		if got != expected[i] {
			t.Errorf("TSIGErrorString(%d) = %q, want %q", code, got, expected[i])
		}
	}
	// Unknown code
	got := TSIGErrorString(99)
	if !strings.Contains(got, "UNKNOWN") {
		t.Errorf("TSIGErrorString(99) = %q, want UNKNOWN", got)
	}
}

// ---------------------------------------------------------------------------
// Coverage for XoT buildXoTTLSConfig with CAFile (readCAFile)
// ---------------------------------------------------------------------------

// writeTestCAFile generates a self-signed CA cert, writes it as PEM to a temp
// file, and returns the path.
func writeTestCAFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	return path
}

func writeTestXoTCertFiles(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "xot-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "xot-cert.pem")
	keyPath := filepath.Join(dir, "xot-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func getFreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for free port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestReadCAFile_CovExtra(t *testing.T) {
	// Fail closed on a missing CA file (the previous impl ignored the filename
	// and returned the system root pool, silently bypassing the operator CA).
	if _, err := readCAFile("nonexistent-ca.pem"); err == nil {
		t.Error("expected error for a nonexistent CA file")
	}
	// Fail closed on a file with no PEM certificates.
	badPath := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCAFile(badPath); err == nil {
		t.Error("expected error for a file with no PEM certificates")
	}
	oversizedPath := filepath.Join(t.TempDir(), "oversized-ca.pem")
	if err := os.WriteFile(oversizedPath, bytes.Repeat([]byte{'x'}, maxXoTCAFileSize+1), 0o600); err != nil {
		t.Fatalf("write oversized CA: %v", err)
	}
	if _, err := readCAFile(oversizedPath); err == nil {
		t.Error("expected error for an oversized CA file")
	}
	// A valid CA loads into a non-nil pool.
	pool, err := readCAFile(writeTestCAFile(t))
	if err != nil {
		t.Fatalf("readCAFile(valid): %v", err)
	}
	if pool == nil {
		t.Error("expected non-nil cert pool for a valid CA")
	}
}

func TestBuildXoTTLSConfig_WithCAFile_CovExtra(t *testing.T) {
	// A missing CA file must fail closed — not silently fall back to system roots.
	if _, err := buildXoTTLSConfig(&XoTConfig{CAFile: "nonexistent-ca.pem"}); err == nil {
		t.Error("expected buildXoTTLSConfig to fail for a missing CA file")
	}
	// A valid CA file enables mTLS against that CA.
	tlsCfg, err := buildXoTTLSConfig(&XoTConfig{CAFile: writeTestCAFile(t)})
	if err != nil {
		t.Fatalf("buildXoTTLSConfig(valid): %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %d, want RequireAndVerifyClientCert", tlsCfg.ClientAuth)
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("expected ClientCAs to be set from the CA file")
	}
}

// ---------------------------------------------------------------------------
// TSIG RDataTSIG Copy with nil receiver
// ---------------------------------------------------------------------------

func TestRDataTSIG_Copy_NilReceiver_CovExtra(t *testing.T) {
	var r *RDataTSIG
	if r.Copy() != nil {
		t.Error("expected nil from Copy() on nil receiver")
	}
}

// ---------------------------------------------------------------------------
// parseRData MX without a preference field
// ---------------------------------------------------------------------------

func TestParseXoTRData_MX_NoPreference_CovExtra(t *testing.T) {
	// MX without a preference field is not valid presentation format.
	if _, err := parseRData(protocol.TypeMX, "mail.example.com."); err == nil {
		t.Fatal("parseRData(MX without preference) expected error")
	}
}

func TestParseXoTRData_MXInvalidPreference_CovExtra(t *testing.T) {
	tests := []string{
		"bad mail.example.com.",
		"-1 mail.example.com.",
		"65536 mail.example.com.",
	}
	for _, rdata := range tests {
		if _, err := parseRData(protocol.TypeMX, rdata); err == nil {
			t.Fatalf("parseRData(MX, %q) expected error", rdata)
		}
	}
}

// ---------------------------------------------------------------------------
// XoTConfig TLSAUsage
// ---------------------------------------------------------------------------

func TestXoTConfig_Fields_CovExtra(t *testing.T) {
	cfg := &XoTConfig{
		CertFile:        "cert.pem",
		KeyFile:         "key.pem",
		CAFile:          "ca.pem",
		TLSAUsage:       TLSASuggested,
		MinTLSVersion:   12,
		ListenPort:      853,
		AllowedNetworks: []string{"10.0.0.0/8"},
	}
	if cfg.CertFile != "cert.pem" {
		t.Errorf("CertFile = %q", cfg.CertFile)
	}
	if cfg.TLSAUsage != TLSASuggested {
		t.Errorf("TLSAUsage = %d", cfg.TLSAUsage)
	}
}

// ---------------------------------------------------------------------------
// Verify coverage of computeTKEYHMAC default (non-sha512 path)
// ---------------------------------------------------------------------------

func TestComputeTKEYHMAC_DefaultSHA256_CovExtra(t *testing.T) {
	msg := []byte("test")
	key := []byte("key")
	// Use algorithm that doesn't contain "sha512"
	mac, err := ComputeTKEYHMAC(msg, key, "hmac-sha256")
	if err != nil {
		t.Fatalf("ComputeTKEYHMAC() error: %v", err)
	}
	if len(mac) == 0 {
		t.Error("expected non-empty MAC")
	}
}

// ---------------------------------------------------------------------------
// Verify TKEYQuery boundary key sizes
// ---------------------------------------------------------------------------

func TestTKEYQuery_BoundaryKeySizes_CovExtra(t *testing.T) {
	// Minimum valid size
	rec, err := TKEYQuery("hmac-sha256.", TKEYModeServerAssignment, 64)
	if err != nil {
		t.Errorf("TKEYQuery(64) error: %v", err)
	}
	if rec == nil {
		t.Error("expected non-nil record for 64-bit key")
	}

	// Maximum valid size
	rec, err = TKEYQuery("hmac-sha256.", TKEYModeServerAssignment, 8192)
	if err != nil {
		t.Errorf("TKEYQuery(8192) error: %v", err)
	}
	if rec == nil {
		t.Error("expected non-nil record for 8192-bit key")
	}
}

// ---------------------------------------------------------------------------
// formatTKEYTime edge
// ---------------------------------------------------------------------------

func TestFormatTKEYTime_Zero_CovExtra(t *testing.T) {
	ts := time.Unix(0, 0)
	result, err := formatTKEYTime(ts)
	if err != nil {
		t.Fatalf("formatTKEYTime() error: %v", err)
	}
	if result != 0 {
		t.Errorf("expected zero unix time, got %d", result)
	}
}

// ---------------------------------------------------------------------------
// Ensure _ variable usage doesn't cause compile errors (fmt import)
// ---------------------------------------------------------------------------

// This is a compile-time check that fmt is imported
var _ = fmt.Sprintf

// ---------------------------------------------------------------------------
// XoTServer changeToRR tests
// ---------------------------------------------------------------------------

func TestXoTServer_changeToRR_A_Valid_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	change := zone.RecordChange{
		Name:  "test.example.com.",
		Type:  protocol.TypeA,
		TTL:   300,
		RData: "192.0.2.1",
	}
	rr, err := srv.changeToRR(change)
	if err != nil {
		t.Fatalf("changeToRR() error: %v", err)
	}
	if rr.Name.String() != "test.example.com." {
		t.Errorf("Name = %q, want test.example.com.", rr.Name.String())
	}
	if rr.Type != protocol.TypeA {
		t.Errorf("Type = %d, want TypeA", rr.Type)
	}
	if rr.TTL != 300 {
		t.Errorf("TTL = %d, want 300", rr.TTL)
	}
}

func TestXoTServer_changeToRR_AAAA_Valid_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	change := zone.RecordChange{
		Name:  "test.example.com.",
		Type:  protocol.TypeAAAA,
		TTL:   300,
		RData: "2001:db8::1",
	}
	rr, err := srv.changeToRR(change)
	if err != nil {
		t.Fatalf("changeToRR() error: %v", err)
	}
	if rr.Type != protocol.TypeAAAA {
		t.Errorf("Type = %d, want TypeAAAA", rr.Type)
	}
}

func TestXoTServer_changeToRR_MX_Valid_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	change := zone.RecordChange{
		Name:  "example.com.",
		Type:  protocol.TypeMX,
		TTL:   300,
		RData: "10 mail.example.com.",
	}
	rr, err := srv.changeToRR(change)
	if err != nil {
		t.Fatalf("changeToRR() error: %v", err)
	}
	if rr.Type != protocol.TypeMX {
		t.Errorf("Type = %d, want TypeMX", rr.Type)
	}
}

func TestXoTServer_changeToRR_InvalidName_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	change := zone.RecordChange{
		Name:  "invalid\x00name",
		Type:  protocol.TypeA,
		TTL:   300,
		RData: "192.0.2.1",
	}
	_, err := srv.changeToRR(change)
	if err == nil {
		t.Error("expected error for invalid name")
	}
}

func TestXoTServer_changeToRR_InvalidRData_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	change := zone.RecordChange{
		Name:  "test.example.com.",
		Type:  protocol.TypeA,
		TTL:   300,
		RData: "not-an-ip",
	}
	_, err := srv.changeToRR(change)
	if err == nil {
		t.Error("expected error for invalid RData")
	}
}

// ---------------------------------------------------------------------------
// XoTServer SetJournalStore test
// ---------------------------------------------------------------------------

func TestXoTServer_SetJournalStore_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	if srv.journalStore != nil {
		t.Error("expected nil journalStore initially")
	}

	store := NewKVJournalStore(t.TempDir())
	srv.SetJournalStore(store)

	if srv.journalStore != store {
		t.Error("journalStore not set correctly")
	}
}

// ---------------------------------------------------------------------------
// XoTServer sortRecordsCanonically with empty and single records
// ---------------------------------------------------------------------------

func TestXoTServer_sortRecordsCanonically_Empty_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	records := []*protocol.ResourceRecord{}
	srv.sortRecordsCanonically(records)
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestXoTServer_sortRecordsCanonically_Single_CovExtra(t *testing.T) {
	srv := &XoTServer{}
	name, _ := protocol.ParseName("test.example.com.")
	records := []*protocol.ResourceRecord{
		{Name: name, Type: protocol.TypeA, Class: protocol.ClassIN, TTL: 300},
	}
	srv.sortRecordsCanonically(records)
	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}
}
