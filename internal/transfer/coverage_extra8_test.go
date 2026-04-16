package transfer

import (
	"bytes"
	"sync"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
	"github.com/nothingdns/nothingdns/internal/zone"
)

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
	s.SetZonesMu(nil)

	if s.zonesMu != nil {
		t.Error("expected zonesMu to be nil after SetZonesMu(nil)")
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

	rr, err := s.createZONEMDRR(zonemd, origin)
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

	rr, err := s.createZONEMDRR(zonemd, origin)
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
