package storage

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

func newTestZoneStore(t *testing.T) (*ZoneStore, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "zonestore-test-*")
	if err != nil {
		t.Fatal(err)
	}
	kv, err := OpenKVStore(dir)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatal(err)
	}
	cleanup := func() {
		kv.Close()
		os.RemoveAll(dir)
	}
	return NewZoneStore(kv), cleanup
}

func TestZoneStoreSaveAndLoad(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	meta := ZoneMeta{Origin: "example.com.", DefaultTTL: 3600}
	records := map[string][]StoredRecord{
		"www.example.com.": {
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "93.184.216.34"},
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "AAAA", RData: "2606:2800:220:1:248:1893:25c8:1946"},
		},
		"mail.example.com.": {
			{Name: "mail.example.com.", TTL: 3600, Class: "IN", Type: "A", RData: "10.0.0.1"},
		},
	}

	if err := zs.SaveZone("example.com.", meta, records); err != nil {
		t.Fatalf("SaveZone: %v", err)
	}

	loadedMeta, loadedRecords, err := zs.LoadZone("example.com.")
	if err != nil {
		t.Fatalf("LoadZone: %v", err)
	}

	if loadedMeta.Origin != "example.com." {
		t.Errorf("origin = %q, want example.com.", loadedMeta.Origin)
	}
	if loadedMeta.DefaultTTL != 3600 {
		t.Errorf("defaultTTL = %d, want 3600", loadedMeta.DefaultTTL)
	}

	wwwRecs := loadedRecords["www.example.com."]
	if len(wwwRecs) != 2 {
		t.Fatalf("www records count = %d, want 2", len(wwwRecs))
	}
	if wwwRecs[0].RData != "93.184.216.34" {
		t.Errorf("www A record = %q, want 93.184.216.34", wwwRecs[0].RData)
	}

	mailRecs := loadedRecords["mail.example.com."]
	if len(mailRecs) != 1 {
		t.Fatalf("mail records count = %d, want 1", len(mailRecs))
	}
}

func TestZoneStoreSaveZoneReplacesExistingBucket(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	meta := ZoneMeta{Origin: "example.com.", DefaultTTL: 3600}
	if err := zs.SaveZone("example.com.", meta, map[string][]StoredRecord{
		"old.example.com.": {
			{Name: "old.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
		},
	}); err != nil {
		t.Fatalf("initial SaveZone: %v", err)
	}

	if err := zs.SaveZone("example.com.", meta, map[string][]StoredRecord{
		"new.example.com.": {
			{Name: "new.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.2"},
		},
	}); err != nil {
		t.Fatalf("replacement SaveZone: %v", err)
	}

	_, records, err := zs.LoadZone("example.com.")
	if err != nil {
		t.Fatalf("LoadZone: %v", err)
	}
	if _, ok := records["old.example.com."]; ok {
		t.Fatal("replacement SaveZone left stale records from old zone bucket")
	}
	if recs := records["new.example.com."]; len(recs) != 1 || recs[0].RData != "192.0.2.2" {
		t.Fatalf("new records = %+v, want replacement A record", recs)
	}
}

func TestDeleteExistingZoneBucketPropagatesUnexpectedError(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	if err := zs.kv.Update(func(tx *Tx) error {
		zones, err := tx.CreateBucket([]byte("zones"))
		if err != nil {
			return err
		}
		_, err = zones.CreateBucket([]byte("example.com."))
		return err
	}); err != nil {
		t.Fatalf("create zones fixture: %v", err)
	}

	err := zs.kv.View(func(tx *Tx) error {
		zones := tx.Bucket([]byte("zones"))
		return deleteExistingZoneBucket(zones, "example.com.")
	})
	if err == nil {
		t.Fatal("deleteExistingZoneBucket should propagate read-only delete error")
	}
	if !strings.Contains(err.Error(), "delete existing zone bucket example.com.") {
		t.Fatalf("error should include zone delete context, got: %v", err)
	}
	if !errors.Is(err, ErrTxNotWritable) {
		t.Fatalf("error should wrap ErrTxNotWritable, got: %v", err)
	}
}

func TestZoneStoreLoadNotFound(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	_, _, err := zs.LoadZone("nonexistent.com.")
	if err != ErrZoneNotFound {
		t.Errorf("expected ErrZoneNotFound, got %v", err)
	}
}

func TestZoneStoreDelete(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	meta := ZoneMeta{Origin: "example.com.", DefaultTTL: 3600}
	records := map[string][]StoredRecord{
		"www.example.com.": {
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		},
	}

	if err := zs.SaveZone("example.com.", meta, records); err != nil {
		t.Fatalf("SaveZone: %v", err)
	}

	if err := zs.DeleteZone("example.com."); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}

	_, _, err := zs.LoadZone("example.com.")
	if err != ErrZoneNotFound {
		t.Errorf("expected ErrZoneNotFound after delete, got %v", err)
	}
}

func TestZoneStoreListZones(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	// Save two zones
	for _, origin := range []string{"example.com.", "example.org."} {
		meta := ZoneMeta{Origin: origin, DefaultTTL: 3600}
		records := map[string][]StoredRecord{
			"www." + origin: {
				{Name: "www." + origin, TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
			},
		}
		if err := zs.SaveZone(origin, meta, records); err != nil {
			t.Fatalf("SaveZone(%s): %v", origin, err)
		}
	}

	zones, err := zs.ListZones()
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("zones count = %d, want 2", len(zones))
	}

	found := map[string]bool{}
	for _, z := range zones {
		found[z] = true
	}
	if !found["example.com."] || !found["example.org."] {
		t.Errorf("expected both zones, got %v", zones)
	}
}

func TestZoneStoreSaveRecords(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	// Create zone first
	meta := ZoneMeta{Origin: "example.com.", DefaultTTL: 3600}
	records := map[string][]StoredRecord{
		"www.example.com.": {
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "1.2.3.4"},
		},
	}
	if err := zs.SaveZone("example.com.", meta, records); err != nil {
		t.Fatalf("SaveZone: %v", err)
	}

	// Partial update: add a new record
	newRecs := []StoredRecord{
		{Name: "api.example.com.", TTL: 60, Class: "IN", Type: "A", RData: "10.0.0.1"},
	}
	if err := zs.SaveRecords("example.com.", "api.example.com.", newRecs); err != nil {
		t.Fatalf("SaveRecords: %v", err)
	}

	// Verify
	_, loaded, err := zs.LoadZone("example.com.")
	if err != nil {
		t.Fatalf("LoadZone: %v", err)
	}

	apiRecs := loaded["api.example.com."]
	if len(apiRecs) != 1 || apiRecs[0].RData != "10.0.0.1" {
		t.Errorf("api records = %+v, want 10.0.0.1", apiRecs)
	}

	// Original records should still be there
	wwwRecs := loaded["www.example.com."]
	if len(wwwRecs) != 1 || wwwRecs[0].RData != "1.2.3.4" {
		t.Errorf("www records = %+v, want 1.2.3.4", wwwRecs)
	}
}

func TestEncodeDecodeRecordsRoundTrip(t *testing.T) {
	original := []StoredRecord{
		{Name: "test.example.com.", TTL: 3600, Class: "IN", Type: "A", RData: "192.168.1.1"},
		{Name: "test.example.com.", TTL: 3600, Class: "IN", Type: "TXT", RData: "v=spf1 include:_spf.example.com ~all"},
	}

	encoded, err := encodeRecords(original)
	if err != nil {
		t.Fatalf("encodeRecords: %v", err)
	}
	decoded, err := decodeRecords(encoded)
	if err != nil {
		t.Fatalf("decodeRecords: %v", err)
	}

	if len(decoded) != len(original) {
		t.Fatalf("count = %d, want %d", len(decoded), len(original))
	}

	for i := range original {
		if decoded[i] != original[i] {
			t.Errorf("record[%d] = %+v, want %+v", i, decoded[i], original[i])
		}
	}
}

func TestEncodeRecordsRejectsOversizedFields(t *testing.T) {
	tests := []struct {
		name   string
		record StoredRecord
	}{
		{
			name:   "name",
			record: StoredRecord{Name: strings.Repeat("a", 0x10000), Class: "IN", Type: "TXT", RData: "ok"},
		},
		{
			name:   "class",
			record: StoredRecord{Name: "www.example.com.", Class: strings.Repeat("C", 0x100), Type: "TXT", RData: "ok"},
		},
		{
			name:   "type",
			record: StoredRecord{Name: "www.example.com.", Class: "IN", Type: strings.Repeat("T", 0x100), RData: "ok"},
		},
		{
			name:   "rdata",
			record: StoredRecord{Name: "www.example.com.", Class: "IN", Type: "TXT", RData: strings.Repeat("x", 0x10000)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := encodeRecords([]StoredRecord{tt.record}); err == nil {
				t.Fatal("encodeRecords accepted field that cannot be represented in the wire format")
			}
		})
	}
}

func TestZoneStoreSaveZoneRejectsOversizedRecord(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	meta := ZoneMeta{Origin: "example.com.", DefaultTTL: 3600}
	records := map[string][]StoredRecord{
		"www.example.com.": {
			{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: strings.Repeat("x", 0x10000)},
		},
	}

	if err := zs.SaveZone("example.com.", meta, records); err == nil {
		t.Fatal("SaveZone accepted an oversized record that would corrupt the stored zone")
	}
}

func TestDecodeRecordsRejectsTrailingData(t *testing.T) {
	encoded, err := encodeRecords([]StoredRecord{
		{Name: "www.example.com.", TTL: 300, Class: "IN", Type: "A", RData: "192.0.2.1"},
	})
	if err != nil {
		t.Fatalf("encodeRecords: %v", err)
	}
	encoded = append(encoded, 0xff)

	if _, err := decodeRecords(encoded); err == nil {
		t.Fatal("decodeRecords accepted trailing bytes after the declared records")
	}
}

func TestDecodeRecordsRejectsImpossibleRecordCountBeforeAllocation(t *testing.T) {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, maxStoredRecordsPerZone)

	if _, err := decodeRecords(data); err == nil {
		t.Fatal("decodeRecords accepted record count that cannot fit in data")
	} else if !strings.Contains(err.Error(), "data capacity") {
		t.Fatalf("decodeRecords error = %v, want data capacity error", err)
	}
}

func TestEncodeDecodeZoneMetaRoundTrip(t *testing.T) {
	original := ZoneMeta{Origin: "example.com.", DefaultTTL: 86400}

	encoded := encodeZoneMeta(original)
	decoded, err := decodeZoneMeta(encoded)
	if err != nil {
		t.Fatalf("decodeZoneMeta: %v", err)
	}

	if decoded != original {
		t.Errorf("decoded = %+v, want %+v", decoded, original)
	}
}

// Owner names starting with "_" (SRV, DMARC, DKIM, ACME challenges) were
// skipped as metadata keys on load, so they vanished after every restart.
func TestZoneStoreLoadKeepsUnderscoreOwnerNames(t *testing.T) {
	zs, cleanup := newTestZoneStore(t)
	defer cleanup()

	records := map[string][]StoredRecord{
		"_sip._tcp.example.com.": {
			{Name: "_sip._tcp.example.com.", TTL: 300, Class: "IN", Type: "SRV", RData: "10 5 5060 sip.example.com."},
		},
		"_dmarc.example.com.": {
			{Name: "_dmarc.example.com.", TTL: 300, Class: "IN", Type: "TXT", RData: `"v=DMARC1; p=reject"`},
		},
		"_acme-challenge.example.com.": {
			{Name: "_acme-challenge.example.com.", TTL: 60, Class: "IN", Type: "TXT", RData: `"token"`},
		},
	}
	if err := zs.SaveZone("example.com.", ZoneMeta{Origin: "example.com.", DefaultTTL: 3600}, records); err != nil {
		t.Fatalf("SaveZone: %v", err)
	}
	meta, loaded, err := zs.LoadZone("example.com.")
	if err != nil {
		t.Fatalf("LoadZone: %v", err)
	}
	if meta.Origin != "example.com." {
		t.Errorf("meta origin = %q", meta.Origin)
	}
	for name := range records {
		if len(loaded[name]) != 1 {
			t.Errorf("%s: loaded %d records, want 1", name, len(loaded[name]))
		}
	}
	if _, ok := loaded["_meta"]; ok {
		t.Error("metadata key must not be returned as a record set")
	}
}
