package transfer

import (
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/zone"
)

func TestEncodeDecodeJournalEntry(t *testing.T) {
	original := &IXFRJournalEntry{
		Serial:    2024010102,
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Added: []zone.RecordChange{
			{Name: "www.example.com.", Type: 1, TTL: 300, RData: "10.0.0.1"},
			{Name: "mail.example.com.", Type: 1, TTL: 3600, RData: "10.0.0.2"},
		},
		Deleted: []zone.RecordChange{
			{Name: "old.example.com.", Type: 1, TTL: 300, RData: "10.0.0.99"},
		},
	}

	encoded := EncodeJournalEntry(original)
	decoded, err := DecodeJournalEntry(encoded)
	if err != nil {
		t.Fatalf("DecodeJournalEntry: %v", err)
	}

	if decoded.Serial != original.Serial {
		t.Errorf("Serial = %d, want %d", decoded.Serial, original.Serial)
	}
	if decoded.Timestamp.Unix() != original.Timestamp.Unix() {
		t.Errorf("Timestamp = %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if len(decoded.Added) != 2 {
		t.Fatalf("Added count = %d, want 2", len(decoded.Added))
	}
	if decoded.Added[0].Name != "www.example.com." || decoded.Added[0].RData != "10.0.0.1" {
		t.Errorf("Added[0] = %+v, want www.example.com. 10.0.0.1", decoded.Added[0])
	}
	if decoded.Added[1].Name != "mail.example.com." {
		t.Errorf("Added[1].Name = %q, want mail.example.com.", decoded.Added[1].Name)
	}
	if len(decoded.Deleted) != 1 {
		t.Fatalf("Deleted count = %d, want 1", len(decoded.Deleted))
	}
	if decoded.Deleted[0].Name != "old.example.com." || decoded.Deleted[0].RData != "10.0.0.99" {
		t.Errorf("Deleted[0] = %+v, want old.example.com. 10.0.0.99", decoded.Deleted[0])
	}
}

func TestEncodeDecodeJournalEntryEmpty(t *testing.T) {
	original := &IXFRJournalEntry{
		Serial:    1,
		Timestamp: time.Now(),
		Added:     nil,
		Deleted:   nil,
	}

	encoded := EncodeJournalEntry(original)
	decoded, err := DecodeJournalEntry(encoded)
	if err != nil {
		t.Fatalf("DecodeJournalEntry: %v", err)
	}

	if decoded.Serial != 1 {
		t.Errorf("Serial = %d, want 1", decoded.Serial)
	}
	if len(decoded.Added) != 0 {
		t.Errorf("Added count = %d, want 0", len(decoded.Added))
	}
	if len(decoded.Deleted) != 0 {
		t.Errorf("Deleted count = %d, want 0", len(decoded.Deleted))
	}
}

func TestDecodeJournalEntryTooShort(t *testing.T) {
	_, err := DecodeJournalEntry([]byte{0, 1, 2})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

func TestEncodeDecodeJournalEntryTypes(t *testing.T) {
	// Test with various record types
	original := &IXFRJournalEntry{
		Serial:    100,
		Timestamp: time.Now(),
		Added: []zone.RecordChange{
			{Name: "example.com.", Type: 1, TTL: 300, RData: "1.2.3.4"},    // A
			{Name: "example.com.", Type: 28, TTL: 300, RData: "2001:db8::1"}, // AAAA
			{Name: "example.com.", Type: 15, TTL: 300, RData: "10 mail.example.com."}, // MX
			{Name: "example.com.", Type: 16, TTL: 300, RData: "v=spf1 include:example.com ~all"}, // TXT
		},
		Deleted: nil,
	}

	encoded := EncodeJournalEntry(original)
	decoded, err := DecodeJournalEntry(encoded)
	if err != nil {
		t.Fatalf("DecodeJournalEntry: %v", err)
	}

	if len(decoded.Added) != 4 {
		t.Fatalf("Added count = %d, want 4", len(decoded.Added))
	}

	for i, got := range decoded.Added {
		want := original.Added[i]
		if got.Name != want.Name || got.Type != want.Type || got.TTL != want.TTL || got.RData != want.RData {
			t.Errorf("Added[%d] = %+v, want %+v", i, got, want)
		}
	}
}
