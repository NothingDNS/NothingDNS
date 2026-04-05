// Package transfer — JournalStore provides persistent IXFR journal storage.
//
// Journal entries are stored in a KVStore bucket per zone, keyed by serial
// number. This allows IXFR responses to be served even after server restarts.
package transfer

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// JournalStore abstracts the persistence backend for IXFR journals.
type JournalStore interface {
	SaveEntry(zoneName string, entry *IXFRJournalEntry) error
	LoadEntries(zoneName string) ([]*IXFRJournalEntry, error)
	Truncate(zoneName string, keepCount int) error
}

// JournalCodec handles serialization of journal entries.
// This is separate from the store so it can be used by any backend.

// EncodeJournalEntry serializes an IXFR journal entry to bytes.
// Format:
//
//	[4 serial][8 timestamp_unix]
//	[4 addedCount]  (for each: [2 nameLen][name][2 type][4 ttl][2 rdataLen][rdata])
//	[4 deletedCount](for each: same format)
func EncodeJournalEntry(entry *IXFRJournalEntry) []byte {
	// Calculate size
	size := 4 + 8 + 4 + 4 // serial + timestamp + addedCount + deletedCount
	for _, rc := range entry.Added {
		size += 2 + len(rc.Name) + 2 + 4 + 2 + len(rc.RData)
	}
	for _, rc := range entry.Deleted {
		size += 2 + len(rc.Name) + 2 + 4 + 2 + len(rc.RData)
	}

	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], entry.Serial)
	offset += 4

	binary.BigEndian.PutUint64(buf[offset:], uint64(entry.Timestamp.Unix()))
	offset += 8

	offset = encodeRecordChanges(buf, offset, entry.Added)
	encodeRecordChanges(buf, offset, entry.Deleted)

	return buf
}

// DecodeJournalEntry deserializes an IXFR journal entry from bytes.
func DecodeJournalEntry(data []byte) (*IXFRJournalEntry, error) {
	if len(data) < 16 { // minimum: serial(4) + timestamp(8) + counts(4+4)
		return nil, fmt.Errorf("journal entry too short: %d bytes", len(data))
	}

	entry := &IXFRJournalEntry{}
	offset := 0

	entry.Serial = binary.BigEndian.Uint32(data[offset:])
	offset += 4

	ts := int64(binary.BigEndian.Uint64(data[offset:]))
	entry.Timestamp = time.Unix(ts, 0)
	offset += 8

	var err error
	entry.Added, offset, err = decodeRecordChanges(data, offset)
	if err != nil {
		return nil, fmt.Errorf("decode added: %w", err)
	}

	entry.Deleted, _, err = decodeRecordChanges(data, offset)
	if err != nil {
		return nil, fmt.Errorf("decode deleted: %w", err)
	}

	return entry, nil
}

func encodeRecordChanges(buf []byte, offset int, changes []zone.RecordChange) int {
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(changes)))
	offset += 4

	for _, rc := range changes {
		binary.BigEndian.PutUint16(buf[offset:], uint16(len(rc.Name)))
		offset += 2
		copy(buf[offset:], rc.Name)
		offset += len(rc.Name)

		binary.BigEndian.PutUint16(buf[offset:], rc.Type)
		offset += 2

		binary.BigEndian.PutUint32(buf[offset:], rc.TTL)
		offset += 4

		binary.BigEndian.PutUint16(buf[offset:], uint16(len(rc.RData)))
		offset += 2
		copy(buf[offset:], rc.RData)
		offset += len(rc.RData)
	}

	return offset
}

func decodeRecordChanges(data []byte, offset int) ([]zone.RecordChange, int, error) {
	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("truncated at change count")
	}
	count := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	changes := make([]zone.RecordChange, 0, count)
	for i := 0; i < count; i++ {
		var rc zone.RecordChange

		if offset+2 > len(data) {
			return nil, offset, fmt.Errorf("truncated at change %d name length", i)
		}
		nameLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+nameLen > len(data) {
			return nil, offset, fmt.Errorf("truncated at change %d name", i)
		}
		rc.Name = string(data[offset : offset+nameLen])
		offset += nameLen

		if offset+2 > len(data) {
			return nil, offset, fmt.Errorf("truncated at change %d type", i)
		}
		rc.Type = binary.BigEndian.Uint16(data[offset:])
		offset += 2

		if offset+4 > len(data) {
			return nil, offset, fmt.Errorf("truncated at change %d TTL", i)
		}
		rc.TTL = binary.BigEndian.Uint32(data[offset:])
		offset += 4

		if offset+2 > len(data) {
			return nil, offset, fmt.Errorf("truncated at change %d rdata length", i)
		}
		rdataLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+rdataLen > len(data) {
			return nil, offset, fmt.Errorf("truncated at change %d rdata", i)
		}
		rc.RData = string(data[offset : offset+rdataLen])
		offset += rdataLen

		changes = append(changes, rc)
	}

	return changes, offset, nil
}
