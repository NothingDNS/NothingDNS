// Package storage — ZoneStore provides persistent zone data storage.
//
// ZoneStore bridges the in-memory zone.Zone structures with the KVStore
// for persistence. Zone records are serialized as simple key-value pairs
// where each domain name maps to a binary encoding of its record set.
//
// Bucket layout:
//
//	zones/
//	  <origin>/
//	    _meta     → zone metadata (origin, default TTL)
//	    <name>    → encoded records for that name
package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// ZoneStore provides persistent storage for DNS zone data.
type ZoneStore struct {
	kv *KVStore
	mu sync.RWMutex
}

// ZoneMeta holds zone metadata for persistence.
type ZoneMeta struct {
	Origin     string
	DefaultTTL uint32
}

// StoredRecord represents a DNS record in storage.
type StoredRecord struct {
	Name  string
	TTL   uint32
	Class string
	Type  string
	RData string
}

// ErrZoneNotFound is returned when a zone is not found in storage.
var ErrZoneNotFound = errors.New("zone not found in storage")

// NewZoneStore creates a ZoneStore backed by the given KVStore.
func NewZoneStore(kv *KVStore) *ZoneStore {
	return &ZoneStore{kv: kv}
}

// SaveZone persists a zone's records to the KV store.
// The zone is stored under a bucket named by its origin.
func (zs *ZoneStore) SaveZone(origin string, meta ZoneMeta, records map[string][]StoredRecord) error {
	zs.mu.Lock()
	defer zs.mu.Unlock()

	return zs.kv.Update(func(tx *Tx) error {
		zones, err := tx.CreateBucketIfNotExists([]byte("zones"))
		if err != nil {
			return fmt.Errorf("create zones bucket: %w", err)
		}

		// Delete existing zone bucket (ignore error if not found)
		_ = zones.DeleteBucket([]byte(origin))
		zoneBucket, err := zones.CreateBucket([]byte(origin))
		if err != nil {
			return fmt.Errorf("create zone bucket %s: %w", origin, err)
		}

		// Store metadata
		metaBytes := encodeZoneMeta(meta)
		if err := zoneBucket.Put([]byte("_meta"), metaBytes); err != nil {
			return fmt.Errorf("put meta: %w", err)
		}

		// Store records grouped by name
		for name, recs := range records {
			encoded := encodeRecords(recs)
			if err := zoneBucket.Put([]byte(name), encoded); err != nil {
				return fmt.Errorf("put records for %s: %w", name, err)
			}
		}

		return nil
	})
}

// LoadZone loads a zone's records from the KV store.
func (zs *ZoneStore) LoadZone(origin string) (ZoneMeta, map[string][]StoredRecord, error) {
	zs.mu.RLock()
	defer zs.mu.RUnlock()

	var meta ZoneMeta
	records := make(map[string][]StoredRecord)

	err := zs.kv.View(func(tx *Tx) error {
		zones := tx.Bucket([]byte("zones"))
		if zones == nil {
			return ErrZoneNotFound
		}

		zoneBucket := zones.Bucket([]byte(origin))
		if zoneBucket == nil {
			return ErrZoneNotFound
		}

		// Load metadata
		metaBytes := zoneBucket.Get([]byte("_meta"))
		if metaBytes == nil {
			return fmt.Errorf("zone %s: missing metadata", origin)
		}
		var err error
		meta, err = decodeZoneMeta(metaBytes)
		if err != nil {
			return fmt.Errorf("decode meta: %w", err)
		}

		// Load all record sets
		metaPrefix := []byte("_")
		zoneBucket.ForEach(func(k, v []byte) error {
			if bytes.HasPrefix(k, metaPrefix) {
				return nil // skip metadata keys
			}
			recs, err := decodeRecords(v)
			if err != nil {
				return fmt.Errorf("decode records for %s: %w", string(k), err)
			}
			records[string(k)] = recs
			return nil
		})

		return nil
	})

	return meta, records, err
}

// DeleteZone removes a zone from storage.
func (zs *ZoneStore) DeleteZone(origin string) error {
	zs.mu.Lock()
	defer zs.mu.Unlock()

	return zs.kv.Update(func(tx *Tx) error {
		zones := tx.Bucket([]byte("zones"))
		if zones == nil {
			return nil
		}
		return zones.DeleteBucket([]byte(origin))
	})
}

// ListZones returns the origins of all stored zones.
func (zs *ZoneStore) ListZones() ([]string, error) {
	zs.mu.RLock()
	defer zs.mu.RUnlock()

	var origins []string
	err := zs.kv.View(func(tx *Tx) error {
		zones := tx.Bucket([]byte("zones"))
		if zones == nil {
			return nil
		}
		// Iterate sub-buckets — each is a zone origin
		if zones.data != nil && zones.data.Buckets != nil {
			for name := range zones.data.Buckets {
				origins = append(origins, name)
			}
		}
		return nil
	})
	return origins, err
}

// SaveRecords persists individual record changes (for dynamic DNS updates).
// This performs a partial update without rewriting the entire zone.
func (zs *ZoneStore) SaveRecords(origin, name string, records []StoredRecord) error {
	zs.mu.Lock()
	defer zs.mu.Unlock()

	return zs.kv.Update(func(tx *Tx) error {
		zones := tx.Bucket([]byte("zones"))
		if zones == nil {
			return ErrZoneNotFound
		}
		zoneBucket := zones.Bucket([]byte(origin))
		if zoneBucket == nil {
			return ErrZoneNotFound
		}

		if len(records) == 0 {
			return zoneBucket.Delete([]byte(name))
		}
		encoded := encodeRecords(records)
		return zoneBucket.Put([]byte(name), encoded)
	})
}

// --- Encoding helpers ---

// Wire format for ZoneMeta:
// [4 bytes originLen][origin string][4 bytes defaultTTL]
func encodeZoneMeta(meta ZoneMeta) []byte {
	originBytes := []byte(meta.Origin)
	buf := make([]byte, 4+len(originBytes)+4)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(originBytes)))
	copy(buf[4:4+len(originBytes)], originBytes)
	binary.BigEndian.PutUint32(buf[4+len(originBytes):], meta.DefaultTTL)
	return buf
}

func decodeZoneMeta(data []byte) (ZoneMeta, error) {
	if len(data) < 8 {
		return ZoneMeta{}, fmt.Errorf("meta too short: %d bytes", len(data))
	}
	originLen := binary.BigEndian.Uint32(data[0:4])
	if int(originLen) > len(data)-8 {
		return ZoneMeta{}, fmt.Errorf("invalid origin length: %d", originLen)
	}
	origin := string(data[4 : 4+originLen])
	defaultTTL := binary.BigEndian.Uint32(data[4+originLen:])
	return ZoneMeta{
		Origin:     origin,
		DefaultTTL: defaultTTL,
	}, nil
}

// Wire format for records:
// [4 bytes count]
// For each record:
//
//	[2 bytes nameLen][name][4 bytes TTL][1 byte classLen][class]
//	[1 byte typeLen][type][2 bytes rdataLen][rdata]
func encodeRecords(records []StoredRecord) []byte {
	size := 4
	for _, r := range records {
		size += 2 + len(r.Name) + 4 + 1 + len(r.Class) + 1 + len(r.Type) + 2 + len(r.RData)
	}

	buf := make([]byte, size)
	offset := 0

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(records)))
	offset += 4

	for _, r := range records {
		binary.BigEndian.PutUint16(buf[offset:], uint16(len(r.Name)))
		offset += 2
		copy(buf[offset:], r.Name)
		offset += len(r.Name)

		binary.BigEndian.PutUint32(buf[offset:], r.TTL)
		offset += 4

		buf[offset] = byte(len(r.Class))
		offset++
		copy(buf[offset:], r.Class)
		offset += len(r.Class)

		buf[offset] = byte(len(r.Type))
		offset++
		copy(buf[offset:], r.Type)
		offset += len(r.Type)

		binary.BigEndian.PutUint16(buf[offset:], uint16(len(r.RData)))
		offset += 2
		copy(buf[offset:], r.RData)
		offset += len(r.RData)
	}

	return buf
}

func decodeRecords(data []byte) ([]StoredRecord, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for record count")
	}

	count := binary.BigEndian.Uint32(data[0:4])
	offset := 4
	records := make([]StoredRecord, 0, count)

	for i := uint32(0); i < count; i++ {
		var r StoredRecord

		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated at record %d name length", i)
		}
		nameLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+nameLen > len(data) {
			return nil, fmt.Errorf("truncated at record %d name", i)
		}
		r.Name = string(data[offset : offset+nameLen])
		offset += nameLen

		if offset+4 > len(data) {
			return nil, fmt.Errorf("truncated at record %d TTL", i)
		}
		r.TTL = binary.BigEndian.Uint32(data[offset:])
		offset += 4

		if offset+1 > len(data) {
			return nil, fmt.Errorf("truncated at record %d class length", i)
		}
		classLen := int(data[offset])
		offset++
		if offset+classLen > len(data) {
			return nil, fmt.Errorf("truncated at record %d class", i)
		}
		r.Class = string(data[offset : offset+classLen])
		offset += classLen

		if offset+1 > len(data) {
			return nil, fmt.Errorf("truncated at record %d type length", i)
		}
		typeLen := int(data[offset])
		offset++
		if offset+typeLen > len(data) {
			return nil, fmt.Errorf("truncated at record %d type", i)
		}
		r.Type = string(data[offset : offset+typeLen])
		offset += typeLen

		if offset+2 > len(data) {
			return nil, fmt.Errorf("truncated at record %d rdata length", i)
		}
		rdataLen := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		if offset+rdataLen > len(data) {
			return nil, fmt.Errorf("truncated at record %d rdata", i)
		}
		r.RData = string(data[offset : offset+rdataLen])
		offset += rdataLen

		records = append(records, r)
	}

	return records, nil
}
