package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WAL (Write-Ahead Log) provides durable storage with crash recovery.
// Each entry is written to disk before being applied to the database.
// Format: [4 bytes CRC32][1 byte type][4 bytes length][N bytes data]

// WAL constants
const (
	WALHeaderSize   = 9 // CRC32(4) + Type(1) + Length(4)
	WALFilePrefix   = "wal-"
	WALFileSuffix   = ".log"
	MaxSegmentSize  = 64 * 1024 * 1024 // 64MB max segment size
	SyncInterval    = 100 * time.Millisecond
)

// Entry types for WAL
const (
	EntryTypePut    byte = 0x01
	EntryTypeDelete byte = 0x02
	EntryTypeBegin  byte = 0x10
	EntryTypeCommit byte = 0x11
	EntryTypeAbort  byte = 0x12
	EntryTypeCheckpoint byte = 0x20
)

// WAL errors
var (
	ErrWALClosed       = errors.New("wal is closed")
	ErrInvalidSegment  = errors.New("invalid segment file")
	ErrCorruptEntry    = errors.New("corrupt wal entry")
	ErrInvalidChecksum = errors.New("invalid checksum")
	ErrSegmentFull     = errors.New("segment is full")
)

// WALEntry represents a single entry in the WAL
type WALEntry struct {
	Type      byte
	Data      []byte
	Timestamp int64
	CRC       uint32
}

// WALSegment represents a single WAL segment file
type WALSegment struct {
	ID       uint64
	Path     string
	file     *os.File
	size     int64
	sealed   bool
	created  time.Time
}

// WAL implements Write-Ahead Logging
type WAL struct {
	mu          sync.Mutex
	dir         string
	segments    []*WALSegment
	active      *WALSegment
	closed      bool
	stopChan    chan struct{}
	syncChan    chan struct{}
	syncPending bool
	wg          sync.WaitGroup
	opts        WALOptions
}

// WALOptions configures the WAL behavior
type WALOptions struct {
	MaxSegmentSize  int64
	SyncInterval    time.Duration
	PreallocateSize int64
}

// DefaultWALOptions returns default WAL options
func DefaultWALOptions() WALOptions {
	return WALOptions{
		MaxSegmentSize:  MaxSegmentSize,
		SyncInterval:    SyncInterval,
		PreallocateSize: 4 * 1024 * 1024, // 4MB preallocation
	}
}

// OpenWAL opens or creates a WAL in the specified directory
func OpenWAL(dir string, opts WALOptions) (*WAL, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}

	wal := &WAL{
		dir:      dir,
		segments: make([]*WALSegment, 0),
		syncChan: make(chan struct{}, 1),
		stopChan: make(chan struct{}),
		opts:     opts,
	}

	// Load existing segments
	if err := wal.loadSegments(); err != nil {
		return nil, fmt.Errorf("load segments: %w", err)
	}

	// Create initial segment if needed
	if len(wal.segments) == 0 {
		if err := wal.createNewSegment(); err != nil {
			return nil, fmt.Errorf("create initial segment: %w", err)
		}
	} else {
		// Use the last segment as active, open its file for appending
		lastPath := wal.segments[len(wal.segments)-1].Path
		file, err := os.OpenFile(lastPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open active segment file: %w", err)
		}
		wal.segments[len(wal.segments)-1].file = file
		wal.active = wal.segments[len(wal.segments)-1]
	}

	// Start sync goroutine
	wal.wg.Add(1)
	go wal.syncLoop()

	return wal, nil
}

// loadSegments loads existing WAL segments from disk
func (wal *WAL) loadSegments() error {
	entries, err := os.ReadDir(wal.dir)
	if err != nil {
		return fmt.Errorf("read directory: %w", err)
	}

	type segmentInfo struct {
		id   uint64
		path string
	}

	var segments []segmentInfo

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, WALFilePrefix) || !strings.HasSuffix(name, WALFileSuffix) {
			continue
		}

		// Parse segment ID from filename
		idStr := strings.TrimPrefix(name, WALFilePrefix)
		idStr = strings.TrimSuffix(idStr, WALFileSuffix)
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			continue // Skip invalid files
		}

		segments = append(segments, segmentInfo{
			id:   id,
			path: filepath.Join(wal.dir, name),
		})
	}

	// Sort segments by ID
	sort.Slice(segments, func(i, j int) bool {
		return segments[i].id < segments[j].id
	})

	// Load segment metadata
	for _, info := range segments {
		stat, err := os.Stat(info.path)
		if err != nil {
			return fmt.Errorf("stat segment %s: %w", info.path, err)
		}

		wal.segments = append(wal.segments, &WALSegment{
			ID:      info.id,
			Path:    info.path,
			size:    stat.Size(),
			sealed:  false,
			created: stat.ModTime(),
		})
	}

	return nil
}

// createNewSegment creates a new WAL segment
func (wal *WAL) createNewSegment() error {
	// Generate new segment ID
	var id uint64
	if len(wal.segments) > 0 {
		id = wal.segments[len(wal.segments)-1].ID + 1
	}

	// Seal the current active segment
	if wal.active != nil {
		wal.active.sealed = true
	}

	// Create new segment file
	path := filepath.Join(wal.dir, fmt.Sprintf("%s%020d%s", WALFilePrefix, id, WALFileSuffix))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("create segment file: %w", err)
	}

	// Preallocate space
	if wal.opts.PreallocateSize > 0 {
		// Close the file first — on Windows, Truncate fails on O_APPEND handles.
		file.Close()
		if err := os.Truncate(path, wal.opts.PreallocateSize); err != nil {
			return fmt.Errorf("preallocate segment: %w", err)
		}
		if err := os.Truncate(path, 0); err != nil {
			return fmt.Errorf("truncate segment: %w", err)
		}
		// Reopen with O_APPEND for writing
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("reopen segment: %w", err)
		}
	}

	segment := &WALSegment{
		ID:      id,
		Path:    path,
		file:    file,
		size:    0,
		sealed:  false,
		created: time.Now(),
	}

	wal.segments = append(wal.segments, segment)
	wal.active = segment

	return nil
}

// Append appends a new entry to the WAL
func (wal *WAL) Append(entryType byte, data []byte) (uint64, error) {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	if wal.closed {
		return 0, ErrWALClosed
	}

	// Check if we need to rotate to a new segment
	entrySize := int64(WALHeaderSize + len(data))
	if wal.active.size+entrySize > wal.opts.MaxSegmentSize {
		if err := wal.createNewSegment(); err != nil {
			return 0, fmt.Errorf("rotate segment: %w", err)
		}
	}

	// Encode entry
	entry := &WALEntry{
		Type:      entryType,
		Data:      data,
		Timestamp: time.Now().UnixNano(),
	}

	buf, err := wal.encodeEntry(entry)
	if err != nil {
		return 0, fmt.Errorf("encode entry: %w", err)
	}

	// Write to active segment
	n, err := wal.active.file.Write(buf)
	if err != nil {
		return 0, fmt.Errorf("write entry: %w", err)
	}

	wal.active.size += int64(n)
	wal.syncPending = true

	// Trigger async sync
	select {
	case wal.syncChan <- struct{}{}:
	default:
	}

	return uint64(wal.active.size), nil
}

// AppendBatch appends multiple entries atomically
func (wal *WAL) AppendBatch(entries []WALEntry) error {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	if wal.closed {
		return ErrWALClosed
	}

	// Write begin marker
	beginData := make([]byte, 8)
	binary.BigEndian.PutUint64(beginData, uint64(len(entries)))
	if _, err := wal.appendLocked(EntryTypeBegin, beginData); err != nil {
		return err
	}

	// Write all entries
	for _, entry := range entries {
		if _, err := wal.appendLocked(entry.Type, entry.Data); err != nil {
			return err
		}
	}

	// Write commit marker
	if _, err := wal.appendLocked(EntryTypeCommit, nil); err != nil {
		return err
	}

	// Sync to ensure durability
	return wal.syncLocked()
}

func (wal *WAL) appendLocked(entryType byte, data []byte) (uint64, error) {
	// Check if we need to rotate
	entrySize := int64(WALHeaderSize + len(data))
	if wal.active.size+entrySize > wal.opts.MaxSegmentSize {
		if err := wal.createNewSegment(); err != nil {
			return 0, fmt.Errorf("rotate segment: %w", err)
		}
	}

	entry := &WALEntry{
		Type:      entryType,
		Data:      data,
		Timestamp: time.Now().UnixNano(),
	}

	buf, err := wal.encodeEntry(entry)
	if err != nil {
		return 0, fmt.Errorf("encode entry: %w", err)
	}

	n, err := wal.active.file.Write(buf)
	if err != nil {
		return 0, fmt.Errorf("write entry: %w", err)
	}

	wal.active.size += int64(n)
	wal.syncPending = true

	return uint64(wal.active.size), nil
}

// encodeEntry encodes a WAL entry with CRC
func (wal *WAL) encodeEntry(entry *WALEntry) ([]byte, error) {
	// Format: [CRC32(4)][Type(1)][Length(4)][Data(N)]
	totalLen := WALHeaderSize + len(entry.Data)
	buf := make([]byte, totalLen)

	// Write type
	buf[4] = entry.Type

	// Write length
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(entry.Data)))

	// Write data
	if len(entry.Data) > 0 {
		copy(buf[WALHeaderSize:], entry.Data)
	}

	// Calculate and write CRC
	crc := crc32.ChecksumIEEE(buf[4:])
	binary.BigEndian.PutUint32(buf[0:4], crc)

	return buf, nil
}

// decodeEntry decodes a WAL entry from bytes
func (wal *WAL) decodeEntry(buf []byte) (*WALEntry, error) {
	if len(buf) < WALHeaderSize {
		return nil, ErrCorruptEntry
	}

	// Read and verify CRC
	storedCRC := binary.BigEndian.Uint32(buf[0:4])
	computedCRC := crc32.ChecksumIEEE(buf[4:])
	if storedCRC != computedCRC {
		return nil, ErrInvalidChecksum
	}

	// Read type
	entryType := buf[4]

	// Read length
	length := binary.BigEndian.Uint32(buf[5:9])
	if len(buf) < WALHeaderSize+int(length) {
		return nil, ErrCorruptEntry
	}

	// Read data
	data := make([]byte, length)
	copy(data, buf[WALHeaderSize:WALHeaderSize+length])

	return &WALEntry{
		Type: entryType,
		Data: data,
		CRC:  storedCRC,
	}, nil
}

// ReadAll reads all entries from the WAL
func (wal *WAL) ReadAll() ([]WALEntry, error) {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	var entries []WALEntry

	for _, segment := range wal.segments {
		segEntries, err := wal.readSegment(segment)
		if err != nil {
			return nil, fmt.Errorf("read segment %d: %w", segment.ID, err)
		}
		entries = append(entries, segEntries...)
	}

	return entries, nil
}

// readSegment reads all entries from a single segment
func (wal *WAL) readSegment(segment *WALSegment) ([]WALEntry, error) {
	file, err := os.Open(segment.Path)
	if err != nil {
		return nil, fmt.Errorf("open segment: %w", err)
	}
	defer file.Close()

	var entries []WALEntry
	buf := make([]byte, 4096)
	pos := int64(0)

	for {
		// Read header
		header := make([]byte, WALHeaderSize)
		_, err := io.ReadFull(io.NewSectionReader(file, pos, WALHeaderSize), header)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read header at %d: %w", pos, err)
		}

		// Parse length
		length := binary.BigEndian.Uint32(header[5:9])

		// Read full entry
		entrySize := WALHeaderSize + int(length)
		if cap(buf) < entrySize {
			buf = make([]byte, entrySize)
		} else {
			buf = buf[:entrySize]
		}

		_, err = io.ReadFull(io.NewSectionReader(file, pos, int64(entrySize)), buf)
		if err != nil {
			return nil, fmt.Errorf("read entry at %d: %w", pos, err)
		}

		// Decode entry
		entry, err := wal.decodeEntry(buf)
		if err != nil {
			// Corrupted entry, stop reading
			break
		}

		entries = append(entries, *entry)
		pos += int64(entrySize)
	}

	return entries, nil
}

// Sync forces a sync of the active segment
func (wal *WAL) Sync() error {
	wal.mu.Lock()
	defer wal.mu.Unlock()
	return wal.syncLocked()
}

func (wal *WAL) syncLocked() error {
	if wal.active.file == nil {
		return nil
	}
	wal.syncPending = false
	return wal.active.file.Sync()
}

// syncLoop periodically syncs the WAL
func (wal *WAL) syncLoop() {
	defer wal.wg.Done()
	ticker := time.NewTicker(wal.opts.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			wal.mu.Lock()
			if wal.syncPending && !wal.closed {
				wal.syncLocked()
			}
			wal.mu.Unlock()
		case <-wal.syncChan:
			wal.mu.Lock()
			if wal.syncPending && !wal.closed {
				wal.syncLocked()
			}
			wal.mu.Unlock()
		case <-wal.stopChan:
			return
		}
	}
}

// Truncate removes all segments up to and including the given segment ID
func (wal *WAL) Truncate(segmentID uint64) error {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	var keep []*WALSegment
	var removed []*WALSegment

	for _, seg := range wal.segments {
		if seg.ID <= segmentID {
			removed = append(removed, seg)
		} else {
			keep = append(keep, seg)
		}
	}

	// Don't remove the active segment
	if len(keep) == 0 {
		keep = []*WALSegment{wal.active}
		removed = removed[:len(removed)-1]
	}

	// Close and delete old segments
	for _, seg := range removed {
		if seg.file != nil {
			seg.file.Close()
		}
		if err := os.Remove(seg.Path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove segment %d: %w", seg.ID, err)
		}
	}

	wal.segments = keep
	return nil
}

// Compact creates a checkpoint and truncates old segments
func (wal *WAL) Compact(checkpointData []byte) error {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	// Write checkpoint
	if _, err := wal.appendLocked(EntryTypeCheckpoint, checkpointData); err != nil {
		return fmt.Errorf("write checkpoint: %w", err)
	}

	if err := wal.syncLocked(); err != nil {
		return fmt.Errorf("sync checkpoint: %w", err)
	}

	// Create new segment after checkpoint
	return wal.createNewSegment()
}

// Close closes the WAL
func (wal *WAL) Close() error {
	wal.mu.Lock()

	if wal.closed {
		wal.mu.Unlock()
		return nil
	}

	wal.closed = true
	close(wal.stopChan)
	wal.mu.Unlock()

	// Wait for syncLoop to finish before closing segment files
	wal.wg.Wait()

	wal.mu.Lock()
	// Final sync
	if wal.syncPending {
		wal.syncLocked()
	}

	// Close all segments
	for _, seg := range wal.segments {
		if seg.file != nil {
			seg.file.Close()
		}
	}
	wal.mu.Unlock()

	return nil
}

// Stats returns WAL statistics
func (wal *WAL) Stats() WALStats {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	var totalSize int64
	for _, seg := range wal.segments {
		totalSize += seg.size
	}

	return WALStats{
		SegmentCount:  len(wal.segments),
		TotalSize:     totalSize,
		ActiveSegment: wal.active.ID,
	}
}

// WALStats contains WAL statistics
type WALStats struct {
	SegmentCount  int
	TotalSize     int64
	ActiveSegment uint64
}

// WALReader provides sequential reading of WAL entries
type WALReader struct {
	wal       *WAL
	segment   int
	file      *os.File
	pos       int64
	buf       *bytes.Buffer
}

// NewReader creates a new WAL reader
func (wal *WAL) NewReader() *WALReader {
	return &WALReader{
		wal: wal,
		buf: bytes.NewBuffer(nil),
	}
}

// Next reads the next entry from the WAL
func (r *WALReader) Next() (*WALEntry, error) {
	for {
		// Try to read from current buffer
		if r.buf.Len() >= WALHeaderSize {
			header := make([]byte, WALHeaderSize)
			if _, err := io.ReadFull(r.buf, header); err != nil {
				return nil, err
			}

			length := binary.BigEndian.Uint32(header[5:9])
			if r.buf.Len() >= int(length) {
				entry, err := r.wal.decodeEntry(append(header, r.buf.Bytes()[:length]...))
				if err != nil {
					return nil, err
				}
				r.buf.Truncate(r.buf.Len() - int(length))
				return entry, nil
			}
		}

		// Need to read more data
		if r.file == nil {
			// Open next segment
			if r.segment >= len(r.wal.segments) {
				return nil, io.EOF
			}

			seg := r.wal.segments[r.segment]
			f, err := os.Open(seg.Path)
			if err != nil {
				return nil, fmt.Errorf("open segment: %w", err)
			}
			r.file = f
			r.pos = 0
			r.segment++
		}

		// Read from file
		readBuf := make([]byte, 4096)
		n, err := r.file.Read(readBuf)
		if n > 0 {
			r.buf.Write(readBuf[:n])
			r.pos += int64(n)
		}
		if err == io.EOF {
			r.file.Close()
			r.file = nil
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}
	}
}

// Close closes the reader
func (r *WALReader) Close() error {
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}
