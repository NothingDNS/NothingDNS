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
	WALHeaderSize  = 9 // CRC32(4) + Type(1) + Length(4)
	WALFilePrefix  = "wal-"
	WALFileSuffix  = ".log"
	MaxSegmentSize = 64 * 1024 * 1024 // 64MB max segment size
	SyncInterval   = 100 * time.Millisecond
)

// Entry types for WAL
const (
	EntryTypePut        byte = 0x01
	EntryTypeDelete     byte = 0x02
	EntryTypeBegin      byte = 0x10
	EntryTypeCommit     byte = 0x11
	EntryTypeAbort      byte = 0x12
	EntryTypeCheckpoint byte = 0x20
)

// WAL errors
var (
	ErrWALClosed       = errors.New("wal is closed")
	ErrInvalidSegment  = errors.New("invalid segment file")
	ErrCorruptEntry    = errors.New("corrupt wal entry")
	ErrInvalidChecksum = errors.New("invalid checksum")
	ErrSegmentFull     = errors.New("segment is full")
	ErrEntryTooLarge   = errors.New("wal entry exceeds max segment size")
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
	ID      uint64
	Path    string
	file    *os.File
	size    int64
	sealed  bool
	created time.Time
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
	syncErr     error
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

func normalizeWALOptions(opts WALOptions) WALOptions {
	defaults := DefaultWALOptions()
	if opts.MaxSegmentSize <= WALHeaderSize {
		opts.MaxSegmentSize = defaults.MaxSegmentSize
	}
	if opts.SyncInterval <= 0 {
		opts.SyncInterval = defaults.SyncInterval
	}
	if opts.PreallocateSize < 0 {
		opts.PreallocateSize = 0
	}
	return opts
}

// OpenWAL opens or creates a WAL in the specified directory
func OpenWAL(dir string, opts WALOptions) (*WAL, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create directory: %w", err)
	}
	opts = normalizeWALOptions(opts)

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
		active := wal.segments[len(wal.segments)-1]

		// Truncate any torn trailing bytes (partial header, partial body,
		// or fully corrupt entry) so subsequent Appends start at the last
		// valid offset. Without this step, recovery would `break` cleanly
		// at the torn bytes but new entries written *past* the garbage
		// would be hidden behind it on the next replay.
		validEnd, err := findValidEnd(active.Path)
		if err != nil {
			return nil, fmt.Errorf("scan active segment %s: %w", active.Path, err)
		}
		if validEnd < active.size {
			if err := os.Truncate(active.Path, validEnd); err != nil {
				return nil, fmt.Errorf("truncate torn tail: %w", err)
			}
			active.size = validEnd
		}

		file, err := os.OpenFile(active.Path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("open active segment file: %w", err)
		}
		active.file = file
		wal.active = active
	}

	// Start sync goroutine
	wal.wg.Add(1)
	go wal.syncLoop()

	return wal, nil
}

// findValidEnd scans a WAL segment file and returns the byte offset
// just past the last entry whose header parses and whose body length
// is fully present in the file. A torn trailing entry — short header,
// truncated body, or any kind of corruption — gets dropped via the
// returned offset, which OpenWAL then truncates to. The scan uses
// the same length-prefix logic as readSegment but stops at first
// problem rather than per-entry CRC validation (that's still done at
// ReadAll time; here we just need a safe append point).
func findValidEnd(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return 0, err
	}
	total := stat.Size()

	var pos int64
	hdr := make([]byte, WALHeaderSize)
	for {
		// Try to read a full header at `pos`.
		n, err := f.ReadAt(hdr, pos)
		if err != nil || n < WALHeaderSize {
			// Partial / no header at this offset — `pos` is the safe end.
			return pos, nil
		}
		length := binary.BigEndian.Uint32(hdr[5:9])
		// Bound the declared body length the same way decodeEntry does so
		// a corrupt header can't claim a multi-GiB body and convince us
		// to keep more bytes than we actually have.
		if int64(length) > MaxSegmentSize {
			return pos, nil
		}
		entryEnd := pos + int64(WALHeaderSize) + int64(length)
		if entryEnd > total {
			// Body is truncated — drop everything from `pos` forward.
			return pos, nil
		}
		pos = entryEnd
	}
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
		if entry.IsDir() {
			continue
		}
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

	// Create new segment file
	path := filepath.Join(wal.dir, fmt.Sprintf("%s%020d%s", WALFilePrefix, id, WALFileSuffix))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("create segment file: %w", err)
	}

	// Preallocate space
	if wal.opts.PreallocateSize > 0 {
		// Close the file first — on Windows, Truncate fails on O_APPEND handles.
		if err := file.Close(); err != nil {
			return cleanupNewSegment(path, fmt.Errorf("close segment before preallocate: %w", err))
		}
		file = nil
		if err := os.Truncate(path, wal.opts.PreallocateSize); err != nil {
			return cleanupNewSegment(path, fmt.Errorf("preallocate segment: %w", err))
		}
		if err := os.Truncate(path, 0); err != nil {
			return cleanupNewSegment(path, fmt.Errorf("truncate segment: %w", err))
		}
		// Reopen with O_APPEND for writing — only append after successful reopen
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return cleanupNewSegment(path, fmt.Errorf("reopen segment: %w", err))
		}
	}

	// Seal the current active segment AND release its file descriptor only
	// after the replacement segment is ready. If preparing the new segment
	// fails, the current active segment remains appendable.
	if wal.active != nil {
		if wal.active.file != nil {
			if wal.syncPending {
				if err := wal.syncLocked(); err != nil {
					return cleanupNewSegmentFile(file, path, fmt.Errorf("sync active segment before rotation: %w", err))
				}
			}
			if err := wal.active.file.Close(); err != nil {
				return cleanupNewSegmentFile(file, path, fmt.Errorf("close active segment before rotation: %w", err))
			}
			wal.active.file = nil
		}
		wal.active.sealed = true
	}

	segment := &WALSegment{
		ID:      id,
		Path:    path,
		file:    file,
		size:    0,
		sealed:  false,
		created: time.Now(),
	}

	// Set active BEFORE adding to segments list to prevent nil pointer on error
	wal.active = segment
	wal.segments = append(wal.segments, segment)

	return nil
}

func cleanupNewSegmentFile(file *os.File, path string, cause error) error {
	if file != nil {
		if err := file.Close(); err != nil {
			cause = errors.Join(cause, fmt.Errorf("close new segment after failure: %w", err))
		}
	}
	return cleanupNewSegment(path, cause)
}

func cleanupNewSegment(path string, cause error) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		cause = errors.Join(cause, fmt.Errorf("remove new segment after failure: %w", err))
	}
	return cause
}

// Append appends a new entry to the WAL
func (wal *WAL) Append(entryType byte, data []byte) (uint64, error) {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	if wal.closed {
		return 0, ErrWALClosed
	}
	if err := wal.checkSyncErrLocked(); err != nil {
		return 0, err
	}

	// Reject an entry that cannot fit in ANY segment. Writing it would succeed
	// here but recovery (decodeEntry/readSegment) rejects length > MaxSegmentSize
	// and would silently drop it — a durable-ack of data that is unreadable on
	// restart (a false-durability / data-loss edge). Fail the Append instead.
	entrySize := int64(WALHeaderSize + len(data))
	if entrySize > wal.opts.MaxSegmentSize {
		return 0, fmt.Errorf("%w: entry %d bytes > segment max %d", ErrEntryTooLarge, entrySize, wal.opts.MaxSegmentSize)
	}

	// Check if we need to rotate to a new segment
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

	// Write the full entry before advancing the segment size. If the
	// writer makes no progress or returns an error after a partial write,
	// truncate back to the pre-Append size so recovery sees a clean log.
	n, err := writeWALBuffer(wal.active.file, buf)
	if err != nil {
		if rollbackErr := wal.rollbackActiveAppend(wal.active.size); rollbackErr != nil {
			return 0, fmt.Errorf("write entry: %w; rollback failed: %w", err, rollbackErr)
		}
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
	if err := wal.checkSyncErrLocked(); err != nil {
		return err
	}

	// Write begin marker
	beginData := make([]byte, 8)
	binary.BigEndian.PutUint64(beginData, uint64(len(entries)))
	if _, err := wal.appendLocked(EntryTypeBegin, beginData); err != nil {
		return err
	}

	// Write all entries; if any fails, write an Abort marker so recovery
	// can distinguish this partial batch from a committed one.
	for _, entry := range entries {
		if _, err := wal.appendLocked(entry.Type, entry.Data); err != nil {
			// Best-effort Abort: if this write also fails, surface the
			// original error — the partial batch will still be filtered
			// by readSegment on recovery because the segment ended without
			// a Commit marker.
			wal.appendLocked(EntryTypeAbort, nil)
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

	n, err := writeWALBuffer(wal.active.file, buf)
	if err != nil {
		// Same torn-write rollback as Append — see comment there.
		if rollbackErr := wal.rollbackActiveAppend(wal.active.size); rollbackErr != nil {
			return 0, fmt.Errorf("write entry: %w; rollback failed: %w", err, rollbackErr)
		}
		return 0, fmt.Errorf("write entry: %w", err)
	}

	wal.active.size += int64(n)
	wal.syncPending = true

	return uint64(wal.active.size), nil
}

func writeWALBuffer(w io.Writer, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := w.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (wal *WAL) rollbackActiveAppend(size int64) error {
	// Truncate to the pre-Append size and reseek so the next Append starts
	// at a known-clean offset. If either operation fails, surface it:
	// silently continuing after a failed rollback can leave hidden torn bytes
	// in front of future entries.
	if err := wal.active.file.Truncate(size); err != nil {
		return fmt.Errorf("truncate active segment to %d: %w", size, err)
	}
	if _, err := wal.active.file.Seek(size, io.SeekStart); err != nil {
		return fmt.Errorf("seek active segment to %d: %w", size, err)
	}
	return nil
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
	// Reject entries larger than a segment before allocating — a corrupted or
	// hostile length prefix otherwise makes us `make([]byte, 4 GiB)` during
	// recovery (VULN-020).
	if int64(length) > MaxSegmentSize {
		return nil, ErrCorruptEntry
	}
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

// readSegment reads all entries from a single segment.
// Only entries from committed batches are returned. A partial batch
// (Begin without a matching Commit, or followed by Abort) is discarded
// on both Abort markers and at segment end.
func (wal *WAL) readSegment(segment *WALSegment) ([]WALEntry, error) {
	file, err := os.Open(segment.Path)
	if err != nil {
		return nil, fmt.Errorf("open segment: %w", err)
	}
	defer file.Close()

	var entries []WALEntry
	buf := make([]byte, 4096)
	pos := int64(0)

	// inBatch tracks whether we are inside an uncommitted batch.
	// Each entry is appended only once it is known to be committed.
	inBatch := false

	for {
		// Read header
		header := make([]byte, WALHeaderSize)
		_, err := io.ReadFull(io.NewSectionReader(file, pos, WALHeaderSize), header)
		if errors.Is(err, io.EOF) {
			break
		}
		// A partial header at the tail of the segment is the signature of
		// a power-loss crash mid-Append: we wrote some bytes but not the
		// full 9-byte header. Treat that as the end of the valid log and
		// discard any uncommitted batch in progress.
		if errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read header at %d: %w", pos, err)
		}

		// Parse length
		length := binary.BigEndian.Uint32(header[5:9])
		// Defensively bound the entry size before allocating — a corrupt
		// header could claim a 4 GiB body and OOM us.
		if int64(length) > wal.opts.MaxSegmentSize {
			break
		}

		// Read full entry
		entrySize := WALHeaderSize + int(length)
		if cap(buf) < entrySize {
			buf = make([]byte, entrySize)
		} else {
			buf = buf[:entrySize]
		}

		_, err = io.ReadFull(io.NewSectionReader(file, pos, int64(entrySize)), buf)
		// Partial trailing entry (some header, not enough body) — same
		// torn-write story; stop and discard any uncommitted batch.
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read entry at %d: %w", pos, err)
		}

		// Decode entry
		entry, err := wal.decodeEntry(buf)
		if err != nil {
			// Corrupted entry, stop reading
			break
		}

		// State machine for batch tracking.
		switch entry.Type {
		case EntryTypeBegin:
			// A new batch starts; discard any previously uncommitted one.
			inBatch = true
			entries = nil
		case EntryTypeCommit:
			// Batch is now committed — keep what we have.
			inBatch = false
		case EntryTypeAbort:
			// Batch was rolled back — discard its entries.
			inBatch = false
			entries = nil
		default:
			// Regular entry: only include it if we are in a committed batch.
			if !inBatch {
				entries = append(entries, *entry)
			}
			// If inBatch is true, the entry is part of a partial batch and
			// is silently discarded; it will be dropped either when we see
			// the matching Commit, when we see Abort, or at segment end.
		}

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
		wal.syncPending = false
		wal.syncErr = nil
		return nil
	}
	if err := wal.active.file.Sync(); err != nil {
		// Don't clear syncPending on error — the next tick / explicit
		// Sync call should retry. Previously this cleared the flag
		// *before* calling Sync, so a transient EIO would silently
		// drop the pending durability promise (the buffer was still
		// in the page cache, but the next Append-bumped syncPending
		// would happily get cleared by the next tick again). Worst
		// case the daemon crashes between the failed Sync and the
		// next Append; with the old ordering nothing remembered
		// "we still owe a sync."
		wal.syncErr = err
		return err
	}
	wal.syncPending = false
	wal.syncErr = nil
	return nil
}

func (wal *WAL) checkSyncErrLocked() error {
	if wal.syncErr != nil {
		return fmt.Errorf("previous WAL sync failed: %w", wal.syncErr)
	}
	return nil
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
				wal.syncErr = wal.syncLocked()
			}
			wal.mu.Unlock()
		case <-wal.syncChan:
			wal.mu.Lock()
			if wal.syncPending && !wal.closed {
				wal.syncErr = wal.syncLocked()
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

	// Don't remove the active segment — if active is in removed list,
	// move it to keep so it stays in wal.segments and its file stays open.
	// This handles the edge case where active.ID <= segmentID but other
	// segments have ID > segmentID.
	for i, seg := range removed {
		if seg == wal.active {
			// Remove from removed, add to keep
			removed = append(removed[:i], removed[i+1:]...)
			keep = append(keep, wal.active)
			break
		}
	}

	// Close and delete old segments
	for _, seg := range removed {
		if seg.file != nil {
			if err := seg.file.Close(); err != nil {
				return fmt.Errorf("close segment %d: %w", seg.ID, err)
			}
			seg.file = nil
		}
		if err := os.Remove(seg.Path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove segment %d: %w", seg.ID, err)
		}
	}

	// Re-sort by ID. The "move active out of removed" branch above can
	// append the active segment to the end of `keep`, but `keep` may
	// already contain segments with higher IDs. ReadAll iterates
	// `wal.segments` in slice order to replay entries oldest-first, so
	// any out-of-order entry here would scramble the recovery sequence
	// — older entries returned after newer ones, breaking the WAL's
	// commit-order invariant.
	sort.Slice(keep, func(i, j int) bool {
		return keep[i].ID < keep[j].ID
	})

	wal.segments = keep
	return nil
}

// Compact creates a checkpoint and truncates old segments
func (wal *WAL) Compact(checkpointData []byte) error {
	wal.mu.Lock()
	defer wal.mu.Unlock()

	if err := wal.checkSyncErrLocked(); err != nil {
		return err
	}

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
	var closeErr error
	if wal.syncPending {
		if err := wal.syncLocked(); err != nil {
			closeErr = fmt.Errorf("final sync: %w", err)
		}
	}

	// Close all segments
	for _, seg := range wal.segments {
		if seg.file != nil {
			if err := seg.file.Close(); err != nil && closeErr == nil {
				closeErr = fmt.Errorf("close segment %d: %w", seg.ID, err)
			}
			seg.file = nil
		}
	}
	wal.mu.Unlock()

	return closeErr
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
	wal     *WAL
	segment int
	file    *os.File
	pos     int64
	buf     *bytes.Buffer
}

var closeWALReaderFile = func(file *os.File) error {
	return file.Close()
}

// NewReader creates a new WAL reader
func (wal *WAL) NewReader() *WALReader {
	return &WALReader{
		wal: wal,
		buf: bytes.NewBuffer(nil),
	}
}

// Next reads the next entry from the WAL
//
// IMPORTANT: bytes.Buffer.Truncate(n) keeps the first n unread bytes
// and DISCARDS the tail. The previous code used
//
//	r.buf.Truncate(r.buf.Len() - int(length))
//
// to "consume" the just-decoded payload, but this kept the payload
// (the front of the buffer) and dropped the tail — corrupting every
// subsequent header read. A single-entry stream limped along because
// the buffer drained to empty before the bug had anything to chew
// on; any multi-entry stream returned garbage from the second
// Next() onward.
//
// Keep the header in the buffer until the full payload is available.
// Otherwise a large entry that spans multiple file reads loses its
// header before the payload arrives, and the next loop interprets
// payload bytes as a fresh header.
func (r *WALReader) Next() (*WALEntry, error) {
	for {
		// Try to read from current buffer
		if r.buf.Len() >= WALHeaderSize {
			header := r.buf.Bytes()[:WALHeaderSize]
			length := binary.BigEndian.Uint32(header[5:9])
			if int64(length) > MaxSegmentSize {
				return nil, ErrCorruptEntry
			}
			entrySize := WALHeaderSize + int(length)
			if r.buf.Len() >= entrySize {
				entryBuf := make([]byte, entrySize)
				copy(entryBuf, r.buf.Bytes()[:entrySize])
				entry, err := r.wal.decodeEntry(entryBuf)
				if err != nil {
					return nil, err
				}
				// Advance past the complete entry we just decoded.
				r.buf.Next(entrySize)
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
			if closeErr := closeWALReaderFile(r.file); closeErr != nil {
				return nil, fmt.Errorf("close segment after EOF: %w", closeErr)
			}
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
		if err := closeWALReaderFile(r.file); err != nil {
			return err
		}
		r.file = nil
	}
	return nil
}
