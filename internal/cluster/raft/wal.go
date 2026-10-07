package raft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path"
	"sync"

	"github.com/nothingdns/nothingdns/internal/util"
)

// maxWALCommandBytes caps the size of any single WAL command entry.
// This prevents a corrupt or attacker-controlled WAL from causing unbounded
// allocation during log replay (VULN-047).
const maxWALCommandBytes = 64 * 1024 * 1024 // 64 MiB

// walMagic marks a v1 (CRC-framed) Raft WAL file. Files without it are
// legacy (un-checksummed) WALs and are migrated to v1 on open.
const walMagic = "RWAL\x01\x00\x00\x00"

// walRecordHeaderSize is CRC32(4) + Index(8) + Term(8) + CmdLen(8).
const walRecordHeaderSize = 28

// WAL is the Write-Ahead Log for Raft log entries.
// It provides durability for uncommitted log entries.
type WAL struct {
	mu      sync.Mutex
	logFile *os.File
	dir     string
}

// NewWAL creates a new WAL. Empty files are stamped with the v1 magic;
// legacy (un-checksummed) files are read tolerantly and migrated to the
// CRC-framed v1 format in one atomic rewrite.
func NewWAL(dir string) (*WAL, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	logPath := path.Join(dir, "raft-wal.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	w := &WAL{
		logFile: f,
		dir:     dir,
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("stat WAL: %w", err)
	}
	if info.Size() == 0 {
		if err := util.WriteFull(f, []byte(walMagic)); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("write WAL magic: %w", err)
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("fsync WAL magic: %w", err)
		}
		return w, nil
	}

	magic := make([]byte, len(walMagic))
	if _, err := f.ReadAt(magic, 0); err == nil && string(magic) == walMagic {
		return w, nil // already v1
	}

	// Legacy file: replay with the tolerant legacy reader, then migrate
	// atomically to the v1 format (magic + per-record CRC).
	entries, err := w.readLegacyLocked()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("migrate legacy WAL: %w", err)
	}
	if err := w.rewriteLocked(entries); err != nil {
		_ = w.logFile.Close()
		return nil, fmt.Errorf("migrate legacy WAL: %w", err)
	}
	util.Infof("raft: migrated legacy WAL %s to CRC-framed v1 format (%d entries)", logPath, len(entries))
	return w, nil
}

// Write writes an entry to the WAL.
func (w *WAL) Write(e entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writeLocked(e)
}

// encodeWALEntry serializes one entry to its on-disk v1 record format:
// CRC32(4) + Index(8) + Term(8) + CommandLen(8) + Command + Type(1).
// The CRC covers everything after itself, so bit-rot anywhere in the
// record is detected on replay (the legacy format had no checksum: a
// flipped bit silently replayed a corrupted command).
func encodeWALEntry(e entry) []byte {
	dataLen := 4 + 8 + 8 + 8 + len(e.Command) + 1
	buf := make([]byte, dataLen)
	offset := 4 // CRC written last

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.Index))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.Term))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(len(e.Command)))
	offset += 8

	copy(buf[offset:], e.Command)
	offset += len(e.Command)

	buf[offset] = byte(e.Type)

	binary.BigEndian.PutUint32(buf[0:4], crc32.ChecksumIEEE(buf[4:]))
	return buf
}

// writeLocked appends one entry. Caller must hold w.mu.
//
// F165: a write that fails part-way (ENOSPC/EFBIG short write) must not leave
// a partial record behind — the next successful append would land after it,
// turning the torn bytes into mid-file corruption that refuses boot. Cut the
// file back to its pre-write size on failure.
func (w *WAL) writeLocked(e entry) error {
	info, err := w.logFile.Stat()
	if err != nil {
		return fmt.Errorf("stat WAL before append: %w", err)
	}
	if err := util.WriteFull(w.logFile, encodeWALEntry(e)); err != nil {
		if terr := w.logFile.Truncate(info.Size()); terr != nil {
			return fmt.Errorf("%w (removing partial WAL record failed: %w)", err, terr)
		}
		return err
	}
	return nil
}

// logPath returns the WAL's backing file path.
func (w *WAL) logPath() string {
	return path.Join(w.dir, "raft-wal.log")
}

// rewriteLocked atomically replaces the WAL contents with kept. It writes the
// kept entries to a temp file, fsyncs it, renames it over the live log, and
// fsyncs the directory so the rename is durable, then reopens the log for
// appending. A crash at any point leaves either the complete old log or the
// complete new log on disk — never a truncated one. This replaces the previous
// Truncate(0)+re-append, where a crash mid-rewrite lost committed entries.
// Caller must hold w.mu.
func (w *WAL) rewriteLocked(kept []entry) error {
	logPath := w.logPath()

	tmp, err := os.CreateTemp(w.dir, "raft-wal-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp WAL: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := os.Chmod(tmpName, 0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp WAL: %w", err)
	}
	if err := util.WriteFull(tmp, []byte(walMagic)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp WAL magic: %w", err)
	}
	for _, e := range kept {
		if err := util.WriteFull(tmp, encodeWALEntry(e)); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("write temp WAL: %w", err)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp WAL: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp WAL: %w", err)
	}

	if err := os.Rename(tmpName, logPath); err != nil {
		return fmt.Errorf("rename WAL: %w", err)
	}
	cleanup = false

	// The rename has already happened, so the live log is now the temp
	// file's inode and w.logFile still references the original, which the
	// rename unlinked. Swap the handle FIRST: returning early on a
	// dir-fsync error before the swap would leave every later append going
	// to an unlinked inode, silently losing committed entries on restart
	// while reporting an error the caller only logs.
	//
	// The dir fsync governs durability of the rename, not which inode the
	// open handle refers to, so doing the swap first is safe.
	if err := w.swapLogFileLocked(logPath); err != nil {
		return err
	}

	if err := syncHardStateParentDir(w.dir); err != nil {
		return fmt.Errorf("fsync WAL dir: %w", err)
	}

	return nil
}

// swapLogFileLocked closes the current append handle and reopens logPath in
// append mode, installing the fresh handle on the WAL. Caller must hold w.mu.
func (w *WAL) swapLogFileLocked(logPath string) error {
	if err := w.logFile.Close(); err != nil {
		return fmt.Errorf("close old WAL handle: %w", err)
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("reopen WAL: %w", err)
	}
	w.logFile = f
	return nil
}

// TruncateAfter removes every entry whose Index is greater than keepThrough,
// rewriting the log file in place. Used when a follower's log conflicts with
// the leader's and the tail must be discarded before the correct entries are
// appended — without this the WAL would keep replaying stale, overwritten
// entries on the next restart.
func (w *WAL) TruncateAfter(keepThrough Index) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	all, err := w.readAllLocked()
	if err != nil {
		return err
	}
	kept := all[:0]
	for _, e := range all {
		if e.Index <= keepThrough {
			kept = append(kept, e)
		}
	}

	return w.rewriteLocked(kept)
}

// CompactBefore removes every entry whose Index is <= through, keeping the
// suffix, and rewrites the file in place. Called after a snapshot subsumes the
// log prefix so the WAL stays bounded and a restart replays only the
// post-snapshot tail.
func (w *WAL) CompactBefore(through Index) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	all, err := w.readAllLocked()
	if err != nil {
		return err
	}
	kept := all[:0]
	for _, e := range all {
		if e.Index > through {
			kept = append(kept, e)
		}
	}

	return w.rewriteLocked(kept)
}

// ReadAll reads all entries from the WAL.
func (w *WAL) ReadAll() ([]entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.readAllLocked()
}

// ErrWALCorrupt reports mid-file corruption (bad CRC or an impossible
// length on a fully-present record). It is deliberately fatal: the node
// refuses to boot rather than silently discard fsync-acked, committed
// entries — matching etcd's WAL, which repairs only a torn tail.
var ErrWALCorrupt = errors.New("raft: WAL corruption detected")

// readAllLocked reads every v1 entry from the start of the file. Caller
// must hold w.mu.
//
// Two failure modes are treated DIFFERENTLY, because conflating them
// destroys data:
//
//   - Torn tail — a crash mid-Write left the LAST record incomplete, so
//     reading it returns a short read (io.ErrUnexpectedEOF). Those bytes
//     were never fsync-acked (Write fsyncs before AppendEntries acks), so
//     truncating them back to the last intact record is safe and lets the
//     node boot. A legit torn write can only truncate the byte stream, so
//     it never fabricates an oversized length (the length was correct when
//     written) — hence oversized length is NOT treated as a torn tail.
//
//   - Mid-file corruption — a fully-present record whose CRC fails, or a
//     record header whose length field is impossible. The record WAS
//     fsync-acked and may be committed cluster-wide; truncating from here
//     would silently drop committed entries and let this node win a later
//     election with a shorter log, losing them everywhere. This is fatal
//     (ErrWALCorrupt): operator intervention / restore-from-peer required.
func (w *WAL) readAllLocked() ([]entry, error) {
	if _, err := w.logFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	// Magic header.
	magic := make([]byte, len(walMagic))
	if _, err := io.ReadFull(w.logFile, magic); err != nil {
		if err == io.EOF {
			return nil, nil // empty file
		}
		return nil, fmt.Errorf("read WAL magic: %w", err)
	}
	if string(magic) != walMagic {
		return nil, fmt.Errorf("WAL missing v1 magic — file was not migrated")
	}

	var entries []entry
	goodOffset := int64(len(walMagic)) // end of the last intact record
	buf := make([]byte, 1024)          // reusable command buffer

	truncateTail := func(err error) ([]entry, error) {
		util.Warnf("raft: WAL torn tail at offset %d (%v) — truncating, %d intact entries kept",
			goodOffset, err, len(entries))
		if terr := w.logFile.Truncate(goodOffset); terr != nil {
			return nil, fmt.Errorf("truncate WAL tail: %w", terr)
		}
		if serr := w.logFile.Sync(); serr != nil {
			return nil, fmt.Errorf("fsync WAL after tail truncate: %w", serr)
		}
		if _, serr := w.logFile.Seek(0, io.SeekEnd); serr != nil {
			return nil, fmt.Errorf("seek WAL end: %w", serr)
		}
		return entries, nil
	}

	for {
		header := make([]byte, walRecordHeaderSize)
		if _, err := io.ReadFull(w.logFile, header); err != nil {
			if err == io.EOF {
				break // clean end of WAL
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return truncateTail(fmt.Errorf("torn record header: %w", err))
			}
			return nil, fmt.Errorf("read WAL header: %w", err)
		}
		wantCRC := binary.BigEndian.Uint32(header[0:4])
		e := entry{}
		e.Index = Index(binary.BigEndian.Uint64(header[4:12]))
		e.Term = Term(binary.BigEndian.Uint64(header[12:20]))
		cmdLen := binary.BigEndian.Uint64(header[20:28])

		// An oversized length on a fully-read header cannot come from a
		// torn write (the length was valid when written); it means the
		// length bytes are corrupted. Fatal, not a tail truncate.
		if cmdLen > maxWALCommandBytes {
			return nil, fmt.Errorf("%w: record at offset %d has impossible cmdLen %d (max %d)",
				ErrWALCorrupt, goodOffset, cmdLen, maxWALCommandBytes)
		}

		if uint64(len(buf)) < cmdLen+1 {
			buf = make([]byte, cmdLen+1)
		}
		body := buf[:cmdLen+1] // command + trailing type byte
		if _, err := io.ReadFull(w.logFile, body); err != nil {
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
				return truncateTail(fmt.Errorf("torn record body: %w", err))
			}
			return nil, fmt.Errorf("read WAL body (%d bytes): %w", len(body), err)
		}

		crc := crc32.ChecksumIEEE(header[4:])
		crc = crc32.Update(crc, crc32.IEEETable, body)
		if crc != wantCRC {
			// The full record was present — this is bit-rot on a durable,
			// possibly-committed entry, not a torn tail. Refuse to boot.
			return nil, fmt.Errorf("%w: CRC mismatch at offset %d (got %08x want %08x)",
				ErrWALCorrupt, goodOffset, crc, wantCRC)
		}

		if cmdLen > 0 {
			e.Command = make([]byte, cmdLen)
			copy(e.Command, body[:cmdLen])
		}
		e.Type = EntryType(body[cmdLen])

		// F164: records are appended in decision order, and a record for
		// index i is only ever written when the log held exactly the
		// entries below i. A later record at an index already seen (retry
		// after a failed fsync, or an append after a TruncateAfter that
		// failed) therefore supersedes that index and everything after it
		// — etcd WAL semantics. Appending blindly replayed both copies and
		// shifted every following entry to the wrong log position.
		for len(entries) > 0 && entries[len(entries)-1].Index >= e.Index {
			entries = entries[:len(entries)-1]
		}
		entries = append(entries, e)
		goodOffset += int64(walRecordHeaderSize) + int64(cmdLen) + 1
	}

	return entries, nil
}

// readLegacyLocked reads a pre-v1 (un-checksummed) WAL:
// Index(8) + Term(8) + CmdLen(8) + Command + Type(1) per record, no magic.
// A torn tail (short read at EOF) is tolerated so migration after a crash
// succeeds. An oversized length, however, is fatal (ErrWALCorrupt): a
// legit legacy torn write never fabricates one, so it means either
// corruption or — critically — a v1 file whose 8-byte magic got corrupted
// and was misdetected as legacy. Silently treating that as a torn tail
// (the old behavior) rewrote the entire log to an empty file. Caller must
// hold w.mu.
func (w *WAL) readLegacyLocked() ([]entry, error) {
	if _, err := w.logFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var entries []entry
	buf := make([]byte, 1024)

	for {
		header := make([]byte, 24)
		if _, err := io.ReadFull(w.logFile, header); err != nil {
			if err == io.EOF {
				break
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				util.Warnf("raft: legacy WAL torn header at tail — %d intact entries kept", len(entries))
				break
			}
			return nil, fmt.Errorf("read legacy WAL header: %w", err)
		}
		e := entry{}
		e.Index = Index(binary.BigEndian.Uint64(header[0:8]))
		e.Term = Term(binary.BigEndian.Uint64(header[8:16]))
		cmdLen := binary.BigEndian.Uint64(header[16:24])

		if cmdLen > maxWALCommandBytes {
			return nil, fmt.Errorf("%w: legacy record has impossible cmdLen %d (corruption, or a v1 WAL with a damaged magic header)",
				ErrWALCorrupt, cmdLen)
		}

		if cmdLen > 0 {
			if uint64(len(buf)) < cmdLen {
				buf = make([]byte, cmdLen)
			}
			if _, err := io.ReadFull(w.logFile, buf[:cmdLen]); err != nil {
				if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
					util.Warnf("raft: legacy WAL torn command at tail — %d intact entries kept", len(entries))
					return entries, nil
				}
				return nil, fmt.Errorf("read legacy WAL cmd (%d bytes): %w", cmdLen, err)
			}
			e.Command = make([]byte, cmdLen)
			copy(e.Command, buf[:cmdLen])
		}

		var typBuf [1]byte
		if _, err := io.ReadFull(w.logFile, typBuf[:]); err != nil {
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
				util.Warnf("raft: legacy WAL torn type byte at tail — %d intact entries kept", len(entries))
				return entries, nil
			}
			return nil, fmt.Errorf("read legacy WAL type: %w", err)
		}
		e.Type = EntryType(typBuf[0])

		entries = append(entries, e)
	}

	return entries, nil
}

// Close closes the WAL.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logFile.Close()
}

// Sync forces the WAL to disk.
func (w *WAL) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.logFile.Sync()
}
