package raft

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
)

// WAL is the Write-Ahead Log for Raft log entries.
// It provides durability for uncommitted log entries.
type WAL struct {
	mu      sync.Mutex
	logFile *os.File
	dir     string
}

// NewWAL creates a new WAL.
func NewWAL(dir string) (*WAL, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	logPath := path.Join(dir, "raft-wal.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	return &WAL{
		logFile: f,
		dir:     dir,
	}, nil
}

// Write writes an entry to the WAL.
func (w *WAL) Write(e entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Format: Index(8) + Term(8) + CommandLen(8) + Command + Type(1)
	dataLen := 8 + 8 + 8 + len(e.Command) + 1
	buf := make([]byte, dataLen)
	offset := 0

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.Index))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(e.Term))
	offset += 8

	binary.BigEndian.PutUint64(buf[offset:], uint64(len(e.Command)))
	offset += 8

	copy(buf[offset:], e.Command)
	offset += len(e.Command)

	buf[offset] = byte(e.Type)

	_, err := w.logFile.Write(buf)
	return err
}

// ReadAll reads all entries from the WAL.
func (w *WAL) ReadAll() ([]entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.logFile.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	var entries []entry
	buf := make([]byte, 1024) // Reusable buffer

	for {
		// Read index
		if _, err := w.logFile.Read(buf[:8]); err != nil {
			break // EOF
		}
		e := entry{}
		e.Index = Index(binary.BigEndian.Uint64(buf[:8]))

		// Read term
		if _, err := w.logFile.Read(buf[:8]); err != nil {
			return nil, fmt.Errorf("read term: %w", err)
		}
		e.Term = Term(binary.BigEndian.Uint64(buf[:8]))

		// Read command length
		if _, err := w.logFile.Read(buf[:8]); err != nil {
			return nil, fmt.Errorf("read cmdlen: %w", err)
		}
		cmdLen := binary.BigEndian.Uint64(buf[:8])

		// Read command
		if cmdLen > 0 {
			if uint64(len(buf)) < cmdLen {
				buf = make([]byte, cmdLen)
			}
			if _, err := w.logFile.Read(buf[:cmdLen]); err != nil {
				return nil, fmt.Errorf("read cmd: %w", err)
			}
			e.Command = make([]byte, cmdLen)
			copy(e.Command, buf[:cmdLen])
		}

		// Read type
		if _, err := w.logFile.Read(buf[:1]); err != nil {
			return nil, fmt.Errorf("read type: %w", err)
		}
		e.Type = EntryType(buf[0])

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
