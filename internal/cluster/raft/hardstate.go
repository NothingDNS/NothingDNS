package raft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nothingdns/nothingdns/internal/util"
)

// HardState is the subset of Raft state that the spec requires to survive
// crashes (Raft §5.1 / §5.4). Persisting and fsync-ing this BEFORE
// responding to any RPC is the foundation of election safety and leader
// completeness — without it, a node restart can vote twice for the same
// term, or a candidate that previously voted "no" for a peer can come back
// up and vote "yes" in the same term.
//
// log entries are intentionally not stored here; the WAL handles them.
// commitIndex is a volatile-derived value and can be recomputed.
type HardState struct {
	CurrentTerm Term
	VotedFor    NodeID
}

const hardStateFileName = "raft-hardstate.bin"
const hardStateMagic uint32 = 0x52485354 // "RHST"
const maxHardStateVotedForLen = 256      // sanity cap

// hardStatePath returns the on-disk path for the HardState file given a
// data directory.
func hardStatePath(dataDir string) string {
	return filepath.Join(dataDir, hardStateFileName)
}

// loadHardState reads the persisted HardState from dataDir. If the file
// does not exist, returns a zero-value HardState with no error (fresh
// cluster startup). Any other I/O or corruption error is propagated.
func loadHardState(dataDir string) (HardState, error) {
	if dataDir == "" {
		return HardState{}, nil
	}
	f, err := os.Open(hardStatePath(dataDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return HardState{}, nil
		}
		return HardState{}, fmt.Errorf("open hardstate: %w", err)
	}
	defer f.Close()

	// Format: magic(4) | currentTerm(8) | votedForLen(2) | votedFor(N)
	var header [4 + 8 + 2]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return HardState{}, fmt.Errorf("read hardstate header: %w", err)
	}
	if binary.BigEndian.Uint32(header[0:4]) != hardStateMagic {
		return HardState{}, errors.New("hardstate magic mismatch")
	}
	hs := HardState{
		CurrentTerm: Term(binary.BigEndian.Uint64(header[4:12])),
	}
	votedLen := binary.BigEndian.Uint16(header[12:14])
	if votedLen > 0 {
		if votedLen > maxHardStateVotedForLen {
			return HardState{}, fmt.Errorf("hardstate votedFor too large: %d", votedLen)
		}
		buf := make([]byte, votedLen)
		if _, err := io.ReadFull(f, buf); err != nil {
			return HardState{}, fmt.Errorf("read votedFor: %w", err)
		}
		hs.VotedFor = NodeID(buf)
	}
	var trailing [1]byte
	n, err := f.Read(trailing[:])
	if n != 0 {
		return HardState{}, errors.New("hardstate has trailing data")
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return HardState{}, fmt.Errorf("check hardstate EOF: %w", err)
	}
	return hs, nil
}

// saveHardState atomically persists hs to dataDir using the temp-file +
// fsync + rename idiom: a crash mid-write cannot leave the canonical file
// in a partial state. The parent directory is fsynced too so the new
// dirent survives. Callers MUST hold any state lock around their hs
// mutation; this function fsyncs and returns synchronously, so by the time
// it returns the change is durable.
var syncHardStateParentDir = func(dir string) error {
	dirFd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFd.Close()
	if err := dirFd.Sync(); err != nil {
		return err
	}
	return nil
}

func saveHardState(dataDir string, hs HardState) (err error) {
	if dataDir == "" {
		return errors.New("raft: hardstate dataDir is empty; refusing to skip persistence")
	}
	voted := []byte(hs.VotedFor)
	if len(voted) > maxHardStateVotedForLen {
		return fmt.Errorf("hardstate votedFor too large: %d", len(voted))
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("mkdir hardstate dir: %w", err)
	}

	tmp, err := os.CreateTemp(dataDir, "raft-hardstate-*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp hardstate: %w", err)
	}
	tmpName := tmp.Name()
	// Cleanup on failure paths.
	cleanup := true
	defer func() {
		if cleanup {
			if removeErr := os.Remove(tmpName); removeErr != nil && !os.IsNotExist(removeErr) && err == nil {
				err = fmt.Errorf("remove temp hardstate: %w", removeErr)
			}
		}
	}()

	if err := os.Chmod(tmpName, 0600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod tmp hardstate: %w", err)
	}

	if err := writeHardState(tmp, hs); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync hardstate: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close hardstate: %w", err)
	}
	if err := os.Rename(tmpName, hardStatePath(dataDir)); err != nil {
		return fmt.Errorf("rename hardstate: %w", err)
	}
	cleanup = false

	if err := syncHardStateParentDir(dataDir); err != nil {
		return fmt.Errorf("fsync hardstate dir: %w", err)
	}
	return nil
}

func writeHardState(w io.Writer, hs HardState) error {
	voted := []byte(hs.VotedFor)
	if len(voted) > maxHardStateVotedForLen {
		return fmt.Errorf("hardstate votedFor too large: %d", len(voted))
	}

	header := make([]byte, 4+8+2)
	binary.BigEndian.PutUint32(header[0:4], hardStateMagic)
	binary.BigEndian.PutUint64(header[4:12], uint64(hs.CurrentTerm))
	binary.BigEndian.PutUint16(header[12:14], uint16(len(voted)))

	if err := util.WriteFull(w, header); err != nil {
		return fmt.Errorf("write hardstate header: %w", err)
	}
	if len(voted) > 0 {
		if err := util.WriteFull(w, voted); err != nil {
			return fmt.Errorf("write votedFor: %w", err)
		}
	}
	return nil
}
