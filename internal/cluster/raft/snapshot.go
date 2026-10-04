package raft

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/nothingdns/nothingdns/internal/util"
)

// Snapshot contains the state machine state at a point in time.
type Snapshot struct {
	Index      Index
	Term       Term
	LastIndex  Index // Highest index in snapshot
	LastTerm   Term  // Term of last index
	Data       []byte
	Membership []NodeID // Peers in the cluster at snapshot time
}

// Snapshotter manages snapshots for log compaction.
type Snapshotter struct {
	mu           sync.RWMutex
	snapshotsDir string
	aeadKey      []byte // L-6: optional AES-256-GCM key for at-rest snapshot encryption
}

// NewSnapshotter creates a new snapshotter.
func NewSnapshotter(dir string) (*Snapshotter, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	return &Snapshotter{
		snapshotsDir: dir,
	}, nil
}

// NewSnapshotterEncrypted creates a snapshotter that writes
// AES-256-GCM-encrypted snapshot files. Reads support both plain and
// encrypted files (dispatched by leading magic byte) so an operator
// can roll an in-place migration: enable the key, and the next Save
// rewrites the snapshot in encrypted form. L-6.
func NewSnapshotterEncrypted(dir string, aeadKey []byte) (*Snapshotter, error) {
	if aeadKey != nil && len(aeadKey) != 32 {
		return nil, fmt.Errorf("aead key must be 32 bytes (%d provided)", len(aeadKey))
	}
	s, err := NewSnapshotter(dir)
	if err != nil {
		return nil, err
	}
	// L-N3: copy the key so caller mutations don't bleed into our
	// AEAD state. Snapshotter has no Close to zeroize the copy, but
	// at least our state is decoupled from caller-held slices.
	if len(aeadKey) > 0 {
		s.aeadKey = append([]byte(nil), aeadKey...)
	}
	return s, nil
}

// Snapshot file magic bytes.
//
// Plain snapshots start with bytes 0..7 of Index (uint64) — for any
// realistic Raft index that's 0x00..0x00 in the high bytes, so the
// encrypted magic 0xE0 is unambiguous: an Index of 0xE000_0000_…
// would be ~16 exa-entries, far beyond any practical cluster.
//
// Encrypted layout:
//
//	byte 0:        0xE0
//	bytes 1-2:     version (big-endian uint16)
//	bytes 3-14:    12-byte nonce
//	bytes 15..end: AES-GCM(plaintext = plain-snapshot-body,
//	                       AAD       = magic||version)
const (
	encryptedSnapshotMagic   = 0xE0
	encryptedSnapshotVersion = 1
	snapAeadNonceLen         = 12
)

// syncSnapshotDir flushes the directory entry created by the final rename.
var syncSnapshotDir = func(dir string) (err error) {
	dirFd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := dirFd.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	if err := dirFd.Sync(); err != nil {
		return err
	}
	return nil
}

// Save saves a snapshot to disk.
//
// Durability: fsync the temp file before rename and fsync the
// snapshots directory after rename so the new file's dirent
// reaches stable storage. Without either, a crash between the
// write and the directory flush could leave Raft believing it
// has a durable snapshot at index N while the file is empty,
// truncated, or absent on next start — and Raft uses the
// snapshot to decide which WAL segments are safe to truncate,
// so a missing snapshot turns into permanent log loss.
func (s *Snapshotter) Save(snap *Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.snapshotsDir, snapFilename(snap.Index))
	base := filepath.Base(filename)

	f, err := os.CreateTemp(s.snapshotsDir, "."+base+"-*.tmp")
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	tmpFile := f.Name()
	keepTemp := false
	defer func() {
		if !keepTemp {
			os.Remove(tmpFile)
		}
	}()

	if err := s.writeSnapshot(f, snap); err != nil {
		f.Close()
		return err
	}

	// fsync the file's data and metadata before rename — closing
	// alone flushes user-space buffers but does NOT guarantee the
	// bytes reach the disk platter.
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err := os.Rename(tmpFile, filename); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	keepTemp = true

	// fsync the directory so the rename's dirent commit reaches
	// stable storage.
	if err := syncSnapshotDir(s.snapshotsDir); err != nil {
		return fmt.Errorf("fsync snapshot dir: %w", err)
	}

	// The new snapshot is durable, so now drop the ones it supersedes.
	// This is best-effort: the snapshot itself is already committed, so a
	// prune failure only leaves dead weight on disk and must not turn a
	// successful Save into a failed one.
	s.pruneLocked()

	return nil
}

// maxRetainedSnapshots bounds how many snapshot files a Snapshotter keeps.
//
// Load() reads only the highest-index file, so every other copy is
// unreachable by construction. A leader snapshots every SnapshotInterval
// (30s by default) and each file holds a full serialization of the state
// machine, so keeping all of them turns the bounded log this subsystem
// exists to maintain into an unbounded pile of dead snapshots. Two are
// retained so an operator still has a fallback if the newest file turns
// out to be unreadable.
const maxRetainedSnapshots = 2

// pruneLocked removes every snapshot file beyond the maxRetainedSnapshots
// highest-indexed ones. Caller must hold s.mu — Save does for its whole body.
func (s *Snapshotter) pruneLocked() {
	entries, err := os.ReadDir(s.snapshotsDir)
	if err != nil {
		util.Warnf("raft: snapshot prune: readdir %s: %v", s.snapshotsDir, err)
		return
	}

	type snapFile struct {
		name  string
		index Index
	}
	var files []snapFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// parseSnapshotFilename only accepts "snapshot-<digits>", so the
		// in-flight ".snapshot-*.tmp" file Save is currently writing is
		// never a candidate for removal.
		idx, ok := parseSnapshotFilename(e.Name())
		if !ok {
			continue
		}
		files = append(files, snapFile{name: e.Name(), index: idx})
	}
	if len(files) <= maxRetainedSnapshots {
		return
	}

	// Highest index first, then drop everything past the retention window.
	sort.Slice(files, func(i, j int) bool { return files[i].index > files[j].index })
	for _, f := range files[maxRetainedSnapshots:] {
		p := filepath.Join(s.snapshotsDir, f.name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			util.Warnf("raft: snapshot prune: remove %s: %v", p, err)
		}
	}
	// The unlinks are dirent mutations and must be flushed too, or a
	// restart can still list the pruned files.
	if err := syncSnapshotDir(s.snapshotsDir); err != nil {
		util.Warnf("raft: snapshot prune: fsync dir: %v", err)
	}
}

// Load loads the latest snapshot from disk.
func (s *Snapshotter) Load() (*Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find latest snapshot file
	files, err := os.ReadDir(s.snapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("readdir: %w", err)
	}

	var latest string
	var latestIndex Index
	for _, f := range files {
		if f.IsDir() || len(f.Name()) < 6 {
			continue
		}
		idx, ok := parseSnapshotFilename(f.Name())
		if ok && (latest == "" || idx > latestIndex) {
			latestIndex = idx
			latest = f.Name()
		}
	}

	if latest == "" {
		return nil, nil
	}

	snapPath := filepath.Join(s.snapshotsDir, latest)
	f, err := os.Open(snapPath)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	return s.readSnapshot(f)
}

func parseSnapshotFilename(name string) (Index, bool) {
	idxStr, ok := strings.CutPrefix(name, "snapshot-")
	if !ok || idxStr == "" {
		return 0, false
	}
	for i := 0; i < len(idxStr); i++ {
		if idxStr[i] < '0' || idxStr[i] > '9' {
			return 0, false
		}
	}
	idx, err := strconv.ParseUint(idxStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return Index(idx), true
}

// writeSnapshot writes a snapshot to a writer.
//
// L-6: if aeadKey is set, the plain serialised body is wrapped in
// AES-256-GCM and emitted as 0xE0 || version || nonce || ciphertext.
// The plain path is unchanged when aeadKey is nil.
func (s *Snapshotter) writeSnapshot(w io.Writer, snap *Snapshot) error {
	if s.aeadKey != nil {
		var plain bytes.Buffer
		if err := s.writePlainSnapshot(&plain, snap); err != nil {
			return err
		}
		gcm, err := newSnapshotGCM(s.aeadKey)
		if err != nil {
			return err
		}
		nonce := make([]byte, snapAeadNonceLen)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return fmt.Errorf("aead nonce: %w", err)
		}
		aad := []byte{encryptedSnapshotMagic, 0x00, byte(encryptedSnapshotVersion)}
		ct := gcm.Seal(nil, nonce, plain.Bytes(), aad)
		out := make([]byte, 0, 3+snapAeadNonceLen+len(ct))
		out = append(out, encryptedSnapshotMagic)
		out = append(out, aad[1:3]...)
		out = append(out, nonce...)
		out = append(out, ct...)
		return util.WriteFull(w, out)
	}
	return s.writePlainSnapshot(w, snap)
}

// writePlainSnapshot is the unencrypted writer body — called directly
// when aeadKey is nil and via writeSnapshot's encrypt wrapper.
func (s *Snapshotter) writePlainSnapshot(w io.Writer, snap *Snapshot) error {
	// Format: Index(8) + Term(8) + LastIndex(8) + LastTerm(8) + DataLen(8) + Data + MembershipLen(4) + Membership
	buf := make([]byte, 8)

	// Index
	binary.BigEndian.PutUint64(buf, uint64(snap.Index))
	if err := util.WriteFull(w, buf); err != nil {
		return err
	}

	// Term
	binary.BigEndian.PutUint64(buf, uint64(snap.Term))
	if err := util.WriteFull(w, buf); err != nil {
		return err
	}

	// LastIndex
	binary.BigEndian.PutUint64(buf, uint64(snap.LastIndex))
	if err := util.WriteFull(w, buf); err != nil {
		return err
	}

	// LastTerm
	binary.BigEndian.PutUint64(buf, uint64(snap.LastTerm))
	if err := util.WriteFull(w, buf); err != nil {
		return err
	}

	// Data
	binary.BigEndian.PutUint64(buf, uint64(len(snap.Data)))
	if err := util.WriteFull(w, buf); err != nil {
		return err
	}
	if err := util.WriteFull(w, snap.Data); err != nil {
		return err
	}

	// Membership
	membershipLen := make([]byte, 4)
	binary.BigEndian.PutUint32(membershipLen, uint32(len(snap.Membership)))
	if err := util.WriteFull(w, membershipLen); err != nil {
		return err
	}
	for _, peerID := range snap.Membership {
		peerBytes := []byte(peerID)
		lenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBytes, uint32(len(peerBytes)))
		if err := util.WriteFull(w, lenBytes); err != nil {
			return err
		}
		if err := util.WriteFull(w, peerBytes); err != nil {
			return err
		}
	}

	return nil
}

// Snapshot wire-format limits. These cap untrusted on-disk fields so
// a corrupt or attacker-planted snapshot file can't drive
// runaway allocations during Load.
//
//   - maxSnapshotDataBytes: state-machine payload. 1 GiB is well
//     above any realistic DNS zone aggregate; well below the
//     uint64 ceiling where make() would OOM the process.
//   - maxSnapshotMembership: number of NodeIDs. 1024 peers is
//     several orders of magnitude beyond any practical Raft cluster.
//   - maxNodeIDBytes: per-NodeID byte length. NodeIDs are short
//     identifiers; 256 bytes is generous.
const (
	maxSnapshotDataBytes  = 1 << 30 // 1 GiB
	maxSnapshotMembership = 1024
	maxNodeIDBytes        = 256
)

// readSnapshot reads a snapshot from a reader. L-6: peeks the first
// byte to dispatch between the encrypted (0xE0) and plain layouts.
func (s *Snapshotter) readSnapshot(r io.Reader) (*Snapshot, error) {
	var magic [1]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if magic[0] == encryptedSnapshotMagic {
		if s.aeadKey == nil {
			return nil, fmt.Errorf("snapshot file is AES-GCM encrypted (magic 0xE0) but no aead key configured")
		}
		return s.readEncryptedSnapshot(r)
	}
	// Plain layout — magic byte was actually the high byte of Index.
	// Re-feed it to the plain reader prepended to the rest of r.
	prefixed := io.MultiReader(bytes.NewReader(magic[:]), r)
	return s.readPlainSnapshot(prefixed)
}

// readEncryptedSnapshot reads (post-magic) version + nonce + ciphertext
// and dispatches the decrypted body through readPlainSnapshot.
func (s *Snapshotter) readEncryptedSnapshot(r io.Reader) (*Snapshot, error) {
	var verBytes [2]byte
	if _, err := io.ReadFull(r, verBytes[:]); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	version := binary.BigEndian.Uint16(verBytes[:])
	if version != encryptedSnapshotVersion {
		return nil, fmt.Errorf("unsupported encrypted snapshot version: %d", version)
	}
	nonce := make([]byte, snapAeadNonceLen)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}
	// L-N1: bound the ciphertext read. A planted snapshot file
	// starting with 0xE0 could otherwise be multi-GB and OOM startup
	// before gcm.Open runs. Cap matches the inner maxSnapshotDataBytes
	// plus generous headroom for the GCM tag, membership list, and
	// other fixed-width fields.
	const maxEncryptedSnapshotBody = maxSnapshotDataBytes + 1024*1024 // +1 MiB headroom
	ct, err := io.ReadAll(io.LimitReader(r, maxEncryptedSnapshotBody+1))
	if err != nil {
		return nil, fmt.Errorf("read ciphertext: %w", err)
	}
	if int64(len(ct)) > maxEncryptedSnapshotBody {
		return nil, fmt.Errorf("snapshot: encrypted body %d exceeds max %d", len(ct), maxEncryptedSnapshotBody)
	}
	gcm, err := newSnapshotGCM(s.aeadKey)
	if err != nil {
		return nil, err
	}
	aad := []byte{encryptedSnapshotMagic, verBytes[0], verBytes[1]}
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("aead decrypt: %w", err)
	}
	return s.readPlainSnapshot(bytes.NewReader(pt))
}

func newSnapshotGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aead key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	return gcm, nil
}

// readPlainSnapshot reads the unencrypted body (Index..Membership).
func (s *Snapshotter) readPlainSnapshot(r io.Reader) (*Snapshot, error) {
	snap := &Snapshot{}

	buf := make([]byte, 8)

	// Index
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read index: %w", err)
	}
	snap.Index = Index(binary.BigEndian.Uint64(buf))

	// Term
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read term: %w", err)
	}
	snap.Term = Term(binary.BigEndian.Uint64(buf))

	// LastIndex
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read lastindex: %w", err)
	}
	snap.LastIndex = Index(binary.BigEndian.Uint64(buf))

	// LastTerm
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read lastterm: %w", err)
	}
	snap.LastTerm = Term(binary.BigEndian.Uint64(buf))

	// Data
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read datalen: %w", err)
	}
	dataLen := binary.BigEndian.Uint64(buf)
	if dataLen > maxSnapshotDataBytes {
		return nil, fmt.Errorf("snapshot dataLen %d exceeds max %d", dataLen, maxSnapshotDataBytes)
	}
	snap.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(r, snap.Data); err != nil {
		return nil, fmt.Errorf("read data: %w", err)
	}

	// Membership
	membershipLen := make([]byte, 4)
	if _, err := io.ReadFull(r, membershipLen); err != nil {
		return nil, fmt.Errorf("read membershiplen: %w", err)
	}
	mCount := binary.BigEndian.Uint32(membershipLen)
	if mCount > maxSnapshotMembership {
		return nil, fmt.Errorf("snapshot membership count %d exceeds max %d", mCount, maxSnapshotMembership)
	}
	for i := uint32(0); i < mCount; i++ {
		lenBytes := make([]byte, 4)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return nil, fmt.Errorf("read peerlen: %w", err)
		}
		peerLen := binary.BigEndian.Uint32(lenBytes)
		if peerLen > maxNodeIDBytes {
			return nil, fmt.Errorf("snapshot peerLen %d exceeds max %d", peerLen, maxNodeIDBytes)
		}
		peerBytes := make([]byte, peerLen)
		if _, err := io.ReadFull(r, peerBytes); err != nil {
			return nil, fmt.Errorf("read peer: %w", err)
		}
		snap.Membership = append(snap.Membership, NodeID(peerBytes))
	}

	return snap, nil
}

// snapFilename returns the filename for a snapshot index.
func snapFilename(index Index) string {
	return fmt.Sprintf("snapshot-%d", index)
}
