package storage

import (
	"bytes"
	"testing"
)

// openTestWAL opens a WAL in a fresh temp dir using production defaults.
func openTestWAL(t *testing.T, dir string) *WAL {
	t.Helper()
	wal, err := OpenWAL(dir, DefaultWALOptions())
	if err != nil {
		t.Fatalf("OpenWAL: %v", err)
	}
	return wal
}

// TestProofRound018_WALRecoversCommittedBatch drives the real AppendBatch and
// the real ReadAll recovery path against a real on-disk WAL.
//
// AppendBatch writes the frame order [Begin, entry..., Commit] (wal.go:445-463).
// readSegment's batch state machine appends a regular entry only when
// `!inBatch` (wal.go:700-702) — i.e. it KEEPS entries written outside a batch
// and DISCARDS every entry inside one, which is the exact inverse of what its
// own comments state ("Each entry is appended only once it is known to be
// committed"; "only include it if we are in a committed batch").
//
// The net effect is that a committed batch survives the fsync but is silently
// dropped on the next recovery: durable-ack'd data that never comes back.
func TestProofRound018_WALRecoversCommittedBatch(t *testing.T) {
	dir := t.TempDir()

	wal := openTestWAL(t, dir)
	want := []WALEntry{
		{Type: 0x21, Data: []byte("first")},
		{Type: 0x22, Data: []byte("second")},
	}
	if err := wal.AppendBatch(want); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen: this is the restart path, exactly what a crash/reboot does.
	wal2 := openTestWAL(t, dir)
	defer func() { _ = wal2.Close() }()

	got, err := wal2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("FAIL: AppendBatch durably committed %d entries, recovery returned %d: %s",
			len(want), len(got), describeEntries(got))
	}
	for i := range want {
		if got[i].Type != want[i].Type || !bytes.Equal(got[i].Data, want[i].Data) {
			t.Errorf("FAIL: entry %d = type 0x%02x %q, want type 0x%02x %q",
				i, got[i].Type, got[i].Data, want[i].Type, want[i].Data)
		}
	}
}

// TestProofRound018_WALRecoversUnbatchedAppend is the control: the plain
// single-entry Append path, which is the ONLY shape production writes today
// (internal/zone/wal_journal.go:124). It must keep working unchanged, both
// before and after the fix — otherwise the fix would be trading one data-loss
// mode for another.
func TestProofRound018_WALRecoversUnbatchedAppend(t *testing.T) {
	dir := t.TempDir()

	wal := openTestWAL(t, dir)
	if _, err := wal.Append(0x31, []byte("plain")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := wal.Append(0x32, []byte("also-plain")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	wal2 := openTestWAL(t, dir)
	defer func() { _ = wal2.Close() }()

	got, err := wal2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("FAIL: control — 2 unbatched Appends recovered as %d: %s", len(got), describeEntries(got))
	}
	if !bytes.Equal(got[0].Data, []byte("plain")) || !bytes.Equal(got[1].Data, []byte("also-plain")) {
		t.Errorf("FAIL: control — unbatched order/content wrong: %s", describeEntries(got))
	}
}

// TestProofRound018_WALMixedBatchAndPlain covers the boundary the fix must get
// right: a committed batch followed by a plain entry, in the same segment. Both
// must survive, in write order.
func TestProofRound018_WALMixedBatchAndPlain(t *testing.T) {
	dir := t.TempDir()

	wal := openTestWAL(t, dir)
	if err := wal.AppendBatch([]WALEntry{
		{Type: 0x41, Data: []byte("batched-1")},
		{Type: 0x42, Data: []byte("batched-2")},
	}); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}
	if _, err := wal.Append(0x43, []byte("plain-after")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := wal.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if err := wal.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	wal2 := openTestWAL(t, dir)
	defer func() { _ = wal2.Close() }()

	got, err := wal2.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	wantData := []string{"batched-1", "batched-2", "plain-after"}
	if len(got) != len(wantData) {
		t.Fatalf("FAIL: batch+plain recovered as %d entries, want %d: %s",
			len(got), len(wantData), describeEntries(got))
	}
	for i, w := range wantData {
		if string(got[i].Data) != w {
			t.Errorf("FAIL: entry %d = %q, want %q", i, got[i].Data, w)
		}
	}
}

func describeEntries(entries []WALEntry) string {
	if len(entries) == 0 {
		return "(no entries)"
	}
	var b bytes.Buffer
	b.WriteByte('[')
	for i, e := range entries {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(string(e.Data))
	}
	b.WriteByte(']')
	return b.String()
}
