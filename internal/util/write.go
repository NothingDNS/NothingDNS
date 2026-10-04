package util

import (
	"io"
	"os"
	"path/filepath"
)

// WriteFull writes all of p to w, retrying on short writes. It returns a
// non-nil error if fewer than len(p) bytes could be written. A Write that
// returns 0, nil is treated as io.ErrNoProgress to avoid spinning forever.
func WriteFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

// AtomicWriteFile writes data to path atomically: create a temporary file in
// the same directory, write+sync, then rename over the target. On any error
// the temp file is cleaned up and the target is left untouched (the rename
// never happens). The temp file is created with mode 0o644 by default; use
// the optional mode argument to override.
//
// This prevents the partial-write corruption that a plain os.WriteFile +
// os.Rename (without syncing the temp file first) can still produce on
// power-loss or kernel crash (the rename metadata may persist before the
// data reaches the platter).
func AtomicWriteFile(path string, data []byte, mode ...os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	tmp, err := os.CreateTemp(dir, "."+base+"-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	// Clean up the temp file unless the rename succeeds.
	keepTemp := false
	defer func() {
		if !keepTemp {
			os.Remove(tmpPath)
		}
	}()

	if err := WriteFull(tmp, data); err != nil {
		tmp.Close() // best-effort; the defer removes it either way
		return err
	}

	fileMode := os.FileMode(0644)
	if len(mode) > 0 {
		fileMode = mode[0]
	}
	if err := tmp.Chmod(fileMode); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	keepTemp = true // prevent defer from removing the now-renamed file
	return nil
}
