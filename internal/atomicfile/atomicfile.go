// Package atomicfile replaces files durably: readers see either the old or
// the new content, never a partial write, and the new content survives a
// crash once WriteFile has returned nil.
package atomicfile

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// WriteFile replaces path with data durably: it writes a temp file in the
// same directory (created with mode 0o700 if missing), fsyncs it, renames it
// over path and fsyncs the directory so the rename itself survives a crash.
//
// Once the rename has succeeded the new content is visible, so a failing
// directory fsync only weakens crash durability: it is logged rather than
// reported (reporting it would make callers roll back state that is already
// on disk).
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := fill(tmp, data, perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	committed = true

	syncDir(dir)
	return nil
}

// fill sets f's mode, writes data to it and fsyncs it.
func fill(f *os.File, data []byte, perm os.FileMode) error {
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync: %w", err)
	}
	return nil
}

// syncDir fsyncs dir, logging (not returning) any failure.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		slog.Warn("atomicfile: open dir for fsync", "dir", dir, "error", err)
		return
	}
	if err := d.Sync(); err != nil {
		slog.Warn("atomicfile: fsync dir", "dir", dir, "error", err)
	}
	if err := d.Close(); err != nil {
		slog.Warn("atomicfile: close dir", "dir", dir, "error", err)
	}
}
