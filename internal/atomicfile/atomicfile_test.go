package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteFile_CreatesAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")

	must(t, WriteFile(path, []byte("one"), 0o600))
	must(t, WriteFile(path, []byte("two"), 0o600))

	got, err := os.ReadFile(path)
	must(t, err)
	if string(got) != "two" {
		t.Fatalf("content = %q, want %q", got, "two")
	}
	fi, err := os.Stat(path)
	must(t, err)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	must(t, err)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, want 0700", di.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	must(t, err)
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestWriteFile_Perm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	must(t, WriteFile(path, nil, 0o640))
	fi, err := os.Stat(path)
	must(t, err)
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v, want 0640", fi.Mode().Perm())
	}
}

func TestWriteFile_ParentIsAFile(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "state")
	must(t, os.WriteFile(blocker, nil, 0o600))

	if err := WriteFile(filepath.Join(blocker, "f.json"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected an error when the parent is a regular file")
	}
}

func TestWriteFile_DirNotWritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	must(t, os.Mkdir(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := WriteFile(filepath.Join(dir, "f.json"), []byte("x"), 0o600); err == nil {
		t.Fatal("expected an error when the directory is not writable")
	}
}

func TestWriteFile_TargetIsADirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "state.json")
	must(t, os.Mkdir(target, 0o700))
	must(t, os.WriteFile(filepath.Join(target, "keep"), nil, 0o600))

	if err := WriteFile(target, []byte("x"), 0o600); err == nil {
		t.Fatal("expected an error when the target is a non-empty directory")
	}
	entries, err := os.ReadDir(dir)
	must(t, err)
	if len(entries) != 1 {
		t.Fatalf("temp file not cleaned up: %v", entries)
	}
}

func TestSyncDir_MissingDirIsOnlyLogged(t *testing.T) {
	syncDir(filepath.Join(t.TempDir(), "missing")) // must not panic
}

func TestFill_Errors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	must(t, os.WriteFile(path, nil, 0o600))

	ro, err := os.Open(path)
	must(t, err)
	defer func() { _ = ro.Close() }()
	if err := fill(ro, []byte("x"), 0o600); err == nil {
		t.Fatal("expected a write error on a read-only file")
	}

	closed, err := os.Open(path)
	must(t, err)
	must(t, closed.Close())
	if err := fill(closed, nil, 0o600); err == nil {
		t.Fatal("expected a chmod error on a closed file")
	}
}
