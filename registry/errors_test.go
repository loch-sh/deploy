package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_stateFileErrors(t *testing.T) {
	t.Run("corrupt JSON", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "registry.json"), []byte("{"), 0o600)
		if _, err := Load(dir); err == nil {
			t.Error("expected error for corrupt registry")
		}
	})

	t.Run("unreadable path", func(t *testing.T) {
		dir := t.TempDir()
		os.Mkdir(filepath.Join(dir, "registry.json"), 0o700)
		if _, err := Load(dir); err == nil {
			t.Error("expected error when the registry file is a directory")
		}
	})
}

func TestClaim_flushFailure(t *testing.T) {
	dir := t.TempDir()
	r, err := Load(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	// Make the state directory impossible to create.
	os.WriteFile(filepath.Join(dir, "state"), nil, 0o600)

	if err := r.Claim("app", "staging", "1"); err == nil {
		t.Error("expected flush error")
	}
}
