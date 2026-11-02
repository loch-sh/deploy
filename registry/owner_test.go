package registry

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

// acmeShopAPI and acmeShop_API both slug to namespace "acme-shop-api".
var (
	ownerA = Owner{Namespace: "acme-shop-api", Environment: "staging", ProjectID: "1", ProjectPath: "acme-shop/api", EnvironmentName: "staging"}
	ownerB = Owner{Namespace: "acme-shop-api", Environment: "staging", ProjectID: "2", ProjectPath: "acme/shop-api", EnvironmentName: "staging"}
)

func TestClaimOwner_recordsExactTuple(t *testing.T) {
	r := newTestRegistry(t)
	if err := r.ClaimOwner(ownerA); err != nil {
		t.Fatal(err)
	}
	e, ok := r.Lookup("acme-shop-api", "staging")
	if !ok || e.ProjectID != "1" || e.ProjectPath != "acme-shop/api" || e.Environment != "staging" || e.ClaimedAt.IsZero() {
		t.Fatalf("entry = %+v", e)
	}
}

func TestClaimOwner_collision(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.ClaimOwner(ownerA)

	err := r.ClaimOwner(ownerB)
	if !errors.Is(err, ErrKeyCollision) || !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("expected ErrKeyCollision (wrapping ErrOwnerMismatch), got %v", err)
	}
	if err := r.VerifyOwner(ownerB); !errors.Is(err, ErrKeyCollision) {
		t.Errorf("verify: expected ErrKeyCollision, got %v", err)
	}
	if err := r.ReleaseOwner(ownerB); !errors.Is(err, ErrKeyCollision) {
		t.Errorf("release: expected ErrKeyCollision, got %v", err)
	}
	// Different project_id without a known tuple is a plain mismatch.
	if err := r.Claim("acme-shop-api", "staging", "2"); !errors.Is(err, ErrOwnerMismatch) {
		t.Errorf("expected ErrOwnerMismatch, got %v", err)
	}
}

func TestClaimOwner_sameProjectNewPath(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.ClaimOwner(ownerA)

	renamed := ownerA
	renamed.ProjectPath = "acme/shop/api"
	if err := r.ClaimOwner(renamed); err != nil {
		t.Fatalf("same project_id must be allowed: %v", err)
	}
	if e, _ := r.Lookup("acme-shop-api", "staging"); e.ProjectPath != "acme/shop/api" {
		t.Errorf("project_path not updated: %+v", e)
	}
	if err := r.VerifyOwner(ownerA); err != nil {
		t.Errorf("verify with old path, same project_id: %v", err)
	}
}

func TestClaimOwner_fillsLegacyMetadata(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.Claim("acme-shop-api", "staging", "1")
	if err := r.ClaimOwner(ownerA); err != nil {
		t.Fatal(err)
	}
	if e, _ := r.Lookup("acme-shop-api", "staging"); e.ProjectPath != "acme-shop/api" {
		t.Errorf("metadata not filled: %+v", e)
	}
}

// A failing write must leave the in-memory state untouched, so a later
// request does not see a claim that was never persisted.
func TestClaimAndRelease_rollbackOnFlushFailure(t *testing.T) {
	dir := t.TempDir()
	r, err := Load(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Claim("kept", "env", "1"); err != nil {
		t.Fatal(err)
	}
	// Replace the state directory with a file: every later write fails.
	must(t, os.RemoveAll(filepath.Join(dir, "state")))
	must(t, os.WriteFile(filepath.Join(dir, "state"), nil, 0o600))

	err = r.Claim("app", "staging", "1")
	if err == nil || errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("expected a write error (not an ownership error), got %v", err)
	}
	if _, ok := r.Lookup("app", "staging"); ok {
		t.Error("failed claim must be rolled back")
	}
	if err := r.ClaimOwner(Owner{Namespace: "kept", Environment: "env", ProjectID: "1", ProjectPath: "x/y"}); err == nil {
		t.Error("expected write error on metadata update")
	}
	if e, _ := r.Lookup("kept", "env"); e.ProjectPath != "" {
		t.Error("failed metadata update must be rolled back")
	}
	if err := r.Release("kept", "env", "1"); err == nil {
		t.Error("expected write error on release")
	}
	if _, ok := r.Lookup("kept", "env"); !ok {
		t.Error("failed release must be rolled back")
	}
	if _, err := r.Import(map[string]Entry{"new-env": {ProjectID: "3"}}); err == nil {
		t.Error("expected write error on import")
	}
	if _, ok := r.Lookup("new", "env"); ok {
		t.Error("failed import must be rolled back")
	}
}

func TestFlush_noTempFileLeft(t *testing.T) {
	dir := t.TempDir()
	r, _ := Load(dir)
	_ = r.ClaimOwner(ownerA)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "registry.json" {
		t.Errorf("state dir = %v", entries)
	}
}

// TestLoad_formats pins the exact on-disk / hand-edited JSON format: Entry
// objects and legacy bare project_id strings may be mixed.
func TestLoad_formats(t *testing.T) {
	dir := t.TempDir()
	doc := `{
  "acme-shop-staging": {
    "project_id": "42",
    "project_path": "acme/shop",
    "environment": "staging",
    "claimed_at": "2026-10-16T09:00:00Z"
  },
  "legacy-app-production": "17"
}`
	must(t, os.WriteFile(filepath.Join(dir, "registry.json"), []byte(doc), 0o600))
	r, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := r.Lookup("acme-shop", "staging"); e.ProjectID != "42" || e.ProjectPath != "acme/shop" || e.ClaimedAt.Year() != 2026 {
		t.Errorf("object entry = %+v", e)
	}
	if err := r.Verify("legacy-app", "production", "17"); err != nil {
		t.Errorf("legacy entry: %v", err)
	}

	// Re-saving converts legacy values to objects.
	_ = r.Claim("other", "env", "5")
	raw, _ := os.ReadFile(filepath.Join(dir, "registry.json"))
	if !strings.Contains(string(raw), `"legacy-app-production": {`) {
		t.Errorf("legacy entry not upgraded on save:\n%s", raw)
	}
}

func TestParseEntries_rejects(t *testing.T) {
	for name, doc := range map[string]string{
		"not an object":   `[]`,
		"bad key":         `{"../etc": "1"}`,
		"empty id":        `{"a-b": ""}`,
		"missing id":      `{"a-b": {"project_path": "a/b"}}`,
		"wrong type":      `{"a-b": 12}`,
		"uppercase key":   `{"A-b": "1"}`,
		"trailing hyphen": `{"a-b-": "1"}`,
	} {
		if _, err := ParseEntries([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestImport(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.Claim("owned", "staging", "1")
	_ = r.Claim("same", "staging", "2")

	changed, err := r.Import(map[string]Entry{
		"legacy-production": {ProjectID: "7", ProjectPath: "legacy", Environment: "production"},
		"same-staging":      {ProjectID: "2", ProjectPath: "same"},
		"owned-staging":     {ProjectID: "1"}, // identical: no change
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"legacy-production", "same-staging"}; !reflect.DeepEqual(changed, want) {
		t.Errorf("changed = %v, want %v", changed, want)
	}
	if err := r.Verify("legacy", "production", "7"); err != nil {
		t.Errorf("imported entry: %v", err)
	}
	if e, _ := r.Lookup("same", "staging"); e.ProjectPath != "same" {
		t.Errorf("metadata not filled: %+v", e)
	}

	// Nothing to do.
	if changed, err := r.Import(map[string]Entry{"owned-staging": {ProjectID: "1"}}); err != nil || changed != nil {
		t.Errorf("no-op import = %v, %v", changed, err)
	}
}

func TestImport_conflictIsAllOrNothing(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.Claim("owned", "staging", "1")

	_, err := r.Import(map[string]Entry{
		"fresh-staging": {ProjectID: "3"},
		"owned-staging": {ProjectID: "9"},
	})
	if !errors.Is(err, ErrOwnerMismatch) {
		t.Fatalf("expected ErrOwnerMismatch, got %v", err)
	}
	if _, ok := r.Lookup("fresh", "staging"); ok {
		t.Error("import with a conflict must not apply any entry")
	}

	for name, in := range map[string]map[string]Entry{
		"bad key":    {"Bad Key": {ProjectID: "1"}},
		"missing id": {"a-b": {}},
	} {
		if _, err := r.Import(in); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestImportFile(t *testing.T) {
	dir := t.TempDir()
	r := newTestRegistry(t)

	path := filepath.Join(dir, "import.json")
	must(t, os.WriteFile(path, []byte(`{"legacy-app-production": "17"}`), 0o600))
	if changed, err := r.ImportFile(path); err != nil || len(changed) != 1 {
		t.Fatalf("ImportFile = %v, %v", changed, err)
	}

	if _, err := r.ImportFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("expected error for a missing file")
	}
	must(t, os.WriteFile(path, []byte(`{`), 0o600))
	if _, err := r.ImportFile(path); err == nil {
		t.Error("expected error for corrupt file")
	}
}
