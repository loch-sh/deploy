package registry

import (
	"errors"
	"testing"
)

func TestClaim_firstClaim(t *testing.T) {
	r := newTestRegistry(t)

	if err := r.Claim("myapp", "staging", "id-abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClaim_sameClaim(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.Claim("myapp", "staging", "id-abc")

	// Same project_id — must succeed (idempotent re-deploy).
	if err := r.Claim("myapp", "staging", "id-abc"); err != nil {
		t.Fatalf("re-claim with same id: unexpected error: %v", err)
	}
}

func TestClaim_ownerMismatch(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.Claim("myapp", "staging", "id-abc")

	if err := r.Claim("myapp", "staging", "id-xyz"); err != ErrOwnerMismatch {
		t.Fatalf("expected ErrOwnerMismatch, got %v", err)
	}
}

func TestRelease(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.Claim("myapp", "staging", "id-abc")

	if err := r.Release("myapp", "staging", "id-abc"); err != nil {
		t.Fatalf("release: %v", err)
	}

	// After release, a different id can claim the slot.
	if err := r.Claim("myapp", "staging", "id-xyz"); err != nil {
		t.Fatalf("claim after release: %v", err)
	}
}

func TestRelease_mismatch(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.Claim("myapp", "staging", "id-abc")

	if err := r.Release("myapp", "staging", "id-wrong"); err != ErrOwnerMismatch {
		t.Fatalf("expected ErrOwnerMismatch, got %v", err)
	}
}

func TestVerify(t *testing.T) {
	r := newTestRegistry(t)
	_ = r.Claim("myapp", "staging", "id-abc")

	if err := r.Verify("myapp", "staging", "id-abc"); err != nil {
		t.Errorf("verify with correct id: %v", err)
	}
	if err := r.Verify("myapp", "staging", "id-xyz"); err != ErrOwnerMismatch {
		t.Errorf("verify with wrong id: expected ErrOwnerMismatch, got %v", err)
	}
	// Unknown namespace/environment — not claimed: nobody may act on it.
	if err := r.Verify("unknown", "env", "any-id"); !errors.Is(err, ErrNotClaimed) {
		t.Errorf("verify for unclaimed slot: expected ErrNotClaimed, got %v", err)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()

	r1, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := r1.Claim("myapp", "staging", "id-abc"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// Load a second registry from the same directory — it should see the claim.
	r2, err := Load(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := r2.Claim("myapp", "staging", "id-xyz"); err != ErrOwnerMismatch {
		t.Fatalf("expected ErrOwnerMismatch after reload, got %v", err)
	}
}

// newTestRegistry creates an in-memory registry backed by a temp directory.
func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	r, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("newTestRegistry: %v", err)
	}
	return r
}
