package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deploy-server/registry"
)

func (e *testEnv) stopHandler() http.Handler {
	return Stop(StopConfig{ComposeBase: e.composeBase, Registry: e.reg, Scheduler: e.sched})
}

// seedStack simulates a previous deploy of testKey owned by project 1.
func (e *testEnv) seedStack(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(e.stackDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.stackDir(), "docker-compose.yml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.reg.Claim("group-app", "staging", "1"); err != nil {
		t.Fatal(err)
	}
	if err := e.sched.Schedule("group-app", "staging", time.Hour); err != nil {
		t.Fatal(err)
	}
}

func stopRequest() *http.Request { return httptest.NewRequest("DELETE", "/stack", nil) }

func TestStop_success(t *testing.T) {
	e := newTestEnv(t)
	e.seedStack(t)

	assertStatus(t, serve(e.stopHandler(), stopRequest(), defaultClaims()), http.StatusNoContent)

	if _, err := os.Stat(e.stackDir()); !os.IsNotExist(err) {
		t.Error("stack dir should be removed")
	}
	if calls := e.docker.Calls(); len(calls) != 3 || !strings.HasSuffix(calls[0], " down --remove-orphans") ||
		calls[1] != psCalls()[0] || calls[2] != psCalls()[1] {
		t.Errorf("docker calls = %q", calls)
	}
	// Ownership released: another project may now claim the key.
	if _, ok := e.reg.Lookup("group-app", "staging"); ok {
		t.Error("registry entry should be released")
	}
	if strings.Contains(e.autostopFile(), "group-app/staging") {
		t.Error("pending auto-stop should be cancelled")
	}
}

// A stack no project has claimed (never deployed, already stopped, or a
// legacy stack not imported into the registry) must not be touched.
func TestStop_notClaimedIsForbidden(t *testing.T) {
	e := newTestEnv(t)
	if err := os.MkdirAll(e.stackDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(e.stackDir(), "docker-compose.yml"), nil, 0o600)

	rec := serve(e.stopHandler(), stopRequest(), defaultClaims())
	assertStatus(t, rec, http.StatusForbidden)
	if !strings.Contains(rec.Body.String(), "not owned by any") {
		t.Errorf("body = %q", rec.Body.String())
	}
	if e.docker.Calls() != nil {
		t.Error("compose down must not run on an unclaimed stack")
	}
	if _, err := os.Stat(e.stackDir()); err != nil {
		t.Error("unclaimed stack must be left untouched")
	}
}

func TestStop_secondStopIsForbidden(t *testing.T) {
	e := newTestEnv(t)
	e.seedStack(t)
	assertStatus(t, serve(e.stopHandler(), stopRequest(), defaultClaims()), http.StatusNoContent)
	assertStatus(t, serve(e.stopHandler(), stopRequest(), defaultClaims()), http.StatusForbidden)
}

func TestStop_keyCollisionIsForbidden(t *testing.T) {
	e := newTestEnv(t)
	e.seedStack(t)
	// Record the owner's exact project_path; the caller is a different project
	// whose own project_path ("group-app") slugs to the same key.
	if err := e.reg.ClaimOwner(registry.Owner{Namespace: "group-app", Environment: "staging", ProjectID: "1", ProjectPath: "group/app"}); err != nil {
		t.Fatal(err)
	}
	claims := defaultClaims()
	claims.ProjectID = "99"
	claims.ProjectPath = "group-app"
	rec := serve(e.stopHandler(), stopRequest(), claims)
	assertStatus(t, rec, http.StatusForbidden)
	if !strings.Contains(rec.Body.String(), "collides") {
		t.Errorf("body = %q, want a collision message", rec.Body.String())
	}
}

func TestStop_rejections(t *testing.T) {
	t.Run("no claims", func(t *testing.T) {
		e := newTestEnv(t)
		assertStatus(t, serve(e.stopHandler(), stopRequest(), nil), http.StatusUnauthorized)
	})

	t.Run("owned by another project", func(t *testing.T) {
		e := newTestEnv(t)
		e.seedStack(t)
		claims := defaultClaims()
		claims.ProjectID = "99"

		assertStatus(t, serve(e.stopHandler(), stopRequest(), claims), http.StatusForbidden)
		if _, err := os.Stat(e.stackDir()); err != nil {
			t.Error("stack of another project must be left untouched")
		}
	})

	t.Run("stack locked", func(t *testing.T) {
		e := newTestEnv(t)
		holdStackLock(t)
		assertStatus(t, serve(e.stopHandler(), cancelledRequest(stopRequest()), defaultClaims()), http.StatusServiceUnavailable)
	})
}

func TestStop_composeDownFailure(t *testing.T) {
	e := newTestEnv(t)
	e.seedStack(t)
	e.docker.FailOn(t, "down")

	assertStatus(t, serve(e.stopHandler(), stopRequest(), defaultClaims()), http.StatusInternalServerError)
	if _, err := os.Stat(e.stackDir()); err != nil {
		t.Error("stack dir must be kept when compose down fails")
	}
	if err := e.reg.Verify("group-app", "staging", "99"); err == nil {
		t.Error("ownership must be kept when compose down fails")
	}
}

func TestOwnershipError_statuses(t *testing.T) {
	for err, want := range map[error]int{
		registry.ErrNotClaimed:    http.StatusForbidden,
		registry.ErrKeyCollision:  http.StatusForbidden,
		registry.ErrOwnerMismatch: http.StatusForbidden,
		os.ErrPermission:          http.StatusInternalServerError,
	} {
		rec := httptest.NewRecorder()
		ownershipError(rec, err)
		if rec.Code != want {
			t.Errorf("%v: status = %d, want %d", err, rec.Code, want)
		}
	}
}
