package handlers

import (
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// claimTestStack registers defaultClaims' project as the owner of testKey.
func (e *testEnv) claimTestStack(t *testing.T) {
	t.Helper()
	if err := e.reg.Claim("group-app", "staging", defaultClaims().ProjectID); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) dirsHandler() http.Handler {
	return Directories(DirsConfig{WebsitesBase: e.websitesBase, Registry: e.reg})
}

func (e *testEnv) websiteDir(service, name string) string {
	return filepath.Join(e.websitesBase, testKey, service, name)
}

func newDirsRequest(body string) *http.Request { return jsonRequest("POST", "/directories", body) }

// currentOwner returns the current uid and gid.
func currentOwner(t *testing.T) (uid, gid int) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("current user: %v", err)
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid
}

func TestDirectories_success(t *testing.T) {
	e := newTestEnv(t)
	e.claimTestStack(t)
	uid, gid := currentOwner(t)

	body := fmt.Sprintf(`{"entries":[
		{"service":"api","name":"storage","mode":"0750","user":"%d"},
		{"service":"api","name":"jwt","mode":"0o700","user":"%d","group":"%d"},
		{"service":"mercure","name":"data","group":"%d"}
	]}`, uid, uid, gid, gid)
	assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusNoContent)

	for _, tc := range []struct {
		service, name string
		mode          os.FileMode
	}{
		{"api", "storage", 0o750},
		{"api", "jwt", 0o700},
		{"mercure", "data", 0o755},
	} {
		info, err := os.Stat(e.websiteDir(tc.service, tc.name))
		if err != nil {
			t.Errorf("%s/%s: %v", tc.service, tc.name, err)
			continue
		}
		if !info.IsDir() || info.Mode().Perm() != tc.mode {
			t.Errorf("%s/%s: mode = %v, want %v", tc.service, tc.name, info.Mode().Perm(), tc.mode)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && (int(st.Uid) != uid || int(st.Gid) != gid) {
			t.Errorf("%s/%s: owner = %d:%d, want %d:%d", tc.service, tc.name, st.Uid, st.Gid, uid, gid)
		}
	}

	// mode/user/group apply to the {name} leaf only: the stack and service
	// directories, which the compose policy never lets a container mount,
	// keep the server's default 0755 (SECURITY.md A2).
	for _, rel := range []string{testKey, filepath.Join(testKey, "api"), filepath.Join(testKey, "mercure")} {
		info, err := os.Lstat(filepath.Join(e.websitesBase, rel))
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o755 {
			t.Errorf("%s: mode = %v, want a 0755 directory", rel, info.Mode())
		}
	}
}

func TestDirectories_rejections(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"invalid JSON", `{`, http.StatusBadRequest},
		{"invalid service", `{"entries":[{"service":"API","name":"x"}]}`, http.StatusBadRequest},
		{"dot-dot name", `{"entries":[{"service":"api","name":".."}]}`, http.StatusBadRequest},
		{"name with slash", `{"entries":[{"service":"api","name":"a/b"}]}`, http.StatusBadRequest},
		{"invalid mode", `{"entries":[{"service":"api","name":"x","mode":"0999"}]}`, http.StatusBadRequest},
		{"setuid mode", `{"entries":[{"service":"api","name":"x","mode":"4755"}]}`, http.StatusBadRequest},
		{"sticky mode", `{"entries":[{"service":"api","name":"x","mode":"01777"}]}`, http.StatusBadRequest},
		{"user name", `{"entries":[{"service":"api","name":"x","user":"www-data"}]}`, http.StatusBadRequest},
		{"group name", `{"entries":[{"service":"api","name":"x","group":"www-data"}]}`, http.StatusBadRequest},
		{"negative uid", `{"entries":[{"service":"api","name":"x","user":"-1"}]}`, http.StatusBadRequest},
		{"uid out of range", `{"entries":[{"service":"api","name":"x","user":"2147483648"}]}`, http.StatusBadRequest},
		{"gid out of range", `{"entries":[{"service":"api","name":"x","group":"99999999999"}]}`, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			e.claimTestStack(t)
			assertStatus(t, serve(e.dirsHandler(), newDirsRequest(tc.body), defaultClaims()), tc.want)
			if _, err := os.Stat(e.websiteDir("api", "x")); !os.IsNotExist(err) {
				t.Error("nothing may be created for an invalid request")
			}
		})
	}

	t.Run("validation happens before any write", func(t *testing.T) {
		e := newTestEnv(t)
		e.claimTestStack(t)
		body := `{"entries":[{"service":"api","name":"ok"},{"service":"api","name":"bad","mode":"7777"}]}`
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusBadRequest)
		if _, err := os.Stat(e.websiteDir("api", "ok")); !os.IsNotExist(err) {
			t.Error("valid entry must not be applied when a later entry is invalid")
		}
	})

	// CI creates bind-mount directories before the first deploy.
	t.Run("not claimed yet is allowed", func(t *testing.T) {
		e := newTestEnv(t)
		body := `{"entries":[{"service":"api","name":"x"}]}`
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusNoContent)
		if _, err := os.Stat(e.websiteDir("api", "x")); err != nil {
			t.Errorf("directory must be created before the first deploy: %v", err)
		}
		if _, ok := e.reg.Lookup("group-app", "staging"); ok {
			t.Error("/directories must not claim the stack")
		}
	})

	t.Run("empty entries", func(t *testing.T) {
		e := newTestEnv(t)
		e.claimTestStack(t)
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(`{"entries":[]}`), defaultClaims()), http.StatusNoContent)
	})

	t.Run("no claims", func(t *testing.T) {
		e := newTestEnv(t)
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(`{"entries":[]}`), nil), http.StatusUnauthorized)
	})

	t.Run("owned by another project", func(t *testing.T) {
		e := newTestEnv(t)
		e.reg.Claim("group-app", "staging", "99")
		body := `{"entries":[{"service":"api","name":"x"}]}`
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusForbidden)
		if _, err := os.Stat(e.websiteDir("api", "x")); !os.IsNotExist(err) {
			t.Error("directory must not be created for another project's stack")
		}
	})
}

func TestDirectories_filesystemFailures(t *testing.T) {
	t.Run("websites base is a file", func(t *testing.T) {
		e := newTestEnv(t)
		e.claimTestStack(t)
		os.MkdirAll(filepath.Dir(e.websitesBase), 0o700)
		os.WriteFile(e.websitesBase, nil, 0o600)

		body := `{"entries":[{"service":"api","name":"x"}]}`
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusInternalServerError)
	})

	t.Run("chown to root as non-root", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: chown cannot fail")
		}
		e := newTestEnv(t)
		e.claimTestStack(t)
		body := `{"entries":[{"service":"api","name":"x","user":"0"}]}`
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusInternalServerError)
	})
}

// A tenant container controls the content of its bind-mounted directories and
// may plant symlinks there. None of them may be followed.
func TestDirectories_symlinkEscapes(t *testing.T) {
	// victim is a directory outside the stack whose mode must never change.
	setup := func(t *testing.T) (*testEnv, string) {
		t.Helper()
		e := newTestEnv(t)
		e.claimTestStack(t)
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.MkdirAll(victim, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(e.websitesBase, testKey), 0o755); err != nil {
			t.Fatal(err)
		}
		return e, victim
	}
	assertUntouched := func(t *testing.T, victim string) {
		t.Helper()
		info, err := os.Stat(victim)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("victim mode changed to %v", info.Mode().Perm())
		}
		if entries, _ := os.ReadDir(victim); len(entries) != 0 {
			t.Errorf("victim content changed: %v", entries)
		}
	}
	body := `{"entries":[{"service":"api","name":"storage","mode":"0777"}]}`

	t.Run("service dir is an absolute symlink", func(t *testing.T) {
		e, victim := setup(t)
		os.Symlink(victim, filepath.Join(e.websitesBase, testKey, "api"))
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusConflict)
		assertUntouched(t, victim)
	})

	t.Run("target dir is an absolute symlink", func(t *testing.T) {
		e, victim := setup(t)
		os.MkdirAll(filepath.Join(e.websitesBase, testKey, "api"), 0o755)
		os.Symlink(victim, e.websiteDir("api", "storage"))
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusConflict)
		assertUntouched(t, victim)
	})

	t.Run("target dir is a relative symlink to another stack", func(t *testing.T) {
		e, _ := setup(t)
		other := filepath.Join(e.websitesBase, "other-stack", "data")
		os.MkdirAll(other, 0o700)
		os.MkdirAll(filepath.Join(e.websitesBase, testKey, "api"), 0o755)
		os.Symlink("../../other-stack/data", e.websiteDir("api", "storage"))
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusConflict)
		assertUntouched(t, other)
	})

	t.Run("stack dir is a symlink to another stack", func(t *testing.T) {
		e, _ := setup(t)
		other := filepath.Join(e.websitesBase, "other-stack")
		os.MkdirAll(other, 0o700)
		os.Remove(filepath.Join(e.websitesBase, testKey))
		os.Symlink("other-stack", filepath.Join(e.websitesBase, testKey))
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusConflict)
		assertUntouched(t, other)
	})

	t.Run("target is a regular file", func(t *testing.T) {
		e, _ := setup(t)
		os.MkdirAll(filepath.Join(e.websitesBase, testKey, "api"), 0o755)
		os.WriteFile(e.websiteDir("api", "storage"), nil, 0o600)
		assertStatus(t, serve(e.dirsHandler(), newDirsRequest(body), defaultClaims()), http.StatusConflict)
	})
}

func TestParseID(t *testing.T) {
	for in, want := range map[string]int{"": -1, "0": 0, "33": 33, "2147483647": 2147483647} {
		if got, err := parseID("user", in); err != nil || got != want {
			t.Errorf("parseID(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"-1", "2147483648", "root", "1e3", " 1"} {
		if _, err := parseID("user", in); err == nil {
			t.Errorf("parseID(%q): expected error", in)
		}
	}
}
