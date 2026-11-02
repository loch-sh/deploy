package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"deploy-server/compose"
	"deploy-server/middleware"
	"deploy-server/registry"
)

// composeUpload is a minimal compose file. It is JSON (valid YAML) so that the
// config-aware fake docker can echo it back as the rendered model.
var composeUpload = upload{"compose_file", "docker-compose.yml", `{"services":{}}`}

// composeWith returns a compose upload with the given JSON content.
func composeWith(content string) upload { return upload{"compose_file", "docker-compose.yml", content} }

// configAwareDocker wraps the fake docker so that `docker compose ... config`
// prints the file passed with -f (the uploaded compose, used as the rendered
// model). The call is still recorded, and FailOn("config") still applies.
func (e *testEnv) configAwareDocker(t *testing.T) {
	t.Helper()
	orig, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`#!/bin/sh
f=""; prev=""; cfg=0
for a in "$@"; do
  [ "$prev" = "-f" ] && f="$a"
  [ "$a" = "config" ] && cfg=1
  prev="$a"
done
if [ "$cfg" = 1 ]; then
  %q "$@" > /dev/null || exit $?
  cat "$f"
  exit 0
fi
exec %q "$@"
`, orig, orig)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// newDeployEnv is newTestEnv with a config-aware fake docker.
func newDeployEnv(t *testing.T) *testEnv {
	t.Helper()
	e := newTestEnv(t)
	e.configAwareDocker(t)
	return e
}

func (e *testEnv) deploy() http.Handler {
	return Deploy(DeployConfig{
		ComposeBase:             e.composeBase,
		WebsitesBase:            e.websitesBase,
		MaxUploadMB:             1,
		Registry:                e.reg,
		Scheduler:               e.sched,
		ProtectedEnvs:           map[string]bool{"production": true},
		ForbiddenTraefikHosts:   []string{"deploy.example.com"},
		AllowedExternalNetworks: []string{"traefik"},
	})
}

// psCalls are the docker ps calls compose.StackContainers runs for testKey.
func psCalls() []string {
	return []string{
		"ps --all --no-trunc --filter label=com.docker.compose.project=" + testKey + " --format {{.ID}}",
		"ps --all --no-trunc --filter name=^/?" + testKey + "[-_] --format {{.ID}}",
	}
}

// composeCalls returns calls without the container inspection ones (docker
// ps, docker inspect).
func composeCalls(calls []string) []string {
	var out []string
	for _, c := range calls {
		if !strings.HasPrefix(c, "ps ") && !strings.HasPrefix(c, "inspect ") {
			out = append(out, c)
		}
	}
	return out
}

// pinnedArgs is the project pinning every compose call must carry.
func pinnedArgs(dir string) string {
	return "compose -p " + testKey + " --project-directory " + dir + " -f " + filepath.Join(dir, "docker-compose.yml") + " "
}

// assertNoStaging fails if a staging directory was left in the compose base.
func (e *testEnv) assertNoStaging(t *testing.T) {
	t.Helper()
	entries, _ := os.ReadDir(e.composeBase)
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), ".staging-") {
			t.Errorf("staging directory left behind: %s", ent.Name())
		}
	}
}

func TestDeploy_success(t *testing.T) {
	e := newDeployEnv(t)

	r := multipartRequest(t, "/deploy", []upload{
		composeUpload,
		{"env_files", "api.env", "A=1\n"},
		{"env_files", ".env", "B=2\n"},
	}, map[string]string{"auto_stop_days": "7"})
	assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusNoContent)

	for name, want := range map[string]string{
		"docker-compose.yml": `{"services":{}}`,
		"api.env":            "A=1\n",
		".env":               "B=2\n",
	} {
		got, err := os.ReadFile(filepath.Join(e.stackDir(), name))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, want)
		}
	}

	calls := e.docker.Calls()
	if len(calls) != 5 {
		t.Fatalf("docker calls = %q", calls)
	}
	// The existing containers are inspected first (none here: no inspect).
	if ps := psCalls(); calls[0] != ps[0] || calls[1] != ps[1] {
		t.Errorf("inspection calls = %q, want %q", calls[:2], ps)
	}
	// The model is rendered from the staging directory, pinned to the stack.
	if !strings.HasPrefix(calls[2], "compose -p "+testKey+" --project-directory "+filepath.Join(e.composeBase, ".staging-")) ||
		!strings.HasSuffix(calls[2], " config --format json --no-env-resolution") {
		t.Errorf("config call = %q", calls[2])
	}
	pinned := pinnedArgs(e.stackDir())
	if calls[3] != pinned+"pull" || calls[4] != pinned+"up -d --remove-orphans --no-build" {
		t.Errorf("docker calls = %q", calls)
	}
	e.assertNoStaging(t)

	if err := e.reg.Verify("group-app", "staging", "1"); err != nil {
		t.Errorf("stack should now be owned by project 1: %v", err)
	}
	if !strings.Contains(e.autostopFile(), "group-app/staging") {
		t.Errorf("auto-stop not scheduled: %s", e.autostopFile())
	}
}

func TestDeploy_redeployPrunesEnvFilesAndCancelsAutoStop(t *testing.T) {
	e := newDeployEnv(t)
	h := e.deploy()

	first := multipartRequest(t, "/deploy", []upload{composeUpload, {"env_files", "old.env", "X=1"}},
		map[string]string{"auto_stop_days": "3"})
	assertStatus(t, serve(h, first, defaultClaims()), http.StatusNoContent)

	second := multipartRequest(t, "/deploy", []upload{composeUpload, {"env_files", "api.env", "A=1"}}, nil)
	assertStatus(t, serve(h, second, defaultClaims()), http.StatusNoContent)

	if _, err := os.Stat(filepath.Join(e.stackDir(), "old.env")); !os.IsNotExist(err) {
		t.Error("stale env file from the previous deploy should be removed")
	}
	if _, err := os.Stat(filepath.Join(e.stackDir(), "api.env")); err != nil {
		t.Errorf("new env file missing: %v", err)
	}
	if strings.Contains(e.autostopFile(), "group-app/staging") {
		t.Error("deploy without auto_stop_days must cancel the pending auto-stop")
	}
}

func TestDeploy_rejectedBeforeTouchingDiskOrDocker(t *testing.T) {
	tests := []struct {
		name   string
		claims *middleware.Claims
		files  []upload
		fields map[string]string
		want   int
	}{
		{"no claims", nil, []upload{composeUpload}, nil, http.StatusUnauthorized},
		{"protected env from unprotected ref",
			&middleware.Claims{ProjectPath: "group/app", ProjectID: "1", Environment: "production"},
			[]upload{composeUpload}, nil, http.StatusForbidden},
		{"invalid auto_stop_days", defaultClaims(), []upload{composeUpload}, map[string]string{"auto_stop_days": "0"}, http.StatusBadRequest},
		{"auto_stop_days over a year", defaultClaims(), []upload{composeUpload}, map[string]string{"auto_stop_days": "366"}, http.StatusBadRequest},
		{"env file overriding compose", defaultClaims(), []upload{composeUpload, {"env_files", "docker-compose.yml", "x"}}, nil, http.StatusBadRequest},
		// mime/multipart already strips path components from file names, so
		// only the name pattern itself can be exercised here.
		{"env file with invalid name", defaultClaims(), []upload{composeUpload, {"env_files", "my env", "x"}}, nil, http.StatusBadRequest},
		{"duplicate env file", defaultClaims(), []upload{composeUpload, {"env_files", "a.env", "1"}, {"env_files", "a.env", "2"}}, nil, http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newDeployEnv(t)
			r := multipartRequest(t, "/deploy", tc.files, tc.fields)
			assertStatus(t, serve(e.deploy(), r, tc.claims), tc.want)

			if _, err := os.Stat(e.stackDir()); !os.IsNotExist(err) {
				t.Error("stack directory must not be created")
			}
			if e.docker.Calls() != nil {
				t.Errorf("docker must not be called: %q", e.docker.Calls())
			}
		})
	}
}

// TestDeploy_policyRejections checks that an unsafe compose model is refused
// with a precise 400 before anything is installed, started or claimed, and
// that the previously deployed files are left untouched.
func TestDeploy_policyRejections(t *testing.T) {
	tests := []struct {
		name    string
		files   []upload
		want    string
		configd bool // whether docker compose config ran
	}{
		{"privileged", []upload{composeWith(`{"services":{"web":{"image":"x","privileged":true}}}`)},
			`service \"web\": privileged: not allowed`, true},
		{"host bind mount", []upload{composeWith(`{"services":{"web":{"volumes":[{"type":"bind","source":"/","target":"/host"}]}}}`)},
			`bind source must be inside the stack's websites directory`, true},
		{"external network not allowed", []upload{composeWith(`{"networks":{"db":{"external":true}}}`)},
			`network \"db\": external`, true},
		{"forbidden traefik host", []upload{composeWith(`{"services":{"web":{"labels":{"traefik.http.routers.w.rule":"Host(` + "`deploy.example.com`" + `)"}}}}`)},
			`is reserved`, true},
		{"foreign container name", []upload{composeWith(`{"services":{"web":{"container_name":"other-prod-db"}}}`)},
			`container_name`, true},
		{"extends", []upload{composeWith("services:\n  web:\n    extends: {file: /etc/passwd, service: a}\n")},
			`service \"web\": extends: not allowed`, false},
		{"include", []upload{composeWith("include: [/etc/hosts]\n")}, `include: not allowed`, false},
		{"invalid yaml", []upload{composeWith("services: [\n")}, `not a valid YAML mapping`, false},
		{"project name in .env", []upload{composeUpload, {"env_files", ".env", "COMPOSE_PROJECT_NAME=other-prod\n"}},
			`COMPOSE_PROJECT_NAME`, false},
		{"rendered model is not JSON", []upload{composeWith("services: {}\n")}, `could not be rendered`, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newDeployEnv(t)
			// A previous deploy left files the rejected one must not touch.
			must(t, os.MkdirAll(e.stackDir(), 0o700))
			must(t, os.WriteFile(filepath.Join(e.stackDir(), "docker-compose.yml"), []byte("previous"), 0o600))

			r := multipartRequest(t, "/deploy", tc.files, nil)
			rec := serve(e.deploy(), r, defaultClaims())
			assertStatus(t, rec, http.StatusBadRequest)
			body := rec.Body.String()
			if !strings.Contains(fmt.Sprintf("%q", body), tc.want) {
				t.Errorf("body = %q, want %q", body, tc.want)
			}
			if strings.Contains(body, e.composeBase) || strings.Contains(body, e.websitesBase) {
				t.Errorf("body leaks a server path: %q", body)
			}

			calls := composeCalls(e.docker.Calls())
			if tc.configd && (len(calls) != 1 || !strings.Contains(calls[0], " config ")) {
				t.Errorf("docker calls = %q, want only config", calls)
			}
			if !tc.configd && calls != nil {
				t.Errorf("docker must not be called: %q", calls)
			}
			if got, _ := os.ReadFile(filepath.Join(e.stackDir(), "docker-compose.yml")); string(got) != "previous" {
				t.Errorf("previous compose file was modified: %q", got)
			}
			e.assertNoStaging(t)
			if err := e.reg.Verify("group-app", "staging", "1"); !errors.Is(err, registry.ErrNotClaimed) {
				t.Errorf("a rejected deploy must not claim the stack: %v", err)
			}
		})
	}
}

func TestDeploy_allowedExternalNetwork(t *testing.T) {
	e := newDeployEnv(t)
	composeJSON := `{"services":{"web":{"networks":{"traefik":null}}},"networks":{"traefik":{"name":"traefik","external":true}}}`

	r := multipartRequest(t, "/deploy", []upload{composeWith(composeJSON)}, nil)
	assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusNoContent)
}

func TestDeploy_bindMount(t *testing.T) {
	bindCompose := func(src string) string {
		return `{"services":{"web":{"volumes":[{"type":"bind","source":"` + src + `","target":"/s"}]}}}`
	}

	t.Run("service/name directory created by /directories", func(t *testing.T) {
		e := newDeployEnv(t)
		src := filepath.Join(e.websitesBase, testKey, "web", "storage")
		if err := os.MkdirAll(src, 0o755); err != nil {
			t.Fatal(err)
		}
		r := multipartRequest(t, "/deploy", []upload{composeWith(bindCompose(src))}, nil)
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusNoContent)
	})

	refused := []struct {
		name  string
		setup func(t *testing.T, stackDir string) string // returns the bind source
		want  string
	}{
		{"stack directory itself", func(t *testing.T, d string) string { return d }, "must be exactly <service>/<name>"},
		{"service directory", func(t *testing.T, d string) string { return filepath.Join(d, "web") }, "must be exactly <service>/<name>"},
		{"below a name directory", func(t *testing.T, d string) string {
			src := filepath.Join(d, "web", "storage", "sub")
			if err := os.MkdirAll(src, 0o755); err != nil {
				t.Fatal(err)
			}
			return src
		}, "must be exactly <service>/<name>"},
		{"not created yet", func(t *testing.T, d string) string { return filepath.Join(d, "web", "storage") }, "does not exist"},
		{"service directory swapped for a symlink", func(t *testing.T, d string) string {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/", filepath.Join(d, "api")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(d, "api", "etc")
		}, `component "api" is a symbolic link`},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			e := newDeployEnv(t)
			src := tc.setup(t, filepath.Join(e.websitesBase, testKey))
			r := multipartRequest(t, "/deploy", []upload{composeWith(bindCompose(src))}, nil)
			rec := serve(e.deploy(), r, defaultClaims())
			assertStatus(t, rec, http.StatusBadRequest)
			if body := rec.Body.String(); !strings.Contains(body, tc.want) || strings.Contains(body, e.websitesBase) {
				t.Errorf("body = %q, want it to contain %q without server paths", body, tc.want)
			}
		})
	}
}

func TestDeploy_configFailures(t *testing.T) {
	t.Run("rejected by docker compose", func(t *testing.T) {
		e := newDeployEnv(t)
		e.docker.FailOn(t, "config")

		rec := serve(e.deploy(), multipartRequest(t, "/deploy", []upload{composeUpload}, nil), defaultClaims())
		assertStatus(t, rec, http.StatusBadRequest)
		if !strings.Contains(rec.Body.String(), "invalid compose file: fake failure on config") {
			t.Errorf("body = %q", rec.Body.String())
		}
		e.assertNoStaging(t)
	})

	t.Run("docker cannot run", func(t *testing.T) {
		e := newDeployEnv(t)
		t.Setenv("PATH", t.TempDir())

		rec := serve(e.deploy(), multipartRequest(t, "/deploy", []upload{composeUpload}, nil), defaultClaims())
		assertStatus(t, rec, http.StatusInternalServerError)
	})
}

func TestDeploy_invalidMultipart(t *testing.T) {
	e := newDeployEnv(t)

	t.Run("not multipart", func(t *testing.T) {
		r := jsonRequest("POST", "/deploy", "{}")
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusBadRequest)
	})

	t.Run("body over MaxUploadMB", func(t *testing.T) {
		big := strings.Repeat("x", 2<<20)
		r := multipartRequest(t, "/deploy", []upload{{"compose_file", "docker-compose.yml", big}}, nil)
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusBadRequest)
	})

	t.Run("missing compose_file", func(t *testing.T) {
		r := multipartRequest(t, "/deploy", []upload{{"env_files", "a.env", "1"}}, nil)
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusBadRequest)
		e.assertNoStaging(t)
	})
}

func TestDeploy_websitesBaseNotConfigured(t *testing.T) {
	e := newDeployEnv(t)
	r := multipartRequest(t, "/deploy", []upload{composeUpload}, nil)
	assertStatus(t, serve(e.deployHandler(), r, defaultClaims()), http.StatusInternalServerError)
	if e.docker.Calls() != nil {
		t.Error("docker must not be called")
	}
}

func TestDeploy_ownedByAnotherProject(t *testing.T) {
	e := newDeployEnv(t)
	if err := e.reg.Claim("group-app", "staging", "99"); err != nil {
		t.Fatal(err)
	}

	r := multipartRequest(t, "/deploy", []upload{composeUpload}, nil)
	assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusForbidden)
	if e.docker.Calls() != nil {
		t.Error("docker must not be called")
	}
}

func TestDeploy_composeFailures(t *testing.T) {
	for _, step := range []string{"pull", "up"} {
		t.Run(step, func(t *testing.T) {
			e := newDeployEnv(t)
			e.docker.FailOn(t, step)

			r := multipartRequest(t, "/deploy", []upload{composeUpload}, map[string]string{"auto_stop_days": "1"})
			rec := serve(e.deploy(), r, defaultClaims())
			assertStatus(t, rec, http.StatusInternalServerError)
			if !strings.Contains(rec.Body.String(), "docker compose "+step+" failed: fake failure on "+step) {
				t.Errorf("body = %q", rec.Body.String())
			}
			if e.autostopFile() != "" {
				t.Error("a failed deploy must not schedule an auto-stop")
			}
			// A failed first deploy must not squat the key.
			if err := e.reg.Verify("group-app", "staging", "1"); !errors.Is(err, registry.ErrNotClaimed) {
				t.Errorf("failed first deploy claimed the stack: %v", err)
			}
		})
	}

	t.Run("failed redeploy keeps ownership", func(t *testing.T) {
		e := newDeployEnv(t)
		must(t, e.reg.Claim("group-app", "staging", "1"))
		e.docker.FailOn(t, "up")

		r := multipartRequest(t, "/deploy", []upload{composeUpload}, nil)
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusInternalServerError)
		if err := e.reg.Verify("group-app", "staging", "1"); err != nil {
			t.Errorf("ownership lost after a failed redeploy: %v", err)
		}
	})
}

func TestDeploy_claimWriteFailure(t *testing.T) {
	e := newDeployEnv(t)
	if err := os.MkdirAll(e.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	must(t, os.Chmod(e.dataDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(e.dataDir, 0o700) })
	if f, err := os.Create(filepath.Join(e.dataDir, "probe")); err == nil {
		_ = f.Close()
		t.Skip("data directory is still writable (running as root?)")
	}

	r := multipartRequest(t, "/deploy", []upload{composeUpload}, nil)
	rec := serve(e.deploy(), r, defaultClaims())
	assertStatus(t, rec, http.StatusInternalServerError)
	if !strings.Contains(rec.Body.String(), "ownership could not be recorded") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestDeploy_filesystemFailures(t *testing.T) {
	t.Run("compose base is a file", func(t *testing.T) {
		e := newDeployEnv(t)
		must(t, os.MkdirAll(filepath.Dir(e.composeBase), 0o700))
		must(t, os.WriteFile(e.composeBase, nil, 0o600))

		r := multipartRequest(t, "/deploy", []upload{composeUpload}, nil)
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusInternalServerError)
	})

	t.Run("compose base not writable", func(t *testing.T) {
		e := newDeployEnv(t)
		must(t, os.MkdirAll(e.composeBase, 0o500))
		t.Cleanup(func() { _ = os.Chmod(e.composeBase, 0o700) })
		if f, err := os.Create(filepath.Join(e.composeBase, "probe")); err == nil {
			_ = f.Close()
			t.Skip("compose base is still writable (running as root?)")
		}

		r := multipartRequest(t, "/deploy", []upload{composeUpload}, nil)
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusInternalServerError)
	})

	t.Run("stack dir is a file", func(t *testing.T) {
		e := newDeployEnv(t)
		must(t, os.MkdirAll(e.composeBase, 0o700))
		must(t, os.WriteFile(e.stackDir(), nil, 0o600))

		r := multipartRequest(t, "/deploy", []upload{composeUpload}, nil)
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusInternalServerError)
	})

	t.Run("env file name taken by a directory", func(t *testing.T) {
		e := newDeployEnv(t)
		must(t, os.MkdirAll(filepath.Join(e.stackDir(), "api.env", "sub"), 0o700))

		r := multipartRequest(t, "/deploy", []upload{composeUpload, {"env_files", "api.env", "A=1"}}, nil)
		assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusInternalServerError)
		e.assertNoStaging(t)
	})
}

func TestDeploy_waitsForStackLock(t *testing.T) {
	e := newDeployEnv(t)
	holdStackLock(t)

	r := cancelledRequest(multipartRequest(t, "/deploy", []upload{composeUpload}, nil))
	assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusServiceUnavailable)
	if e.docker.Calls() != nil {
		t.Error("docker must not be called while the stack is locked")
	}
}

func TestClientExcerpt(t *testing.T) {
	dir := "/data/compose/.staging-x-123"
	got := clientExcerpt("error in "+dir+"/docker-compose.yml\n", dir)
	if got != "error in <stack>/docker-compose.yml" {
		t.Errorf("clientExcerpt = %q", got)
	}

	long := strings.Repeat("é", clientExcerptBytes) + "END"
	got = clientExcerpt(long, "")
	if len(got) > clientExcerptBytes+len("…") || !strings.HasSuffix(got, "END") || !strings.HasPrefix(got, "…") {
		t.Errorf("clientExcerpt(long) = %q (%d bytes)", got, len(got))
	}
	if !strings.Contains(got, "é") || strings.ContainsRune(got, '�') {
		t.Errorf("clientExcerpt must cut on a UTF-8 boundary: %q", got)
	}
}

func TestWriteReader_missingDir(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "missing", "file")
	if err := writeReader(strings.NewReader("x"), dest, 0o600); err == nil {
		t.Error("expected error when the destination directory does not exist")
	}
}

func TestPruneStackDir_missingDir(t *testing.T) {
	if err := pruneStackDir(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Error("expected error for a missing directory")
	}
}

func TestStopFunc(t *testing.T) {
	e := newTestEnv(t)
	must(t, os.MkdirAll(e.stackDir(), 0o700))
	must(t, os.WriteFile(filepath.Join(e.stackDir(), "docker-compose.yml"), nil, 0o600))

	t.Run("waits for the stack lock", func(t *testing.T) {
		unlock, _ := stackLocks.lock(context.Background(), testKey)
		defer unlock()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := StopFunc(e.composeBase)(ctx, "group-app", "staging"); err == nil {
			t.Error("expected error when the context is cancelled while waiting")
		}
	})

	t.Run("stops and removes the stack", func(t *testing.T) {
		if err := StopFunc(e.composeBase)(context.Background(), "group-app", "staging"); err != nil {
			t.Fatalf("StopFunc: %v", err)
		}
		if _, err := os.Stat(e.stackDir()); !os.IsNotExist(err) {
			t.Error("stack dir should be removed")
		}
		if calls := e.docker.Calls(); len(calls) != 3 || calls[0] != pinnedArgs(e.stackDir())+"down --remove-orphans" {
			t.Errorf("docker calls = %q", calls)
		}
	})
}

func TestDeploy_envFilesBracketField(t *testing.T) {
	e := newDeployEnv(t)

	r := multipartRequest(t, "/deploy", []upload{
		composeUpload,
		{"env_files[]", "api.env", "A=1\n"},
		{"env_files", "db.env", "B=2\n"},
	}, nil)
	assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusNoContent)

	for _, name := range []string{"api.env", "db.env"} {
		if _, err := os.Stat(filepath.Join(e.stackDir(), name)); err != nil {
			t.Errorf("%s not installed: %v", name, err)
		}
	}

	dup := multipartRequest(t, "/deploy", []upload{
		composeUpload, {"env_files[]", "a.env", "1"}, {"env_files", "a.env", "2"},
	}, nil)
	assertStatus(t, serve(e.deploy(), dup, defaultClaims()), http.StatusBadRequest)
}

func TestContextStatus(t *testing.T) {
	for err, want := range map[error]int{
		fmt.Errorf("up: %w", context.DeadlineExceeded): http.StatusGatewayTimeout,
		fmt.Errorf("up: %w", context.Canceled):         http.StatusServiceUnavailable,
		errors.New("exit status 1"):                    0,
	} {
		if got := contextStatus(err); got != want {
			t.Errorf("contextStatus(%v) = %d, want %d", err, got, want)
		}
	}
}

func TestComposeFailure_timeout(t *testing.T) {
	rec := httptest.NewRecorder()
	err := fmt.Errorf("docker compose up: %w (signal: interrupt)", context.DeadlineExceeded)
	composeFailure(rec, stack{}, "up", "/srv", &compose.Output{Stderr: "boom in /srv/x"}, err)
	if rec.Code != http.StatusGatewayTimeout || !strings.Contains(rec.Body.String(), "boom in <stack>/x") {
		t.Errorf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
}

func TestValidateStaged_contextErrors(t *testing.T) {
	e := newDeployEnv(t)
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(`{"services":{}}`), 0o600))
	st := stack{Key: testKey}
	policy := compose.Policy{Key: testKey, ProjectDir: dir, WebsitesDir: e.websitesBase}

	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	if code, _ := validateStaged(expired, st, dir, policy); code != http.StatusGatewayTimeout {
		t.Errorf("expired context: code = %d, want 504", code)
	}

	cancelled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if code, _ := validateStaged(cancelled, st, dir, policy); code != http.StatusServiceUnavailable {
		t.Errorf("cancelled context: code = %d, want 503", code)
	}
}
