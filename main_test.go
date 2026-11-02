package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"deploy-server/config"
	"deploy-server/internal/testutil"
	"deploy-server/middleware"
	"deploy-server/registry"
	"deploy-server/scheduler"
)

const testAudience = "https://deploy.example.com"

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

func testConfig(t *testing.T, issuer string) *config.Config {
	t.Helper()
	root := t.TempDir()
	return &config.Config{
		ListenAddr:            freeAddr(t),
		ComposeBase:           filepath.Join(root, "compose"),
		WebsitesBase:          filepath.Join(root, "websites"),
		DataDir:               filepath.Join(root, "data"),
		MaxUploadMB:           1,
		GitLabIssuer:          issuer,
		GitLabAudience:        testAudience,
		ProtectedEnvironments: map[string]bool{"production": true},
	}
}

// claimStack loads the registry in dataDir and registers projectID as the owner
// of namespace/environment, so ownership checks on an existing stack pass.
func claimStack(t *testing.T, dataDir, namespace, environment, projectID string) *registry.Registry {
	t.Helper()
	reg, err := registry.Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Claim(namespace, environment, projectID); err != nil {
		t.Fatal(err)
	}
	return reg
}

// freeAddr returns a loopback address with a port that was free a moment ago.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// startRun runs the server in the background and waits until /health answers.
func startRun(t *testing.T, cfg *config.Config) (base string, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	//goland:noinspection HttpUrlsUsage
	base = "http://" + cfg.ListenAddr
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(base + "/health")
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("run exited early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("server did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}

	return base, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			return fmt.Errorf("run did not return after cancellation")
		}
	}
}

func TestRun_servesAuthenticatedRequestsAndShutsDown(t *testing.T) {
	testutil.FakeDocker(t)
	iss := testutil.NewIssuer(t)
	cfg := testConfig(t, iss.URL)
	claimStack(t, cfg.DataDir, "group-app", "staging", "1")
	base, stop := startRun(t, cfg)

	token := iss.Token(t, testAudience, map[string]any{
		"project_path": "group/app", "project_id": "1", "environment": "staging",
	})

	for _, tc := range []struct {
		auth string
		want int
	}{
		{"Bearer " + token, http.StatusNoContent},
		{"", http.StatusUnauthorized},
	} {
		req, _ := http.NewRequest("DELETE", base+"/stack", nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("with token=%v: status = %d, want %d", tc.auth != "", resp.StatusCode, tc.want)
		}
	}

	if err := stop(); err != nil {
		t.Errorf("run returned %v, want nil after graceful shutdown", err)
	}
}

func TestRun_startupFailures(t *testing.T) {
	iss := testutil.NewIssuer(t)

	tests := map[string]func(t *testing.T, cfg *config.Config){
		"data dir is a file": func(t *testing.T, cfg *config.Config) {
			must(t, os.WriteFile(cfg.DataDir, nil, 0o600))
		},
		"oidc discovery fails": func(t *testing.T, cfg *config.Config) {
			srv := httptest.NewServer(http.NotFoundHandler())
			t.Cleanup(srv.Close)
			cfg.GitLabIssuer = srv.URL
		},
		"corrupt registry": func(t *testing.T, cfg *config.Config) {
			must(t, os.MkdirAll(cfg.DataDir, 0o700))
			must(t, os.WriteFile(filepath.Join(cfg.DataDir, "registry.json"), []byte("{"), 0o600))
		},
		"corrupt scheduler state": func(t *testing.T, cfg *config.Config) {
			must(t, os.MkdirAll(cfg.DataDir, 0o700))
			must(t, os.WriteFile(filepath.Join(cfg.DataDir, "autostop.json"), []byte("{"), 0o600))
		},
		"address already in use": func(t *testing.T, cfg *config.Config) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			cfg.ListenAddr = ln.Addr().String()
		},
	}

	for name, breakCfg := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(t, iss.URL)
			breakCfg(t, cfg)
			if err := run(context.Background(), cfg); err == nil {
				t.Error("expected run to fail")
			}
		})
	}
}

func TestNewMux_routingAndAllowlist(t *testing.T) {
	cfg := testConfig(t, "")
	_, allowed, _ := net.ParseCIDR("203.0.113.10/32")
	cfg.AllowedIPs = []*net.IPNet{allowed}

	reg := claimStack(t, cfg.DataDir, "group-app", "staging", "1")
	mux := testMux(t, cfg, reg, staticAuth(&middleware.Claims{ProjectPath: "group/app", ProjectID: "1", Environment: "staging"}))

	testutil.FakeDocker(t)
	tests := []struct {
		name, method, path, remote string
		want                       int
	}{
		{"health is exempt from the allowlist", "GET", "/health", "198.51.100.1:1234", http.StatusOK},
		{"protected route from a foreign IP", "DELETE", "/stack", "198.51.100.1:1234", http.StatusForbidden},
		{"protected route from an allowed IP", "DELETE", "/stack", "203.0.113.10:1234", http.StatusNoContent},
		{"exec is routed", "POST", "/exec", "203.0.113.10:1234", http.StatusBadRequest},
		{"directories is routed", "POST", "/directories", "203.0.113.10:1234", http.StatusBadRequest},
		{"deploy is routed", "POST", "/deploy", "203.0.113.10:1234", http.StatusBadRequest},
		{"wrong method", "GET", "/deploy", "203.0.113.10:1234", http.StatusMethodNotAllowed},
		{"unknown route", "GET", "/nope", "203.0.113.10:1234", http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r.RemoteAddr = tc.remote
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, r)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body %q)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestNewLogger_writesJSONLines(t *testing.T) {
	var buf bytes.Buffer
	newLogger(&buf).Info("audit", "status", 204, "command", []string{"php", "bin/console"})

	var entry map[string]any
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("log line is not JSON: %q: %v", buf.String(), err)
	}
	if entry["msg"] != "audit" || entry["level"] != "INFO" || entry["status"] != float64(204) {
		t.Errorf("entry = %v", entry)
	}
	if cmd, ok := entry["command"].([]any); !ok || len(cmd) != 2 {
		t.Errorf("command should be a JSON array, got %v", entry["command"])
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent use. runMain installs the
// logger writing to it as the slog default — which also captures the standard
// log package — so goroutines outliving runMain (e.g. an HTTP server logging a
// TLS handshake error) may still write while the test reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// Bytes returns a copy of the content written so far.
func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

// runMainOutput runs runMain with args and a fresh environment and returns its
// exit code and the decoded log entries.
func runMainOutput(t *testing.T, args []string, env map[string]string) (int, []map[string]any) {
	t.Helper()
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	for k, v := range env {
		t.Setenv(k, v)
	}

	var buf syncBuffer
	code := runMain(args, &buf)

	var entries []map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var e map[string]any
		if err := dec.Decode(&e); err != nil {
			t.Fatalf("log output is not JSON lines: %v", err)
		}
		entries = append(entries, e)
	}
	return code, entries
}

func TestRunMain_failuresExitNonZeroWithJSONLog(t *testing.T) {
	// TLS so the issuer passes config validation (https:// only); discovery
	// then fails (untrusted certificate, no OIDC document) at server startup.
	// Its handshake-error logs are discarded so they do not interleave with
	// the server's JSON log lines.
	notOIDC := httptest.NewUnstartedServer(http.NotFoundHandler())
	notOIDC.Config.ErrorLog = log.New(io.Discard, "", 0)
	notOIDC.StartTLS()
	defer notOIDC.Close()

	//goland:noinspection HttpUrlsUsage
	tests := []struct {
		name    string
		env     map[string]string
		wantMsg string
	}{
		{"invalid configuration", map[string]string{"GITLAB_ISSUER": "", "GITLAB_AUDIENCE": ""}, "invalid configuration"},
		{"plain-http issuer", map[string]string{"GITLAB_ISSUER": "http://gitlab.example.com", "GITLAB_AUDIENCE": testAudience}, "invalid configuration"},
		{"server startup failure", map[string]string{
			"GITLAB_ISSUER":   notOIDC.URL,
			"GITLAB_AUDIENCE": testAudience,
			"DATA_DIR":        t.TempDir(),
			"LISTEN_ADDR":     freeAddr(t),
		}, "server failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, entries := runMainOutput(t, nil, tc.env)
			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			last := entries[len(entries)-1]
			if last["level"] != "ERROR" || last["msg"] != tc.wantMsg || last["error"] == "" {
				t.Errorf("last log entry = %v", last)
			}
		})
	}
}

// TestNewMux_authorisationOnEveryEndpoint checks that the namespace allowlist
// and the protected-environment rule apply to all four protected endpoints,
// not only to /deploy.
func TestNewMux_authorisationOnEveryEndpoint(t *testing.T) {
	cfg := testConfig(t, "")
	cfg.AllowedNamespaces = []string{"apps/atmosphere"}

	reg := claimStack(t, cfg.DataDir, "apps-atmosphere-api-app", "production", "1")

	var claims *middleware.Claims
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(middleware.ContextWithClaims(r.Context(), claims)))
		})
	}
	mux := testMux(t, cfg, reg, auth)
	testutil.FakeDocker(t)

	no := false
	identities := []struct {
		name   string
		claims middleware.Claims
	}{
		{"foreign namespace", middleware.Claims{
			ProjectPath: "apps/atmosphere-evil/app", NamespacePath: "apps/atmosphere-evil",
			ProjectID: "1", Environment: "staging", RefProtected: true,
		}},
		{"production from an unprotected branch", middleware.Claims{
			ProjectPath: "apps/atmosphere/app", NamespacePath: "apps/atmosphere",
			ProjectID: "1", Environment: "production",
		}},
		{"production not protected in GitLab", middleware.Claims{
			ProjectPath: "apps/atmosphere/app", NamespacePath: "apps/atmosphere",
			ProjectID: "1", Environment: "production", RefProtected: true, EnvironmentProtected: &no,
		}},
	}
	endpoints := []struct{ method, path string }{
		{"POST", "/deploy"}, {"DELETE", "/stack"}, {"POST", "/directories"}, {"POST", "/exec"},
	}
	for _, id := range identities {
		for _, ep := range endpoints {
			t.Run(id.name+" "+ep.method+" "+ep.path, func(t *testing.T) {
				claims = &id.claims
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, httptest.NewRequest(ep.method, ep.path, nil))
				if rec.Code != http.StatusForbidden {
					t.Errorf("status = %d, want 403 (body %q)", rec.Code, rec.Body.String())
				}
			})
		}
	}

	t.Run("allowed sub-namespace on a protected branch reaches the handler", func(t *testing.T) {
		claims = &middleware.Claims{
			ProjectPath: "apps/atmosphere/api/app", NamespacePath: "apps/atmosphere/api",
			ProjectID: "1", Environment: "production", RefProtected: true,
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("DELETE", "/stack", nil))
		if rec.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204 (body %q)", rec.Code, rec.Body.String())
		}
	})
}

func TestRunMain_arguments(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
	}{
		{"help", []string{"-h"}, 0},
		{"version", []string{"-version"}, 0},
		{"unknown flag", []string{"-nope"}, 2},
		{"positional argument", []string{"extra"}, 2},
		{"missing flag value", []string{"-import-registry"}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := runMainOutput(t, tc.args, nil); code != tc.wantCode {
				t.Errorf("exit code = %d, want %d", code, tc.wantCode)
			}
		})
	}
}

func TestRunMain_importRegistry(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "state") // created by the import
	legacy := filepath.Join(t.TempDir(), "legacy.json")
	must(t, os.WriteFile(legacy, []byte(`{"group-app-staging":{"project_id":"42","project_path":"group/app","environment":"staging"},"other-production":"7"}`), 0o600))

	// Only DATA_DIR is needed: the OIDC settings are not required offline.
	env := map[string]string{"DATA_DIR": dataDir, "GITLAB_ISSUER": "", "GITLAB_AUDIENCE": ""}
	code, entries := runMainOutput(t, []string{"-import-registry", legacy}, env)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (logs %v)", code, entries)
	}
	last := entries[len(entries)-1]
	if last["msg"] != "registry import done" || last["changed"] != float64(2) {
		t.Errorf("last log entry = %v", last)
	}

	reg, err := registry.Load(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := reg.Lookup("group-app", "staging"); !ok || e.ProjectID != "42" {
		t.Errorf("imported entry = %+v, %v", e, ok)
	}

	// A conflicting owner aborts the import: exit 1, registry unchanged.
	conflict := filepath.Join(t.TempDir(), "conflict.json")
	must(t, os.WriteFile(conflict, []byte(`{"group-app-staging":"99"}`), 0o600))
	if code, _ := runMainOutput(t, []string{"-import-registry", conflict}, env); code != 1 {
		t.Errorf("conflicting import: exit code = %d, want 1", code)
	}
	if reg, _ := registry.Load(dataDir); reg != nil {
		if e, _ := reg.Lookup("group-app", "staging"); e.ProjectID != "42" {
			t.Errorf("conflicting import modified the registry: %+v", e)
		}
	}

	failures := map[string]struct {
		dataDir, file string
	}{
		"missing file":       {dataDir, filepath.Join(t.TempDir(), "absent.json")},
		"data dir is a file": {legacy, legacy},
		"corrupt registry":   {corruptRegistryDir(t), legacy},
	}
	for name, f := range failures {
		t.Run(name, func(t *testing.T) {
			env := map[string]string{"DATA_DIR": f.dataDir}
			if code, _ := runMainOutput(t, []string{"-import-registry", f.file}, env); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
		})
	}
}

// corruptRegistryDir returns a data dir holding an unreadable registry.json.
func corruptRegistryDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "registry.json"), []byte("{"), 0o600))
	return dir
}

// policyDocker installs a fake docker binary first in PATH: `compose ...
// config` prints the file given with -f (used as the rendered model), every
// other call succeeds silently.
func policyDocker(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
f=""; prev=""; cfg=0
for a in "$@"; do
  [ "$prev" = "-f" ] && f="$a"
  [ "$a" = "config" ] && cfg=1
  prev="$a"
done
[ "$cfg" = 1 ] && cat "$f"
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestNewMux_deployPolicyIsConfigured checks that FORBIDDEN_TRAEFIK_HOSTS and
// ALLOWED_EXTERNAL_NETWORKS reach the deploy handler.
func TestNewMux_deployPolicyIsConfigured(t *testing.T) {
	policyDocker(t)
	cfg := testConfig(t, "")
	cfg.MaxUploadMB = 1
	cfg.ForbiddenTraefikHosts = []string{"deploy.example.com"}
	cfg.AllowedExternalNetworks = []string{"web"}

	reg, err := registry.Load(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	mux := testMux(t, cfg, reg, staticAuth(&middleware.Claims{ProjectPath: "group/app", ProjectID: "1", Environment: "staging"}))

	tests := []struct {
		name, compose string
		want          int
		wantBody      string
	}{
		{"forbidden traefik host",
			`{"services":{"web":{"image":"x","labels":{"traefik.http.routers.w.rule":"Host(` + "`deploy.example.com`" + `)"}}}}`,
			http.StatusBadRequest, "reserved"},
		{"external network not allowed",
			`{"services":{"web":{"image":"x","networks":{"db":null}}},"networks":{"db":{"name":"db","external":true}}}`,
			http.StatusBadRequest, "external"},
		{"allowed external network",
			`{"services":{"web":{"image":"x","networks":{"web":null}}},"networks":{"web":{"name":"web","external":true}}}`,
			http.StatusNoContent, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			part, _ := mw.CreateFormFile("compose_file", "docker-compose.yml")
			if _, err := io.WriteString(part, tc.compose); err != nil {
				t.Fatal(err)
			}
			must(t, mw.Close())
			r := httptest.NewRequest("POST", "/deploy", &body)
			r.Header.Set("Content-Type", mw.FormDataContentType())

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, r)
			if rec.Code != tc.want || !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Errorf("status = %d, body %q; want %d containing %q", rec.Code, rec.Body.String(), tc.want, tc.wantBody)
			}
		})
	}
}

// must fails the test immediately when err is not nil.
func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// staticAuth is a fake auth middleware: it accepts every request and injects
// claims as the caller identity.
func staticAuth(claims *middleware.Claims) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(middleware.ContextWithClaims(r.Context(), claims)))
		})
	}
}

// testMux builds the server mux around reg, with a fresh scheduler stored in
// cfg.DataDir and the given fake auth middleware.
func testMux(t *testing.T, cfg *config.Config, reg *registry.Registry, auth func(http.Handler) http.Handler) *http.ServeMux {
	t.Helper()
	sched, err := scheduler.Load(cfg.DataDir, nil)
	must(t, err)
	return newMux(cfg, auth, slog.New(slog.DiscardHandler), reg, sched)
}
