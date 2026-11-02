package handlers

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deploy-server/internal/testutil"
	"deploy-server/middleware"
	"deploy-server/registry"
	"deploy-server/scheduler"
)

// TestMain silences server logs so test output stays readable.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

// testKey is the stack key derived from defaultClaims.
const testKey = "group-app-staging"

// testEnv wires the handlers to temp directories, a real registry and
// scheduler, and a fake docker binary.
type testEnv struct {
	composeBase  string
	websitesBase string
	dataDir      string
	reg          *registry.Registry
	sched        *scheduler.Scheduler
	docker       *testutil.DockerLog
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	root := t.TempDir()
	e := &testEnv{
		composeBase:  filepath.Join(root, "compose"),
		websitesBase: filepath.Join(root, "websites"),
		dataDir:      filepath.Join(root, "data"),
		docker:       testutil.FakeDocker(t),
	}

	var err error
	if e.reg, err = registry.Load(e.dataDir); err != nil {
		t.Fatalf("registry: %v", err)
	}
	noop := func(context.Context, string, string) error { return nil }
	if e.sched, err = scheduler.Load(e.dataDir, noop); err != nil {
		t.Fatalf("scheduler: %v", err)
	}
	return e
}

func (e *testEnv) stackDir() string { return filepath.Join(e.composeBase, testKey) }

// autostopFile returns the scheduler's persisted state ("" when absent).
func (e *testEnv) autostopFile() string {
	raw, _ := os.ReadFile(filepath.Join(e.dataDir, "autostop.json"))
	return string(raw)
}

func (e *testEnv) deployHandler() http.Handler {
	return Deploy(DeployConfig{
		ComposeBase:   e.composeBase,
		MaxUploadMB:   1,
		Registry:      e.reg,
		Scheduler:     e.sched,
		ProtectedEnvs: map[string]bool{"production": true},
	})
}

func defaultClaims() *middleware.Claims {
	return &middleware.Claims{ProjectPath: "group/app", ProjectID: "1", Environment: "staging"}
}

// serve runs h on r, injecting claims when non-nil.
func serve(h http.Handler, r *http.Request, claims *middleware.Claims) *httptest.ResponseRecorder {
	if claims != nil {
		r = r.WithContext(middleware.ContextWithClaims(r.Context(), claims))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// upload is one multipart file part.
type upload struct {
	field, name, content string
}

// multipartRequest builds a multipart POST with the given files and fields.
func multipartRequest(t *testing.T, path string, files []upload, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, f := range files {
		part, err := mw.CreateFormFile(f.field, f.name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(part, f.content)
	}
	for k, v := range fields {
		mw.WriteField(k, v)
	}
	mw.Close()

	r := httptest.NewRequest("POST", path, &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func jsonRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// cancelledRequest returns r bound to an already-cancelled context.
func cancelledRequest(r *http.Request) *http.Request {
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	return r.WithContext(ctx)
}

// holdStackLock takes the lock of testKey until the test ends.
func holdStackLock(t *testing.T) {
	t.Helper()
	unlock, err := stackLocks.lock(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body: %q)", rec.Code, want, rec.Body.String())
	}
}
