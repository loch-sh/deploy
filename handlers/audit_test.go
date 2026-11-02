package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"deploy-server/middleware"
)

// auditedEntry serves r through h wrapped in the audit middleware and returns
// the audit entry.
func auditedEntry(t *testing.T, h http.Handler, r *http.Request) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	audited := middleware.Audit(slog.New(slog.NewJSONHandler(&buf, nil)), nil)(h)
	serve(audited, r, defaultClaims())

	var e map[string]any
	if err := json.Unmarshal(buf.Bytes(), &e); err != nil {
		t.Fatalf("decode audit entry %q: %v", buf.String(), err)
	}
	return e
}

func TestHandlersAddAuditDetails(t *testing.T) {
	e := newTestEnv(t)

	t.Run("deploy", func(t *testing.T) {
		r := multipartRequest(t, "/deploy", []upload{composeUpload, {"env_files", "api.env", "A=1"}},
			map[string]string{"auto_stop_days": "7"})
		entry := auditedEntry(t, e.deployHandler(), r)
		if entry["auto_stop_days"] != float64(7) || !equalList(entry["env_files"], "api.env") {
			t.Errorf("entry = %v", entry)
		}
	})

	t.Run("exec", func(t *testing.T) {
		r := jsonRequest("POST", "/exec", `{"service":"api","command":["php","bin/console"]}`)
		entry := auditedEntry(t, e.execHandler(), r)
		if entry["service"] != "api" || !equalList(entry["command"], "php", "bin/console") {
			t.Errorf("entry = %v", entry)
		}
	})

	t.Run("directories", func(t *testing.T) {
		r := newDirsRequest(`{"entries":[{"service":"api","name":"storage"}]}`)
		entry := auditedEntry(t, e.dirsHandler(), r)
		if !equalList(entry["directories"], "api/storage") {
			t.Errorf("entry = %v", entry)
		}
	})
}

func equalList(v any, want ...string) bool {
	got, ok := v.([]any)
	if !ok || len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
