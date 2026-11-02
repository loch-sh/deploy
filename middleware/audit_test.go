package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// auditEntries decodes the JSON audit lines written to buf.
func auditEntries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var entries []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var e map[string]any
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		entries = append(entries, e)
	}
	return entries
}

// onlyEntry serves r through h and returns the single audit entry produced.
func onlyEntry(t *testing.T, h http.Handler, buf *bytes.Buffer, r *http.Request) map[string]any {
	t.Helper()
	buf.Reset()
	h.ServeHTTP(httptest.NewRecorder(), r)
	entries := auditEntries(t, buf)
	if len(entries) != 1 {
		t.Fatalf("got %d audit entries, want 1: %s", len(entries), buf.String())
	}
	return entries[0]
}

func newAuditLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

func TestAudit_withOIDC(t *testing.T) {
	v, iss := newTestVerifier(t)
	var buf bytes.Buffer

	h := Audit(newAuditLogger(&buf), nil)(v.OIDCAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		AddAuditAttrs(r.Context(), slog.String("service", "api"))
		w.WriteHeader(http.StatusNoContent)
	})))

	t.Run("authenticated request records identity and action details", func(t *testing.T) {
		token := iss.Token(t, testAudience, map[string]any{
			"project_path": "group/app", "project_id": "42", "environment": "staging",
			"ref": "main", "ref_protected": "true", "user_login": "alice",
			"user_email": "alice@example.com", "sha": "abc123",
			"namespace_path": "group", "environment_protected": "false",
		})
		r := httptest.NewRequest("DELETE", "/stack", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.RemoteAddr = "203.0.113.10:5555"

		e := onlyEntry(t, h, &buf, r)
		want := map[string]any{
			"level": "INFO", "msg": "audit", "method": "DELETE", "path": "/stack",
			"status": float64(204), "client_ip": "203.0.113.10",
			"project_path": "group/app", "project_id": "42", "environment": "staging",
			"ref": "main", "ref_protected": true, "user_login": "alice", "sha": "abc123",
			"namespace_path": "group", "environment_protected": false,
			"service": "api",
		}
		for k, v := range want {
			if e[k] != v {
				t.Errorf("%s = %v, want %v", k, e[k], v)
			}
		}
		if _, ok := e["user_email"]; ok {
			t.Error("user_email must not be logged")
		}
		if _, ok := e["error"]; ok {
			t.Error("successful request must not carry an error")
		}
	})

	t.Run("missing token", func(t *testing.T) {
		e := onlyEntry(t, h, &buf, httptest.NewRequest("POST", "/deploy", nil))
		if e["level"] != "WARN" || e["status"] != float64(401) || e["error"] != "missing bearer token" {
			t.Errorf("entry = %v", e)
		}
		if _, ok := e["project_path"]; ok {
			t.Error("no identity must be recorded for an unauthenticated request")
		}
	})

	t.Run("invalid token records the precise reason", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/deploy", nil)
		r.Header.Set("Authorization", "Bearer "+iss.Token(t, "https://other.example.com", nil))
		e := onlyEntry(t, h, &buf, r)
		if e["error"] != "invalid token" || !strings.Contains(e["auth_error"].(string), "audience") {
			t.Errorf("entry = %v", e)
		}
	})

	t.Run("unreadable claims", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/deploy", nil)
		r.Header.Set("Authorization", "Bearer "+iss.Token(t, testAudience, map[string]any{"project_id": 42}))
		if e := onlyEntry(t, h, &buf, r); e["auth_error"] == nil {
			t.Errorf("entry = %v", e)
		}
	})
}

func TestAudit_rejectedByAllowlist(t *testing.T) {
	var buf bytes.Buffer
	_, allowed, _ := net.ParseCIDR("203.0.113.0/24")
	_, proxy, _ := net.ParseCIDR("10.0.0.0/8")
	proxies := []*net.IPNet{proxy}

	h := Audit(newAuditLogger(&buf), proxies)(IPAllowlist([]*net.IPNet{allowed}, proxies)(http.NotFoundHandler()))

	r := httptest.NewRequest("POST", "/exec", nil)
	r.RemoteAddr = "10.0.0.2:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")

	e := onlyEntry(t, h, &buf, r)
	if e["status"] != float64(403) || e["client_ip"] != "198.51.100.7" || e["error"] != "forbidden" {
		t.Errorf("entry = %v", e)
	}
}

func TestAudit_statusAndErrorCapture(t *testing.T) {
	var buf bytes.Buffer
	audited := func(fn http.HandlerFunc) http.Handler { return Audit(newAuditLogger(&buf), nil)(fn) }

	t.Run("implicit 200", func(t *testing.T) {
		h := audited(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
		if e := onlyEntry(t, h, &buf, httptest.NewRequest("GET", "/x", nil)); e["status"] != float64(200) || e["level"] != "INFO" {
			t.Errorf("entry = %v", e)
		}
	})

	t.Run("first status wins", func(t *testing.T) {
		h := audited(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			w.WriteHeader(http.StatusInternalServerError)
		})
		if e := onlyEntry(t, h, &buf, httptest.NewRequest("GET", "/x", nil)); e["status"] != float64(202) {
			t.Errorf("entry = %v", e)
		}
	})

	t.Run("server error body is truncated", func(t *testing.T) {
		h := audited(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(strings.Repeat("a", 200)))
			_, _ = w.Write([]byte(strings.Repeat("b", 200)))
			_, _ = w.Write([]byte("c"))
		})
		e := onlyEntry(t, h, &buf, httptest.NewRequest("GET", "/x", nil))
		if e["level"] != "ERROR" || e["error"] != strings.Repeat("a", 200)+strings.Repeat("b", 56) {
			t.Errorf("entry = %v", e)
		}
	})

	t.Run("unresolvable client ip", func(t *testing.T) {
		h := audited(func(w http.ResponseWriter, r *http.Request) {})
		r := httptest.NewRequest("GET", "/x", nil)
		r.RemoteAddr = "not-an-ip"
		if e := onlyEntry(t, h, &buf, r); e["client_ip"] != "" {
			t.Errorf("entry = %v", e)
		}
	})
}

func TestAddAuditAttrs_withoutAuditIsNoop(t *testing.T) {
	AddAuditAttrs(context.Background(), slog.String("k", "v")) // must not panic
}

func TestStatusWriter_unwrap(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}
	if sw.Unwrap() != rec {
		t.Error("Unwrap must return the underlying writer")
	}
}

func TestClaimsAuditAttrs_environmentProtectedOnlyWhenPresent(t *testing.T) {
	for _, a := range claimsAuditAttrs(&Claims{}) {
		if a.Key == "environment_protected" {
			t.Error("environment_protected must be omitted when the claim is absent")
		}
	}
}
