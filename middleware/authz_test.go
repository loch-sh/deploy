package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// serveAuthz runs mw with claims in the context (none when c is nil) and
// returns the status code.
func serveAuthz(mw func(http.Handler) http.Handler, c *Claims) int {
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest("POST", "/exec", nil)
	if c != nil {
		r = r.WithContext(ContextWithClaims(r.Context(), c))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

func TestRequireNamespace(t *testing.T) {
	mw := RequireNamespace([]string{"infra", "apps/atmosphere"})

	tests := []struct {
		ns   string
		want int
	}{
		{"infra", http.StatusNoContent},
		{"infra/tools", http.StatusNoContent},
		{"apps/atmosphere", http.StatusNoContent},
		{"apps/atmosphere/api", http.StatusNoContent},
		{"Apps/Atmosphere/API", http.StatusNoContent}, // case-insensitive
		{"apps/atmosphere-evil", http.StatusForbidden},
		{"apps", http.StatusForbidden},
		{"infrastructure", http.StatusForbidden},
		{"other/infra", http.StatusForbidden},
		{"", http.StatusForbidden}, // claim missing
	}
	for _, tc := range tests {
		t.Run(tc.ns, func(t *testing.T) {
			if code := serveAuthz(mw, &Claims{NamespacePath: tc.ns}); code != tc.want {
				t.Errorf("namespace %q: status = %d, want %d", tc.ns, code, tc.want)
			}
		})
	}

	t.Run("no claims", func(t *testing.T) {
		if code := serveAuthz(mw, nil); code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", code)
		}
	})

	t.Run("disabled when empty", func(t *testing.T) {
		if code := serveAuthz(RequireNamespace(nil), &Claims{NamespacePath: "anything"}); code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", code)
		}
	})
}

func TestRequireProtectedRef(t *testing.T) {
	mw := RequireProtectedRef(map[string]bool{"production": true})
	yes, no := true, false

	tests := []struct {
		name string
		c    Claims
		want int
	}{
		{"protected env, protected ref", Claims{Environment: "production", RefProtected: true}, http.StatusNoContent},
		{"protected env, unprotected ref", Claims{Environment: "production"}, http.StatusForbidden},
		{"protected env after slug, unprotected ref", Claims{Environment: "Production"}, http.StatusForbidden},
		{"env protected in GitLab too", Claims{Environment: "production", RefProtected: true, EnvironmentProtected: &yes}, http.StatusNoContent},
		{"env not protected in GitLab", Claims{Environment: "production", RefProtected: true, EnvironmentProtected: &no}, http.StatusForbidden},
		{"environment_protected does not replace ref_protected", Claims{Environment: "production", EnvironmentProtected: &yes}, http.StatusForbidden},
		{"other env, unprotected ref", Claims{Environment: "staging"}, http.StatusNoContent},
		{"other env, env unprotected", Claims{Environment: "staging", EnvironmentProtected: &no}, http.StatusNoContent},
		{"no environment claim", Claims{}, http.StatusNoContent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if code := serveAuthz(mw, &tc.c); code != tc.want {
				t.Errorf("status = %d, want %d", code, tc.want)
			}
		})
	}

	t.Run("no claims", func(t *testing.T) {
		if code := serveAuthz(mw, nil); code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", code)
		}
	})
}
