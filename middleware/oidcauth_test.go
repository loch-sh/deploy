package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"deploy-server/internal/testutil"
)

const testAudience = "https://deploy.example.com"

// newTestVerifier returns a Verifier backed by a fake GitLab issuer.
func newTestVerifier(t *testing.T) (*Verifier, *testutil.Issuer) {
	t.Helper()
	iss := testutil.NewIssuer(t)
	v, err := NewVerifier(context.Background(), iss.URL, testAudience)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v, iss
}

func TestNewVerifier_discoveryFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	if _, err := NewVerifier(context.Background(), srv.URL, testAudience); err == nil {
		t.Fatal("expected discovery failure")
	}
}

func TestOIDCAuth(t *testing.T) {
	v, iss := newTestVerifier(t)

	var got *Claims
	h := v.OIDCAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = ClaimsFromContext(r.Context())
	}))

	serve := func(authHeader string) int {
		got = nil
		r := httptest.NewRequest("POST", "/deploy", nil)
		if authHeader != "" {
			r.Header.Set("Authorization", authHeader)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}

	t.Run("valid token exposes claims", func(t *testing.T) {
		token := iss.Token(t, testAudience, map[string]any{
			"project_path":  "group/project",
			"project_id":    "42",
			"environment":   "staging",
			"ref":           "main",
			"ref_protected": "true",
			"user_login":    "alice",
			"user_email":    "alice@example.com",
			"sha":           "abc123",
		})
		if code := serve("Bearer " + token); code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		want := Claims{
			ProjectPath: "group/project", ProjectID: "42", Environment: "staging",
			Ref: "main", RefProtected: true, UserLogin: "alice",
			UserEmail: "alice@example.com", SHA: "abc123",
		}
		if got == nil || *got != want {
			t.Errorf("claims = %+v, want %+v", got, want)
		}
	})

	rejected := map[string]string{
		"missing header":    "",
		"not bearer":        "Basic dXNlcjpwYXNz",
		"empty bearer":      "Bearer ",
		"garbage token":     "Bearer not-a-jwt",
		"wrong audience":    "Bearer " + iss.Token(t, "https://other.example.com", nil),
		"expired token":     "Bearer " + iss.Token(t, testAudience, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
		"unreadable claims": "Bearer " + iss.Token(t, testAudience, map[string]any{"project_id": 42}),
	}
	for name, header := range rejected {
		t.Run(name, func(t *testing.T) {
			if code := serve(header); code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", code)
			}
			if got != nil {
				t.Error("next handler must not be called")
			}
		})
	}

	t.Run("token from another issuer", func(t *testing.T) {
		other := testutil.NewIssuer(t)
		if code := serve("Bearer " + other.Token(t, testAudience, nil)); code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", code)
		}
	})
}

func TestOIDCAuth_gitlabClaims(t *testing.T) {
	v, iss := newTestVerifier(t)
	var got *Claims
	h := v.OIDCAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = ClaimsFromContext(r.Context())
	}))
	serve := func(claims map[string]any) *Claims {
		got = nil
		r := httptest.NewRequest("POST", "/deploy", nil)
		r.Header.Set("Authorization", "Bearer "+iss.Token(t, testAudience, claims))
		h.ServeHTTP(httptest.NewRecorder(), r)
		return got
	}

	c := serve(map[string]any{"namespace_path": "apps/atmosphere", "environment_protected": "false"})
	if c == nil || c.NamespacePath != "apps/atmosphere" {
		t.Fatalf("claims = %+v", c)
	}
	if c.EnvironmentProtected == nil || *c.EnvironmentProtected {
		t.Errorf("EnvironmentProtected = %v, want false", c.EnvironmentProtected)
	}

	c = serve(map[string]any{"environment_protected": "true"})
	if c == nil || c.EnvironmentProtected == nil || !*c.EnvironmentProtected {
		t.Errorf("EnvironmentProtected should be true, claims = %+v", c)
	}

	c = serve(nil)
	if c == nil || c.EnvironmentProtected != nil {
		t.Errorf("EnvironmentProtected should be nil when absent, claims = %+v", c)
	}
}

func TestOIDCAuth_tokenAgeAndClockSkew(t *testing.T) {
	v, iss := newTestVerifier(t)
	h := v.OIDCAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serve := func(claims map[string]any) int {
		r := httptest.NewRequest("POST", "/deploy", nil)
		r.Header.Set("Authorization", "Bearer "+iss.Token(t, testAudience, claims))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	now := time.Now()

	tests := []struct {
		name   string
		claims map[string]any
		want   int
	}{
		{"fresh token", nil, http.StatusOK},
		{"iat 9 minutes ago", map[string]any{"iat": now.Add(-9 * time.Minute).Unix()}, http.StatusOK},
		{"iat 11 minutes ago (replay window)", map[string]any{"iat": now.Add(-11 * time.Minute).Unix()}, http.StatusUnauthorized},
		{"iat slightly in the future (skew)", map[string]any{"iat": now.Add(10 * time.Second).Unix()}, http.StatusOK},
		{"iat far in the future", map[string]any{"iat": now.Add(5 * time.Minute).Unix()}, http.StatusUnauthorized},
		{"no iat", map[string]any{"iat": nil}, http.StatusUnauthorized},
		{"exp just passed, within skew", map[string]any{"exp": now.Add(-10 * time.Second).Unix()}, http.StatusOK},
		{"exp passed beyond skew", map[string]any{"exp": now.Add(-2 * time.Minute).Unix()}, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if code := serve(tc.claims); code != tc.want {
				t.Errorf("status = %d, want %d", code, tc.want)
			}
		})
	}
}

func TestNewVerifier_httpClientTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // hang until the test ends
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	_, err := newVerifier(context.Background(), srv.URL, testAudience, &http.Client{Timeout: 100 * time.Millisecond})
	if err == nil {
		t.Fatal("expected discovery to time out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("discovery took %s, the client timeout was not applied", elapsed)
	}
}
