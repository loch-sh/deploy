package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"deploy-server/internal/slug"
	"deploy-server/middleware"
)

func reqWithClaims(c *middleware.Claims) (st stack, code int, msg string) {
	r := httptest.NewRequest("POST", "/deploy", nil)
	if c != nil {
		r = r.WithContext(middleware.ContextWithClaims(r.Context(), c))
	}
	return stackFromClaims(r)
}

func TestStackFromClaims(t *testing.T) {
	t.Run("derives slugified namespace and environment", func(t *testing.T) {
		st, code, msg := reqWithClaims(&middleware.Claims{
			ProjectPath: "My-Group/My_Project",
			ProjectID:   "42",
			Environment: "staging",
		})
		if code != 0 {
			t.Fatalf("unexpected failure: %d %s", code, msg)
		}
		if st.Namespace != "my-group-my-project" {
			t.Errorf("Namespace = %q", st.Namespace)
		}
		if st.Environment != "staging" {
			t.Errorf("Environment = %q", st.Environment)
		}
		if st.Key != "my-group-my-project-staging" {
			t.Errorf("Key = %q", st.Key)
		}
		if st.ProjectID != "42" {
			t.Errorf("ProjectID = %q", st.ProjectID)
		}
	})

	t.Run("rejects missing environment claim", func(t *testing.T) {
		_, code, _ := reqWithClaims(&middleware.Claims{ProjectPath: "g/p", ProjectID: "1"})
		if code == 0 {
			t.Error("expected failure for missing environment claim")
		}
	})

	t.Run("rejects missing project claims", func(t *testing.T) {
		_, code, _ := reqWithClaims(&middleware.Claims{Environment: "staging"})
		if code == 0 {
			t.Error("expected failure for missing project_path/project_id")
		}
	})

	t.Run("rejects request without verified claims", func(t *testing.T) {
		_, code, _ := reqWithClaims(nil)
		if code == 0 {
			t.Error("expected failure when no claims present")
		}
	})
}

func TestRequireProtectedRef(t *testing.T) {
	protected := map[string]bool{"production": true}

	// Production from an unprotected ref must be refused.
	if msg := requireProtectedRef(stack{Environment: "production", RefProtected: false}, protected); msg == "" {
		t.Error("expected production+unprotected ref to be refused")
	}
	// Production from a protected ref is allowed.
	if msg := requireProtectedRef(stack{Environment: "production", RefProtected: true}, protected); msg != "" {
		t.Errorf("production+protected ref should be allowed, got %q", msg)
	}
	// Non-protected environment is always allowed.
	if msg := requireProtectedRef(stack{Environment: "staging", RefProtected: false}, protected); msg != "" {
		t.Errorf("staging should be allowed, got %q", msg)
	}
}

// TestGitlabSlugMatchesSharedSlug guards against drift between the handlers'
// gitlabSlug and internal/slug.GitLab, which config and middleware use to
// normalise PROTECTED_ENVS and the environment claim.
func TestGitlabSlugMatchesSharedSlug(t *testing.T) {
	inputs := []string{
		"production", "Production", "My-Group/My_Project", "a//b", "--x--", "é",
		"review/feature-1", strings.Repeat("a", 70), strings.Repeat("a", 62) + "-b", "",
	}
	for _, in := range inputs {
		if got, want := gitlabSlug(in), slug.GitLab(in); got != want {
			t.Errorf("gitlabSlug(%q) = %q, slug.GitLab = %q", in, got, want)
		}
	}
}
