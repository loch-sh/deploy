package handlers

import (
	"testing"
)

func TestGitlabSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"myapp", "myapp"},
		{"MyApp", "myapp"},
		{"group/project", "group-project"},
		{"group/sub/project", "group-sub-project"},
		{"my_app", "my-app"},
		{"my.app", "my-app"},
		{"staging", "staging"},
		{"production", "production"},
		{"MY-APP-123", "my-app-123"},
		// GitLab does NOT collapse consecutive hyphens — each non-alnum → one "-".
		{"a//b", "a--b"},
		{"_leading", "leading"},
		{"trailing_", "trailing"},
		// Each non-ASCII letter becomes a single hyphen (per-rune), matching Ruby.
		{"héllo", "h-llo"},
	}

	for _, tc := range tests {
		got := gitlabSlug(tc.input)
		if got != tc.want {
			t.Errorf("gitlabSlug(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestValidateSlug(t *testing.T) {
	valid := []string{"myapp", "my-app", "app123", "a", "a" + repeat("b", 62)}
	for _, s := range valid {
		if err := validateSlug("x", s); err != nil {
			t.Errorf("validateSlug(%q) unexpected error: %v", s, err)
		}
	}

	invalid := []string{"", "-myapp", "myapp-", "my app", "MyApp", "my_app", "a" + repeat("b", 63)}
	for _, s := range invalid {
		if err := validateSlug("x", s); err == nil {
			t.Errorf("validateSlug(%q) expected error, got nil", s)
		}
	}
}

func TestSafeChild(t *testing.T) {
	base := "/data/compose"

	ok, err := safeChild(base, "myapp-staging")
	if err != nil {
		t.Fatalf("safeChild: unexpected error: %v", err)
	}
	if ok != "/data/compose/myapp-staging" {
		t.Errorf("safeChild: got %q, want /data/compose/myapp-staging", ok)
	}

	// Path traversal attempts must be rejected.
	traversals := []string{"../etc", "../../etc/passwd", "foo/../../../etc"}
	for _, rel := range traversals {
		if _, err := safeChild(base, rel); err == nil {
			t.Errorf("safeChild(%q) should have returned an error", rel)
		}
	}
}

func repeat(s string, n int) string {
	result := make([]byte, n*len(s))
	for i := range result {
		result[i] = s[i%len(s)]
	}
	return string(result)
}

func TestValidateEnvFileName(t *testing.T) {
	valid := []string{"api.env", ".env", "dolibarr.env", "API_v2.env"}
	for _, s := range valid {
		if err := validateEnvFileName(s); err != nil {
			t.Errorf("validateEnvFileName(%q) unexpected error: %v", s, err)
		}
	}

	invalid := []string{"", ".", "..", "../api.env", "sub/api.env", `sub\api.env`, "docker-compose.yml", "api.env.tmp", "a b.env"}
	for _, s := range invalid {
		if err := validateEnvFileName(s); err == nil {
			t.Errorf("validateEnvFileName(%q) expected error, got nil", s)
		}
	}
}

func TestValidateDirName(t *testing.T) {
	valid := []string{"storage", "jwt", "public_uploads", "v1.2", "Media"}
	for _, s := range valid {
		if err := validateDirName(s); err != nil {
			t.Errorf("validateDirName(%q) unexpected error: %v", s, err)
		}
	}

	invalid := []string{"", ".", "..", ".hidden", "a/b", `a\b`, "-x"}
	for _, s := range invalid {
		if err := validateDirName(s); err == nil {
			t.Errorf("validateDirName(%q) expected error, got nil", s)
		}
	}
}

func TestParseAutoStopDays(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"7", 7, false},
		{"0", 0, true},
		{"-1", 0, true},
		{"abc", 0, true},
	}
	for _, tc := range tests {
		got, err := parseAutoStopDays(tc.input)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("parseAutoStopDays(%q) = %d, %v; want %d, err=%v", tc.input, got, err, tc.want, tc.wantErr)
		}
	}
}
