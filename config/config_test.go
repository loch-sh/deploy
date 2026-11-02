package config

import (
	"os"
	"testing"
)

// setRequired sets the env vars Load() requires and returns a cleanup func.
func setRequired(t *testing.T) {
	t.Helper()
	os.Setenv("GITLAB_ISSUER", "https://gitlab.example.com")
	os.Setenv("GITLAB_AUDIENCE", "https://deploy.example.com")
}

func TestLoad_defaults(t *testing.T) {
	// Unset all optional env vars that Load reads.
	for _, k := range []string{"LISTEN_ADDR", "COMPOSE_BASE", "WEBSITES_BASE", "MAX_UPLOAD_MB", "DATA_DIR", "PROTECTED_ENVS"} {
		os.Unsetenv(k)
	}
	setRequired(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want \":8080\"", cfg.ListenAddr)
	}
	if cfg.ComposeBase != "/data/compose" {
		t.Errorf("ComposeBase = %q, want \"/data/compose\"", cfg.ComposeBase)
	}
	if cfg.MaxUploadMB != 10 {
		t.Errorf("MaxUploadMB = %d, want 10", cfg.MaxUploadMB)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("DataDir = %q, want \"./data\"", cfg.DataDir)
	}
	if !cfg.ProtectedEnvironments["production"] {
		t.Errorf("ProtectedEnvironments should default to include \"production\", got %v", cfg.ProtectedEnvironments)
	}
}

func TestLoad_envOverrides(t *testing.T) {
	os.Setenv("LISTEN_ADDR", ":9090")
	os.Setenv("COMPOSE_BASE", "/srv/compose")
	os.Setenv("MAX_UPLOAD_MB", "50")
	os.Setenv("PROTECTED_ENVS", "production, recette")
	setRequired(t)
	defer func() {
		for _, k := range []string{"LISTEN_ADDR", "COMPOSE_BASE", "MAX_UPLOAD_MB", "PROTECTED_ENVS", "GITLAB_ISSUER", "GITLAB_AUDIENCE"} {
			os.Unsetenv(k)
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want \":9090\"", cfg.ListenAddr)
	}
	if cfg.ComposeBase != "/srv/compose" {
		t.Errorf("ComposeBase = %q, want \"/srv/compose\"", cfg.ComposeBase)
	}
	if cfg.MaxUploadMB != 50 {
		t.Errorf("MaxUploadMB = %d, want 50", cfg.MaxUploadMB)
	}
	if !cfg.ProtectedEnvironments["production"] || !cfg.ProtectedEnvironments["recette"] {
		t.Errorf("ProtectedEnvironments = %v, want production+recette", cfg.ProtectedEnvironments)
	}
}

func TestLoad_missingRequired(t *testing.T) {
	os.Unsetenv("GITLAB_ISSUER")
	os.Unsetenv("GITLAB_AUDIENCE")
	if _, err := Load(); err == nil {
		t.Error("expected error when GITLAB_ISSUER/GITLAB_AUDIENCE are unset")
	}
}

func TestParseCIDRList(t *testing.T) {
	nets, err := parseCIDRList(" 203.0.113.10 , 10.0.0.0/8 ,, 2001:db8::1 ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(nets) != 3 {
		t.Fatalf("got %d networks, want 3", len(nets))
	}
	// Bare IPv4 became a /32 host network.
	if ones, _ := nets[0].Mask.Size(); ones != 32 {
		t.Errorf("bare IPv4 should be /32, got /%d", ones)
	}
	// Bare IPv6 became a /128 host network.
	if ones, _ := nets[2].Mask.Size(); ones != 128 {
		t.Errorf("bare IPv6 should be /128, got /%d", ones)
	}

	if _, err := parseCIDRList(""); err != nil {
		t.Errorf("empty list should not error, got %v", err)
	}
	if _, err := parseCIDRList("not-an-ip"); err == nil {
		t.Error("expected error for invalid entry")
	}
}

func TestLoad_invalidMaxUpload(t *testing.T) {
	setRequired(t)
	os.Setenv("MAX_UPLOAD_MB", "notanumber")
	defer func() {
		os.Unsetenv("MAX_UPLOAD_MB")
		os.Unsetenv("GITLAB_ISSUER")
		os.Unsetenv("GITLAB_AUDIENCE")
	}()

	if _, err := Load(); err == nil {
		t.Error("expected error for invalid MAX_UPLOAD_MB")
	}
}

func TestLoad_issuerMustBeHTTPS(t *testing.T) {
	t.Setenv("GITLAB_AUDIENCE", "https://deploy.example.com")
	for _, issuer := range []string{"http://gitlab.example.com", "gitlab.example.com", "https://", "://bad"} {
		t.Setenv("GITLAB_ISSUER", issuer)
		if _, err := Load(); err == nil {
			t.Errorf("issuer %q: expected error", issuer)
		}
	}
	t.Setenv("GITLAB_ISSUER", "https://gitlab.example.com")
	if _, err := Load(); err != nil {
		t.Errorf("https issuer rejected: %v", err)
	}
}

func TestLoad_maxUploadBounds(t *testing.T) {
	t.Setenv("GITLAB_ISSUER", "https://gitlab.example.com")
	t.Setenv("GITLAB_AUDIENCE", "https://deploy.example.com")
	for v, ok := range map[string]bool{"0": false, "-5": false, "1025": false, "1": true, "1024": true} {
		t.Setenv("MAX_UPLOAD_MB", v)
		_, err := Load()
		if ok != (err == nil) {
			t.Errorf("MAX_UPLOAD_MB=%s: err = %v, want ok=%v", v, err, ok)
		}
	}
}

func TestLoad_protectedEnvsAreSlugified(t *testing.T) {
	t.Setenv("GITLAB_ISSUER", "https://gitlab.example.com")
	t.Setenv("GITLAB_AUDIENCE", "https://deploy.example.com")

	t.Setenv("PROTECTED_ENVS", "Production, prod/EU ,")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]bool{"production": true, "prod-eu": true}
	if len(cfg.ProtectedEnvironments) != len(want) || !cfg.ProtectedEnvironments["production"] || !cfg.ProtectedEnvironments["prod-eu"] {
		t.Errorf("ProtectedEnvironments = %v, want %v", cfg.ProtectedEnvironments, want)
	}

	t.Setenv("PROTECTED_ENVS", "production,///")
	if _, err := Load(); err == nil {
		t.Error("expected error for a protected env with an empty slug")
	}
}

func TestLoad_allowedNamespaces(t *testing.T) {
	t.Setenv("GITLAB_ISSUER", "https://gitlab.example.com")
	t.Setenv("GITLAB_AUDIENCE", "https://deploy.example.com")

	t.Setenv("ALLOWED_NAMESPACES", "")
	cfg, err := Load()
	if err != nil || cfg.AllowedNamespaces != nil {
		t.Fatalf("empty ALLOWED_NAMESPACES: cfg = %v, err = %v", cfg, err)
	}

	t.Setenv("ALLOWED_NAMESPACES", " infra , /Apps/Atmosphere/ ,, ")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.AllowedNamespaces) != 2 || cfg.AllowedNamespaces[0] != "infra" || cfg.AllowedNamespaces[1] != "apps/atmosphere" {
		t.Errorf("AllowedNamespaces = %q", cfg.AllowedNamespaces)
	}

	for _, bad := range []string{"apps//x", "apps/../infra", "a b", "apps/./x", "*"} {
		t.Setenv("ALLOWED_NAMESPACES", bad)
		if _, err := Load(); err == nil {
			t.Errorf("ALLOWED_NAMESPACES=%q: expected error", bad)
		}
	}
}

func TestLoad_invalidCIDRs(t *testing.T) {
	t.Setenv("GITLAB_ISSUER", "https://gitlab.example.com")
	t.Setenv("GITLAB_AUDIENCE", "https://deploy.example.com")
	for _, k := range []string{"ALLOWED_IPS", "TRUSTED_PROXIES"} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, "10.0.0.0/99")
			if _, err := Load(); err == nil {
				t.Errorf("%s: expected error", k)
			}
		})
	}
}

func TestLoad_forbiddenTraefikHosts(t *testing.T) {
	t.Setenv("GITLAB_ISSUER", "https://gitlab.example.com")
	t.Setenv("GITLAB_AUDIENCE", "https://deploy.example.com")

	t.Setenv("FORBIDDEN_TRAEFIK_HOSTS", "")
	if cfg, err := Load(); err != nil || cfg.ForbiddenTraefikHosts != nil {
		t.Fatalf("empty: cfg = %v, err = %v", cfg, err)
	}

	t.Setenv("FORBIDDEN_TRAEFIK_HOSTS", " Deploy.Example.com:443 , gitlab.example.com., deploy.example.com, 203.0.113.10, [2001:db8::1]:8443 ,")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"deploy.example.com", "gitlab.example.com", "203.0.113.10", "2001:db8::1"}
	if len(cfg.ForbiddenTraefikHosts) != len(want) {
		t.Fatalf("ForbiddenTraefikHosts = %q, want %q", cfg.ForbiddenTraefikHosts, want)
	}
	for i := range want {
		if cfg.ForbiddenTraefikHosts[i] != want[i] {
			t.Errorf("ForbiddenTraefikHosts[%d] = %q, want %q", i, cfg.ForbiddenTraefikHosts[i], want[i])
		}
	}

	for _, bad := range []string{"*.example.com", "exa mple.com", "-bad.com", "a..b", "http://x.com", ":443"} {
		t.Setenv("FORBIDDEN_TRAEFIK_HOSTS", bad)
		if _, err := Load(); err == nil {
			t.Errorf("FORBIDDEN_TRAEFIK_HOSTS=%q: expected error", bad)
		}
	}
}

func TestLoad_allowedExternalNetworks(t *testing.T) {
	t.Setenv("GITLAB_ISSUER", "https://gitlab.example.com")
	t.Setenv("GITLAB_AUDIENCE", "https://deploy.example.com")

	t.Setenv("ALLOWED_EXTERNAL_NETWORKS", "")
	if cfg, err := Load(); err != nil || cfg.AllowedExternalNetworks != nil {
		t.Fatalf("empty: cfg = %v, err = %v", cfg, err)
	}

	t.Setenv("ALLOWED_EXTERNAL_NETWORKS", " web , Traefik_Public.1, web,, ")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.AllowedExternalNetworks) != 2 || cfg.AllowedExternalNetworks[0] != "web" || cfg.AllowedExternalNetworks[1] != "Traefik_Public.1" {
		t.Errorf("AllowedExternalNetworks = %q", cfg.AllowedExternalNetworks)
	}

	for _, bad := range []string{"-web", ".web", "we b", "web/x", "_web"} {
		t.Setenv("ALLOWED_EXTERNAL_NETWORKS", bad)
		if _, err := Load(); err == nil {
			t.Errorf("ALLOWED_EXTERNAL_NETWORKS=%q: expected error", bad)
		}
	}
}

func TestDataDirFromEnv(t *testing.T) {
	t.Setenv("DATA_DIR", "")
	if got := DataDirFromEnv(); got != "./data" {
		t.Errorf("default = %q", got)
	}
	t.Setenv("DATA_DIR", "/srv/state")
	if got := DataDirFromEnv(); got != "/srv/state" {
		t.Errorf("override = %q", got)
	}
}
