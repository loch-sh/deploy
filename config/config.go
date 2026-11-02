// Package config loads server configuration from environment variables.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"deploy-server/internal/slug"
)

// Bounds for MAX_UPLOAD_MB.
const (
	minUploadMB      = 1
	maxUploadMBLimit = 1024
)

// Config holds all runtime configuration for the deploy server.
type Config struct {
	// ListenAddr is the TCP address the HTTP server binds to (e.g. ":8080").
	ListenAddr string

	// ComposeBase is the root directory for Docker Compose stacks.
	// Each stack lives at ComposeBase/{namespace}-{environment}/.
	ComposeBase string

	// WebsitesBase is the root directory for bind-mount project data.
	// Directories are created at WebsitesBase/{namespace}-{environment}/{service}/{name}/.
	WebsitesBase string

	// MaxUploadMB is the maximum allowed multipart upload size in megabytes.
	MaxUploadMB int64

	// DataDir is the directory used to store server state (registry.json, autostop.json).
	DataDir string

	// GitLabIssuer is the OIDC issuer URL of the GitLab instance that signs CI
	// ID tokens (e.g. "https://gitlab.example.com"). The server discovers the
	// JWKS via OIDC discovery at {issuer}/.well-known/openid-configuration and
	// verifies every request's Bearer token against it.
	GitLabIssuer string

	// GitLabAudience is the audience ("aud" claim) the server requires in every
	// ID token. It must match the `aud:` configured in the GitLab job's
	// id_tokens block. This binds tokens to this server and prevents a token
	// minted for another service from being replayed here.
	GitLabAudience string

	// ProtectedEnvironments lists environment slugs that may only be targeted
	// from a protected branch/tag (the token's ref_protected claim must be
	// true). The configured names are normalised with the same GitLab
	// slugification as the token's environment claim, so "Production" and
	// "production" are equivalent. Defaults to {"production"}.
	ProtectedEnvironments map[string]bool

	// AllowedNamespaces lists the GitLab namespace paths (groups/subgroups or
	// user namespaces) whose projects may call the server. A token is accepted
	// only when its namespace_path claim equals one of them or is a sub-path of
	// one ("apps/atmosphere" allows "apps/atmosphere/api" but not
	// "apps/atmosphere-evil"). Entries are lowercased, without leading/trailing
	// slashes. When empty every project of the GitLab instance is allowed.
	AllowedNamespaces []string

	// ForbiddenTraefikHosts lists host names that no stack may claim in a
	// Traefik Host() rule (typically this server's own public host name, or
	// GitLab's). Entries are lowercased, without port or trailing dot.
	ForbiddenTraefikHosts []string

	// AllowedExternalNetworks lists the external Docker networks stacks may
	// join (typically Traefik's network, e.g. "web"). Names are kept as is
	// (Docker network names are case-sensitive). When empty no external
	// network is allowed.
	AllowedExternalNetworks []string

	// AllowedIPs is the network allowlist: only requests whose resolved client
	// IP falls inside one of these networks are served (the /health endpoint is
	// exempt). Typically the GitLab server / CI-runner egress address. When
	// empty the allowlist is disabled (all IPs allowed).
	AllowedIPs []*net.IPNet

	// TrustedProxies lists the networks of reverse proxies (e.g. Traefik) that
	// are trusted to set X-Forwarded-For. The real client IP is only taken from
	// that header when the direct peer is one of these proxies; otherwise the
	// socket peer address is used. This prevents X-Forwarded-For spoofing.
	TrustedProxies []*net.IPNet
}

// Load reads configuration from environment variables, applying defaults where values are absent.
//
// Environment variables:
//
//	LISTEN_ADDR      — HTTP listen address         (default: ":8080")
//	COMPOSE_BASE     — base dir for compose stacks (default: "/data/compose")
//	WEBSITES_BASE    — base dir for bind mounts    (default: "/data/websites")
//	MAX_UPLOAD_MB    — max upload size in MB       (default: 10, range 1..1024)
//	DATA_DIR         — server state directory      (default: "./data")
//	GITLAB_ISSUER    — GitLab OIDC issuer URL      (required, https://)
//	GITLAB_AUDIENCE  — required token audience     (required)
//	PROTECTED_ENVS   — comma-separated env names   (default: "production")
//	ALLOWED_NAMESPACES — namespace_path prefixes   (default: "" → all allowed)
//	FORBIDDEN_TRAEFIK_HOSTS — hosts no stack may route (default: "")
//	ALLOWED_EXTERNAL_NETWORKS — joinable external networks (default: "" → none)
//	ALLOWED_IPS      — IP/CIDR allowlist           (default: "" → disabled)
//	TRUSTED_PROXIES  — proxy IP/CIDR for XFF trust (default: "")
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:     envOrDefault("LISTEN_ADDR", ":8080"),
		ComposeBase:    envOrDefault("COMPOSE_BASE", "/data/compose"),
		WebsitesBase:   envOrDefault("WEBSITES_BASE", "/data/websites"),
		DataDir:        DataDirFromEnv(),
		GitLabIssuer:   os.Getenv("GITLAB_ISSUER"),
		GitLabAudience: os.Getenv("GITLAB_AUDIENCE"),
	}

	if c.GitLabIssuer == "" {
		return nil, fmt.Errorf("GITLAB_ISSUER is required (e.g. https://gitlab.example.com)")
	}
	if err := validateIssuer(c.GitLabIssuer); err != nil {
		return nil, fmt.Errorf("invalid GITLAB_ISSUER: %w", err)
	}
	if c.GitLabAudience == "" {
		return nil, fmt.Errorf("GITLAB_AUDIENCE is required (must match the id_tokens aud in .gitlab-ci.yml)")
	}

	var err error
	c.ProtectedEnvironments, err = parseEnvSet(envOrDefault("PROTECTED_ENVS", "production"))
	if err != nil {
		return nil, fmt.Errorf("invalid PROTECTED_ENVS: %w", err)
	}
	c.AllowedNamespaces, err = parseNamespaceList(os.Getenv("ALLOWED_NAMESPACES"))
	if err != nil {
		return nil, fmt.Errorf("invalid ALLOWED_NAMESPACES: %w", err)
	}
	c.ForbiddenTraefikHosts, err = parseHostList(os.Getenv("FORBIDDEN_TRAEFIK_HOSTS"))
	if err != nil {
		return nil, fmt.Errorf("invalid FORBIDDEN_TRAEFIK_HOSTS: %w", err)
	}
	c.AllowedExternalNetworks, err = parseNetworkList(os.Getenv("ALLOWED_EXTERNAL_NETWORKS"))
	if err != nil {
		return nil, fmt.Errorf("invalid ALLOWED_EXTERNAL_NETWORKS: %w", err)
	}
	c.AllowedIPs, err = parseCIDRList(os.Getenv("ALLOWED_IPS"))
	if err != nil {
		return nil, fmt.Errorf("invalid ALLOWED_IPS: %w", err)
	}
	c.TrustedProxies, err = parseCIDRList(os.Getenv("TRUSTED_PROXIES"))
	if err != nil {
		return nil, fmt.Errorf("invalid TRUSTED_PROXIES: %w", err)
	}

	maxUploadMB, err := envIntOrDefault("MAX_UPLOAD_MB", 10)
	if err != nil {
		return nil, fmt.Errorf("invalid MAX_UPLOAD_MB: %w", err)
	}
	if maxUploadMB < minUploadMB || maxUploadMB > maxUploadMBLimit {
		return nil, fmt.Errorf("invalid MAX_UPLOAD_MB: %d is outside %d..%d", maxUploadMB, minUploadMB, maxUploadMBLimit)
	}
	c.MaxUploadMB = maxUploadMB

	return c, nil
}

// DataDirFromEnv returns the state directory (DATA_DIR, default "./data")
// without loading nor validating the rest of the configuration. It is used by
// offline maintenance commands such as -import-registry.
func DataDirFromEnv() string {
	return envOrDefault("DATA_DIR", "./data")
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envIntOrDefault(key string, defaultVal int64) (int64, error) {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal, nil
	}
	return strconv.ParseInt(v, 10, 64)
}

// parseCIDRList parses a comma-separated list of IPs and/or CIDR blocks into
// networks. Bare IPs are treated as a single-host network (/32 or /128).
// An empty string yields a nil slice (feature disabled).
func parseCIDRList(csv string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for part := range strings.SplitSeq(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if strings.Contains(p, "/") {
			_, n, err := net.ParseCIDR(p)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", p, err)
			}
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			return nil, fmt.Errorf("%q is not a valid IP or CIDR", p)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// validateIssuer requires an absolute https:// URL with a host: the issuer is
// where the JWKS used to verify every token is fetched from, so it must never
// be retrieved over plain HTTP.
func validateIssuer(issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%q must be an https:// URL", issuer)
	}
	return nil
}

// parseEnvSet turns "a, B ,c" into the set of their GitLab slugs
// {"a","b","c"}, ignoring blanks. The slugification is the one applied to the
// token's environment claim, so a configured name always matches the
// environment it designates. A name whose slug is empty is rejected rather
// than silently ignored, which would leave the environment unprotected.
func parseEnvSet(csv string) (map[string]bool, error) {
	set := make(map[string]bool)
	for part := range strings.SplitSeq(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		s := slug.GitLab(p)
		if s == "" {
			return nil, fmt.Errorf("%q has an empty slug", p)
		}
		set[s] = true
	}
	return set, nil
}

// namespacePathRE matches a GitLab namespace path: one or more segments of
// letters, digits, '.', '_' or '-', separated by single slashes.
var namespacePathRE = regexp.MustCompile(`^[a-z0-9_.-]+(/[a-z0-9_.-]+)*$`)

// parseNamespaceList parses ALLOWED_NAMESPACES: comma-separated GitLab
// namespace paths, lowercased (GitLab paths are unique case-insensitively)
// and stripped of surrounding slashes. An empty string yields nil (no
// restriction).
func parseNamespaceList(csv string) ([]string, error) {
	var out []string
	for part := range strings.SplitSeq(csv, ",") {
		p := strings.ToLower(strings.Trim(strings.TrimSpace(part), "/"))
		if p == "" {
			continue
		}
		if !namespacePathRE.MatchString(p) {
			return nil, fmt.Errorf("%q is not a valid GitLab namespace path", part)
		}
		for seg := range strings.SplitSeq(p, "/") {
			if seg == "." || seg == ".." {
				return nil, fmt.Errorf("%q is not a valid GitLab namespace path", part)
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// hostLabelRE matches one DNS label (lowercase).
var hostLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// parseHostList parses FORBIDDEN_TRAEFIK_HOSTS: comma-separated host names,
// optionally with a port ("deploy.example.com:443") or a trailing dot, which
// are stripped. Hosts are lowercased and deduplicated. Each must be a valid
// DNS name or an IP address. An empty string yields nil.
func parseHostList(csv string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for part := range strings.SplitSeq(csv, ",") {
		p := strings.ToLower(strings.TrimSpace(part))
		if p == "" {
			continue
		}
		if host, port, err := net.SplitHostPort(p); err == nil {
			if _, err := strconv.ParseUint(port, 10, 16); err != nil {
				return nil, fmt.Errorf("%q has an invalid port", strings.TrimSpace(part))
			}
			p = host
		}
		p = strings.TrimSuffix(strings.Trim(p, "[]"), ".")
		if !validHost(p) {
			return nil, fmt.Errorf("%q is not a valid host name", strings.TrimSpace(part))
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// validHost reports whether h is an IP address or a lowercase DNS name.
func validHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if h == "" || len(h) > 253 {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if !hostLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

// networkNameRE matches a Docker network name.
var networkNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// parseNetworkList parses ALLOWED_EXTERNAL_NETWORKS: comma-separated Docker
// network names, kept case-sensitive and deduplicated. An empty string yields
// nil (no external network allowed).
func parseNetworkList(csv string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	for part := range strings.SplitSeq(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if !networkNameRE.MatchString(p) {
			return nil, fmt.Errorf("%q is not a valid Docker network name", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}
