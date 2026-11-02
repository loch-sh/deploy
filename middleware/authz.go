package middleware

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"deploy-server/internal/slug"
)

// Authorisation middleware. Both must be placed inside OIDCAuth: they only read
// the verified claims it stores in the request context, and reject the request
// with 401 when there are none (a wiring error, never a client error).

// RequireNamespace restricts the server to projects living under one of the
// allowed GitLab namespace paths. The token's namespace_path claim must equal
// an allowed path or be a sub-path of it: "apps/atmosphere" allows
// "apps/atmosphere" and "apps/atmosphere/api", but not "apps/atmosphere-evil".
// Matching is case-insensitive (GitLab paths are unique case-insensitively);
// allowed entries are expected lowercased, as config.Load produces them.
//
// A token without a namespace_path claim is rejected while the allowlist is
// active. When allowed is empty the middleware is a no-op (every project of the
// GitLab instance may call the server).
func RequireNamespace(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(allowed) == 0 {
			return next // disabled
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				http.Error(w, "missing verified claims", http.StatusUnauthorized)
				return
			}
			if !namespaceAllowed(claims.NamespacePath, allowed) {
				AddAuditAttrs(r.Context(), slog.String("authz_error", "namespace not allowed"))
				http.Error(w, fmt.Sprintf("namespace %q is not allowed to use this server", claims.NamespacePath), http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// namespaceAllowed reports whether ns equals one of allowed or is a sub-path
// of one of them. The comparison is done on whole path segments.
func namespaceAllowed(ns string, allowed []string) bool {
	ns = strings.ToLower(ns)
	if ns == "" {
		return false
	}
	for _, p := range allowed {
		if ns == p || strings.HasPrefix(ns, p+"/") {
			return true
		}
	}
	return false
}

// RequireProtectedRef enforces the protected-environment rule on every request
// it wraps (deploy, exec, stop, directories). For a token whose environment —
// normalised with the same GitLab slugification as the stack identity — is
// listed in protectedEnvs:
//
//   - ref_protected must be true (the pipeline runs on a protected
//     branch/tag), and
//   - when the token carries the environment_protected claim, it must be true
//     as well: GitLab reporting the environment as unprotected while this
//     server treats it as protected is a configuration mismatch, refused
//     rather than trusted. An absent claim is not held against the caller
//     (older GitLab versions do not emit it).
//
// Tokens for other environments, or with no environment claim at all (the
// handlers reject those with 400), pass through untouched.
func RequireProtectedRef(protectedEnvs map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				http.Error(w, "missing verified claims", http.StatusUnauthorized)
				return
			}
			if msg := protectedRefViolation(claims, protectedEnvs); msg != "" {
				AddAuditAttrs(r.Context(), slog.String("authz_error", msg))
				http.Error(w, msg, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// protectedRefViolation returns why claims may not act on a protected
// environment, or "" when the request is allowed.
func protectedRefViolation(c *Claims, protectedEnvs map[string]bool) string {
	env := slug.GitLab(c.Environment)
	if env == "" || !protectedEnvs[env] {
		return ""
	}
	if !c.RefProtected {
		return fmt.Sprintf("environment %q may only be targeted from a protected branch/tag", env)
	}
	if c.EnvironmentProtected != nil && !*c.EnvironmentProtected {
		return fmt.Sprintf("environment %q is protected here but not in GitLab (environment_protected=false)", env)
	}
	return ""
}
