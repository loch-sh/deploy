// Package middleware provides HTTP middleware for the deploy server.
//
// Authentication is delegated to GitLab via OpenID Connect. Each CI job mints a
// short-lived ID token (the `id_tokens` block in .gitlab-ci.yml) signed by the
// GitLab instance. This middleware verifies that token's signature, issuer,
// audience and expiry against the instance's published JWKS, then exposes the
// verified claims to downstream handlers. No long-lived shared secret exists.
package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	// maxTokenAge bounds how long after issuance (iat) an ID token is accepted,
	// independently of its exp. GitLab CI tokens are used within seconds of the
	// job start, so a longer window only widens the replay window of a leaked
	// token (e.g. one printed in a job log).
	maxTokenAge = 10 * time.Minute

	// clockSkew is the tolerated clock drift between GitLab and this server.
	// go-oidc has no leeway option for exp, so it is applied by shifting the
	// verifier's clock back (oidc.Config.Now): a token is accepted up to
	// clockSkew after its exp. go-oidc already allows 5 minutes on nbf. The
	// same tolerance applies to an iat slightly in the future.
	clockSkew = 30 * time.Second

	// discoveryTimeout bounds every HTTP request to the GitLab instance (OIDC
	// discovery at startup, JWKS fetch/refresh at runtime), so a hung GitLab
	// cannot block startup or pile up request goroutines.
	discoveryTimeout = 10 * time.Second
)

// Claims holds the subset of GitLab ID-token claims the deploy server relies on.
// They are derived from a cryptographically verified token, so handlers can
// trust them as the caller's true identity — they are never client-asserted.
type Claims struct {
	// ProjectPath is the full GitLab project path, e.g. "group/sub/project".
	ProjectPath string
	// NamespacePath is the project's group/user namespace, e.g. "group/sub".
	NamespacePath string
	// ProjectID is the numeric GitLab project id (stable ownership identity).
	ProjectID string
	// Environment is the deployment environment name, e.g. "staging".
	Environment string
	// Ref is the branch or tag that triggered the pipeline.
	Ref string
	// RefProtected reports whether Ref is a protected branch/tag.
	RefProtected bool
	// EnvironmentProtected reports whether the job's environment is a GitLab
	// protected environment. nil when the token does not carry the claim.
	EnvironmentProtected *bool
	// UserLogin and UserEmail identify the human who triggered the pipeline.
	UserLogin string
	UserEmail string
	// SHA is the commit the deployment was built from.
	SHA string
}

// gitlabClaims mirrors the raw GitLab ID-token payload. GitLab serialises
// several logically-boolean/numeric claims as JSON strings, so flexible types
// are used where needed.
type gitlabClaims struct {
	ProjectPath          string    `json:"project_path"`
	NamespacePath        string    `json:"namespace_path"`
	ProjectID            string    `json:"project_id"`
	Environment          string    `json:"environment"`
	EnvironmentProtected *flexBool `json:"environment_protected"`
	Ref                  string    `json:"ref"`
	RefProtected         flexBool  `json:"ref_protected"`
	UserLogin            string    `json:"user_login"`
	UserEmail            string    `json:"user_email"`
	SHA                  string    `json:"sha"`
}

// flexBool unmarshals both JSON booleans (true) and JSON strings ("true"),
// because GitLab encodes ref_protected as a string in ID tokens.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	*b = s == "true"
	return nil
}

type ctxKey struct{}

// ClaimsFromContext returns the verified claims attached by OIDCAuth.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// ContextWithClaims returns a copy of ctx carrying claims. OIDCAuth uses it
// internally; it is also exported so handler tests can inject claims without a
// live OIDC provider.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, claims)
}

// Verifier wraps an oidc.IDTokenVerifier. Construct it with NewVerifier.
type Verifier struct {
	verifier *oidc.IDTokenVerifier
	now      func() time.Time
}

// NewVerifier performs OIDC discovery against issuer and returns a Verifier that
// requires the given audience. It contacts the GitLab instance, so it can fail
// at startup if GitLab is unreachable.
//
// All requests to GitLab (discovery and JWKS) use an HTTP client bounded by
// discoveryTimeout. The https:// requirement on the issuer is enforced by the
// configuration (config.Load), not here, so tests can use a plain-HTTP issuer.
func NewVerifier(ctx context.Context, issuer, audience string) (*Verifier, error) {
	return newVerifier(ctx, issuer, audience, &http.Client{Timeout: discoveryTimeout})
}

// newVerifier is NewVerifier with an injectable HTTP client. The client is
// carried by the context passed to oidc.NewProvider; go-oidc keeps it for the
// provider's JWKS key set as well.
func newVerifier(ctx context.Context, issuer, audience string, client *http.Client) (*Verifier, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover %s: %w", issuer, err)
	}
	v := &Verifier{now: time.Now}
	v.verifier = provider.Verifier(&oidc.Config{
		ClientID: audience,
		// Shift the clock back by clockSkew: go-oidc then accepts a token up
		// to clockSkew past its exp (it has no dedicated leeway option).
		Now: func() time.Time { return v.now().Add(-clockSkew) },
	})
	return v, nil
}

// checkTokenAge enforces the anti-replay window on the token's iat: it must be
// present, not older than maxTokenAge and not further than clockSkew in the
// future.
func (v *Verifier) checkTokenAge(iat time.Time) error {
	if iat.IsZero() {
		return fmt.Errorf("token has no iat claim")
	}
	now := v.now()
	if age := now.Sub(iat); age > maxTokenAge+clockSkew {
		return fmt.Errorf("token issued %s ago, older than %s", age.Truncate(time.Second), maxTokenAge)
	}
	if iat.After(now.Add(clockSkew)) {
		return fmt.Errorf("token issued in the future (iat %s)", iat.UTC().Format(time.RFC3339))
	}
	return nil
}

// OIDCAuth returns middleware that verifies the Authorization: Bearer <id_token>
// header. On success the verified Claims are stored in the request context;
// otherwise the request is rejected with 401.
func (v *Verifier) OIDCAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found || raw == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		idToken, err := v.verifier.Verify(r.Context(), raw)
		if err != nil {
			// The precise reason (expired, wrong audience…) goes to the audit
			// log only; the client gets a generic message.
			AddAuditAttrs(r.Context(), slog.String("auth_error", err.Error()))
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if err := v.checkTokenAge(idToken.IssuedAt); err != nil {
			AddAuditAttrs(r.Context(), slog.String("auth_error", err.Error()))
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		var gcl gitlabClaims
		if err := idToken.Claims(&gcl); err != nil {
			AddAuditAttrs(r.Context(), slog.String("auth_error", err.Error()))
			http.Error(w, "unreadable token claims", http.StatusUnauthorized)
			return
		}

		claims := &Claims{
			ProjectPath:   gcl.ProjectPath,
			NamespacePath: gcl.NamespacePath,
			ProjectID:     gcl.ProjectID,
			Environment:   gcl.Environment,
			Ref:           gcl.Ref,
			RefProtected:  bool(gcl.RefProtected),
			UserLogin:     gcl.UserLogin,
			UserEmail:     gcl.UserEmail,
			SHA:           gcl.SHA,
		}
		if gcl.EnvironmentProtected != nil {
			p := bool(*gcl.EnvironmentProtected)
			claims.EnvironmentProtected = &p
		}

		AddAuditAttrs(r.Context(), claimsAuditAttrs(claims)...)
		next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
	})
}
