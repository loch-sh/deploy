package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxAuditErrorBytes caps how much of an error response body is copied into
// the audit entry.
const maxAuditErrorBytes = 256

// auditRecord collects attributes contributed while a request is being served:
// verified identity (OIDCAuth) and action details (handlers).
type auditRecord struct {
	mu    sync.Mutex
	attrs []slog.Attr
}

type auditKey struct{}

// AddAuditAttrs attaches attributes to the audit entry of the request carried
// by ctx. It is a no-op when the request is not audited.
func AddAuditAttrs(ctx context.Context, attrs ...slog.Attr) {
	rec, ok := ctx.Value(auditKey{}).(*auditRecord)
	if !ok {
		return
	}
	rec.mu.Lock()
	rec.attrs = append(rec.attrs, attrs...)
	rec.mu.Unlock()
}

// Audit returns middleware that writes exactly one "audit" entry per request
// once it has been served: method, path, status, resolved client IP, duration,
// the error message for failed requests, plus whatever inner layers added via
// AddAuditAttrs (the caller's verified GitLab identity, action details).
//
// It must wrap the IP allowlist and the token verification so that rejected
// requests are audited too. trustedProxies is used to resolve the client IP
// exactly as the allowlist does.
func Audit(logger *slog.Logger, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &auditRecord{}
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), auditKey{}, rec)))

			client := ""
			if ip := clientIP(r, trustedProxies); ip != nil {
				client = ip.String()
			}
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.status),
				slog.String("client_ip", client),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			}
			if sw.status >= http.StatusBadRequest {
				attrs = append(attrs, slog.String("error", strings.TrimSpace(sw.errBody.String())))
			}
			rec.mu.Lock()
			attrs = append(attrs, rec.attrs...)
			rec.mu.Unlock()

			logger.LogAttrs(r.Context(), auditLevel(sw.status), "audit", attrs...)
		})
	}
}

// claimsAuditAttrs returns the identity attributes recorded for a verified
// caller. The e-mail address is deliberately left out; user_login identifies
// the person.
func claimsAuditAttrs(c *Claims) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("project_path", c.ProjectPath),
		slog.String("namespace_path", c.NamespacePath),
		slog.String("project_id", c.ProjectID),
		slog.String("environment", c.Environment),
		slog.String("ref", c.Ref),
		slog.Bool("ref_protected", c.RefProtected),
		slog.String("user_login", c.UserLogin),
		slog.String("sha", c.SHA),
	}
	// environment_protected is only logged when the token carries it, so its
	// absence stays distinguishable from false.
	if c.EnvironmentProtected != nil {
		attrs = append(attrs, slog.Bool("environment_protected", *c.EnvironmentProtected))
	}
	return attrs
}

func auditLevel(status int) slog.Level {
	switch {
	case status >= http.StatusInternalServerError:
		return slog.LevelError
	case status >= http.StatusBadRequest:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}

// statusWriter records the response status and the beginning of error bodies.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	errBody     bytes.Buffer
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.status >= http.StatusBadRequest {
		if room := maxAuditErrorBytes - w.errBody.Len(); room > 0 {
			w.errBody.Write(b[:min(len(b), room)])
		}
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
