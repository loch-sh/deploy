package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"deploy-server/compose"
	"deploy-server/middleware"
	"deploy-server/registry"
	"deploy-server/scheduler"
)

// DeployConfig holds the dependencies needed by the deploy handler.
type DeployConfig struct {
	ComposeBase   string
	WebsitesBase  string // bind-mount sources must be WebsitesBase/<key>/<service>/<name>
	MaxUploadMB   int64
	Registry      *registry.Registry
	Scheduler     *scheduler.Scheduler
	ProtectedEnvs map[string]bool
	// ForbiddenTraefikHosts are host names no stack may route with Traefik
	// (compose.Policy.ForbiddenHosts). Populated from FORBIDDEN_TRAEFIK_HOSTS;
	// it should at least contain the deploy server's own public host name.
	ForbiddenTraefikHosts []string
	// AllowedExternalNetworks are the external networks (e.g. Traefik's shared
	// network) stacks may join (compose.Policy.AllowedExternalNetworks). Empty
	// means every `external: true` network is refused.
	AllowedExternalNetworks []string
}

// maxAutoStopDays caps auto_stop_days.
const maxAutoStopDays = 365

// Excerpt sizes for docker compose output: what is logged on failure, and what
// is returned to the client (stderr tail only, server paths redacted).
const (
	logExcerptBytes    = 64 << 10
	clientExcerptBytes = 400
)

// Deploy handles POST /deploy.
//
// The target namespace/environment are derived from the verified GitLab ID
// token (project_path + environment claims), never from the request body. It:
//  1. Resolves the stack identity from the token claims.
//  2. Enforces the protected-branch rule for protected environments.
//  3. Validates every input (auto_stop_days, env file names) up front.
//  4. Takes the per-stack lock and checks project ownership via the registry.
//  5. Refuses (409) to deploy while existing containers of the stack have bind
//     mounts outside the WEBSITES_BASE/<key>/<service>/<name> layout
//     (checkExistingMounts).
//  6. Writes the uploaded files to a staging directory and validates the
//     rendered compose model against the deployment policy (compose.Policy).
//  7. Moves the validated files into the stack directory and prunes stale files.
//  8. Runs docker compose pull && up, pinned to the stack's project name.
//  9. Records ownership (only once the deploy succeeded) and schedules the
//     auto-stop, or cancels a previous one when none is requested.
func Deploy(cfg DeployConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// -- Identity from verified claims -------------------------------------
		st, code, msg := stackFromClaims(r)
		if code != 0 {
			httpError(w, msg, code)
			return
		}
		if msg := requireProtectedRef(st, cfg.ProtectedEnvs); msg != "" {
			httpError(w, msg, http.StatusForbidden)
			return
		}

		maxBytes := cfg.MaxUploadMB << 20 // MB → bytes
		// Cap the total request body, not just the in-memory portion.
		// ParseMultipartForm's argument only bounds memory; without this wrapper
		// the overflow spills to unbounded temp files on disk (disk-fill DoS).
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		if err := r.ParseMultipartForm(maxBytes); err != nil {
			httpError(w, fmt.Sprintf("invalid multipart form: %v", err), http.StatusBadRequest)
			return
		}

		// -- Validate every input before touching disk or Docker ---------------
		autoStopDays, err := parseAutoStopDays(r.FormValue("auto_stop_days"))
		if err == nil && autoStopDays > maxAutoStopDays {
			err = fmt.Errorf("auto_stop_days must not exceed %d", maxAutoStopDays)
		}
		if err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Accept both "env_files" and the "env_files[]" spelling used by
		// `curl -F "env_files[]=@…"` in CI examples.
		envFiles := append(r.MultipartForm.File["env_files"], r.MultipartForm.File["env_files[]"]...)
		keep := map[string]bool{composeFileName: true}
		for _, fh := range envFiles {
			if err := validateEnvFileName(fh.Filename); err != nil {
				httpError(w, err.Error(), http.StatusBadRequest)
				return
			}
			if keep[fh.Filename] {
				httpError(w, fmt.Sprintf("env file %q is uploaded more than once", fh.Filename), http.StatusBadRequest)
				return
			}
			keep[fh.Filename] = true
		}

		envNames := make([]string, 0, len(envFiles))
		for _, fh := range envFiles {
			envNames = append(envNames, fh.Filename)
		}
		middleware.AddAuditAttrs(r.Context(),
			slog.Int("auto_stop_days", autoStopDays),
			slog.Any("env_files", envNames),
		)

		if cfg.WebsitesBase == "" {
			slog.Error("deploy: WebsitesBase is not configured")
			httpError(w, "server misconfigured", http.StatusInternalServerError)
			return
		}

		// -- Serialise operations on this stack --------------------------------
		unlock, err := stackLocks.lock(r.Context(), st.Key)
		if err != nil {
			httpError(w, "request cancelled while waiting for another operation on this stack", http.StatusServiceUnavailable)
			return
		}
		defer unlock()

		// -- Ownership check ---------------------------------------------------
		// Only verified here: ownership is recorded once the deploy succeeded,
		// so a rejected or failed first deploy does not squat the key. The
		// stack lock makes Verify + Claim atomic for this key.
		owner := stackOwner(r, st)
		if err := cfg.Registry.VerifyOwner(owner); err != nil && !errors.Is(err, registry.ErrNotClaimed) {
			ownershipError(w, err)
			return
		}

		// -- Build stack paths (path traversal safe) ---------------------------
		stackDir, err := safeChild(cfg.ComposeBase, st.Key)
		if err != nil {
			httpError(w, "invalid stack path", http.StatusBadRequest)
			return
		}
		websitesDir, err := safeChild(cfg.WebsitesBase, st.Key)
		if err != nil {
			httpError(w, "invalid stack path", http.StatusBadRequest)
			return
		}

		// -- Existing containers ----------------------------------------------
		// Before anything is written: a container left by an older deployment
		// with a bind on <key>/ or <key>/<service>/ (or outside the stack's data
		// directory) could swap a validated bind source for a symlink during
		// pull. Such a stack must be removed with DELETE /stack first (409).
		if code, msg := checkExistingMounts(r.Context(), st, websitesDir); code != 0 {
			httpError(w, msg, code)
			return
		}

		// -- Stage the uploaded files ------------------------------------------
		// Files are written to a private staging directory next to the stack
		// directory (same filesystem, so they can be renamed into place) and the
		// exact bytes written there are what gets validated and then deployed.
		// Stack keys never start with a dot, so the name cannot collide.
		if err := os.MkdirAll(cfg.ComposeBase, 0o700); err != nil {
			slog.Error("deploy: create compose base", "dir", cfg.ComposeBase, "error", err)
			httpError(w, "failed to create stack directory", http.StatusInternalServerError)
			return
		}
		staging, err := os.MkdirTemp(cfg.ComposeBase, ".staging-"+st.Key+"-")
		if err != nil {
			slog.Error("deploy: create staging directory", "dir", cfg.ComposeBase, "error", err)
			httpError(w, "failed to create stack directory", http.StatusInternalServerError)
			return
		}
		defer os.RemoveAll(staging)

		if code, msg := stageFiles(r, staging, envFiles); code != 0 {
			httpError(w, msg, code)
			return
		}

		// -- Validate the compose model against the deployment policy ----------
		policy := compose.Policy{
			Key:                     st.Key,
			ProjectDir:              staging,
			WebsitesDir:             websitesDir,
			ForbiddenHosts:          cfg.ForbiddenTraefikHosts,
			AllowedExternalNetworks: cfg.AllowedExternalNetworks,
		}
		if code, msg := validateStaged(r.Context(), st, staging, policy); code != 0 {
			httpError(w, msg, code)
			return
		}

		// -- Move the validated files into the stack directory -----------------
		if err := os.MkdirAll(stackDir, 0o700); err != nil {
			slog.Error("deploy: create stack directory", "dir", stackDir, "error", err)
			httpError(w, "failed to create stack directory", http.StatusInternalServerError)
			return
		}
		for name := range keep {
			if err := os.Rename(filepath.Join(staging, name), filepath.Join(stackDir, name)); err != nil {
				slog.Error("deploy: install file", "dir", stackDir, "file", name, "error", err)
				httpError(w, fmt.Sprintf("failed to install %s", name), http.StatusInternalServerError)
				return
			}
		}

		// Remove env files left over from a previous deploy so the stack only
		// sees what this deploy uploaded.
		if err := pruneStackDir(stackDir, keep); err != nil {
			slog.Error("deploy: prune stack directory", "dir", stackDir, "error", err)
			httpError(w, "failed to clean stack directory", http.StatusInternalServerError)
			return
		}

		// -- Run docker compose pull + up --------------------------------------
		cs := compose.Stack{Key: st.Key, Dir: stackDir, ComposeFile: filepath.Join(stackDir, composeFileName)}
		if out, err := compose.Pull(r.Context(), cs); err != nil {
			composeFailure(w, st, "pull", stackDir, out, err)
			return
		}
		// Up is detached from the request context once started (see compose.Up).
		if out, err := compose.Up(r.Context(), cs); err != nil {
			composeFailure(w, st, "up", stackDir, out, err)
			return
		}

		// -- Record ownership --------------------------------------------------
		if err := cfg.Registry.ClaimOwner(owner); err != nil {
			slog.Error("deploy: record ownership", "namespace", st.Namespace, "environment", st.Environment, "error", err)
			if errors.Is(err, registry.ErrOwnerMismatch) || errors.Is(err, registry.ErrKeyCollision) {
				ownershipError(w, err)
				return
			}
			httpError(w, "stack deployed but ownership could not be recorded; retry the deploy", http.StatusInternalServerError)
			return
		}

		// -- Auto-stop --------------------------------------------------------
		// Every deploy defines the auto-stop state: without auto_stop_days any
		// previously scheduled stop is cancelled.
		duration := time.Duration(autoStopDays) * 24 * time.Hour
		if err := cfg.Scheduler.Schedule(st.Namespace, st.Environment, duration); err != nil {
			slog.Error("deploy: schedule auto-stop", "namespace", st.Namespace, "environment", st.Environment, "error", err)
			// Non-fatal — deployment already succeeded.
		}

		slog.Info("deploy: stack deployed", "namespace", st.Namespace, "environment", st.Environment)
		w.WriteHeader(http.StatusNoContent)
	}
}

// stageFiles writes the uploaded compose file and env files into dir. It
// returns an HTTP status code and message on failure.
func stageFiles(r *http.Request, dir string, envFiles []*multipart.FileHeader) (int, string) {
	if err := writeFormFile(r, "compose_file", filepath.Join(dir, composeFileName), 0o600); err != nil {
		var missing *missingFieldError
		if errors.As(err, &missing) {
			return http.StatusBadRequest, fmt.Sprintf("compose_file: %v", err)
		}
		slog.Error("deploy: stage compose file", "error", err)
		return http.StatusInternalServerError, "compose_file: failed to write file"
	}
	for _, fh := range envFiles {
		f, err := fh.Open()
		if err != nil {
			return http.StatusBadRequest, fmt.Sprintf("env_files: cannot read %s", fh.Filename)
		}
		writeErr := writeReader(f, filepath.Join(dir, fh.Filename), 0o600)
		f.Close()
		if writeErr != nil {
			slog.Error("deploy: stage env file", "file", fh.Filename, "error", writeErr)
			return http.StatusInternalServerError, fmt.Sprintf("env_files: failed to write %s", fh.Filename)
		}
	}
	return 0, ""
}

// validateStaged checks the staged files against the deployment policy:
//  1. the raw compose file must not use include/extends/label_file, which would
//     make docker compose read other server files while rendering it;
//  2. an uploaded .env must not override COMPOSE_* / DOCKER_* settings;
//  3. the model rendered by `docker compose config` (pinned to the stack's
//     project name) must satisfy compose.ValidatePolicy.
//
// It returns an HTTP status code and message on failure.
func validateStaged(ctx context.Context, st stack, staging string, policy compose.Policy) (int, string) {
	composeFile := filepath.Join(staging, composeFileName)
	raw, err := os.ReadFile(composeFile)
	if err != nil {
		slog.Error("deploy: read staged compose file", "error", err)
		return http.StatusInternalServerError, "failed to read compose file"
	}
	if err := compose.CheckSource(raw); err != nil {
		return http.StatusBadRequest, err.Error()
	}
	if dotEnv, err := os.ReadFile(filepath.Join(staging, ".env")); err == nil {
		if err := compose.CheckDotEnv(dotEnv); err != nil {
			return http.StatusBadRequest, err.Error()
		}
	}

	out, err := compose.Config(ctx, compose.Stack{Key: st.Key, Dir: staging, ComposeFile: composeFile})
	if err != nil {
		slog.Warn("deploy: compose config failed", "namespace", st.Namespace, "environment", st.Environment,
			"error", err, "stderr", tail(out.Stderr, logExcerptBytes))
		if code := contextStatus(err); code != 0 {
			return code, "docker compose config " + http.StatusText(code)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return http.StatusInternalServerError, "failed to render compose file"
		}
		return http.StatusBadRequest, "invalid compose file: " + clientExcerpt(out.Stderr, staging)
	}
	doc, err := compose.ParseModel([]byte(out.Stdout))
	if err != nil {
		slog.Error("deploy: parse compose config", "namespace", st.Namespace, "environment", st.Environment, "error", err)
		return http.StatusBadRequest, "compose file could not be rendered"
	}
	if err := compose.ValidatePolicy(doc, policy); err != nil {
		return http.StatusBadRequest, err.Error()
	}
	return 0, ""
}

// composeFailure logs a failed docker compose step (output truncated) and
// replies with a generic message plus a short, redacted stderr excerpt.
func composeFailure(w http.ResponseWriter, st stack, step, stackDir string, out *compose.Output, err error) {
	slog.Error("deploy: compose "+step+" failed", "namespace", st.Namespace, "environment", st.Environment,
		"error", err, "stdout", tail(out.Stdout, logExcerptBytes), "stderr", tail(out.Stderr, logExcerptBytes))
	msg := fmt.Sprintf("docker compose %s failed", step)
	code := http.StatusInternalServerError
	if c := contextStatus(err); c != 0 {
		code = c
		msg = fmt.Sprintf("docker compose %s: %s", step, strings.ToLower(http.StatusText(c)))
	}
	if ex := clientExcerpt(out.Stderr, stackDir); ex != "" {
		msg += ": " + ex
	}
	httpError(w, msg, code)
}

// contextStatus maps a compose error caused by its context to an HTTP status:
// 504 when the operation hit its timeout, 503 when the request was cancelled
// (e.g. while waiting for a free docker slot), 0 otherwise.
func contextStatus(err error) int {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	case errors.Is(err, context.Canceled):
		return http.StatusServiceUnavailable
	}
	return 0
}

// clientExcerpt returns the last clientExcerptBytes of s with dir (a server
// path) redacted, safe to return to the client.
func clientExcerpt(s, dir string) string {
	if dir != "" {
		s = strings.ReplaceAll(s, dir, "<stack>")
	}
	return strings.TrimSpace(tail(s, clientExcerptBytes))
}

// tail returns at most the last n bytes of s, on a valid UTF-8 boundary,
// prefixed with "…" when cut.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + strings.ToValidUTF8(s[len(s)-n:], "")
}

// pruneStackDir removes every regular file in dir whose name is not in keep.
func pruneStackDir(dir string, keep map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if keep[e.Name()] || !e.Type().IsRegular() {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// writeFormFile reads the named file field from the multipart form and writes
// it to dest with the given permissions.
func writeFormFile(r *http.Request, field, dest string, perm os.FileMode) error {
	f, _, err := r.FormFile(field)
	if err != nil {
		return &missingFieldError{field: field, err: err}
	}
	defer f.Close()
	return writeReader(f, dest, perm)
}

// missingFieldError reports a missing or unreadable multipart file field.
type missingFieldError struct {
	field string
	err   error
}

func (e *missingFieldError) Error() string {
	return fmt.Sprintf("missing or unreadable field %q: %v", e.field, e.err)
}

func (e *missingFieldError) Unwrap() error { return e.err }

// writeReader copies from src to dest atomically via a temp file.
func writeReader(src io.Reader, dest string, perm os.FileMode) error {
	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// httpError writes a plain-text error response. Using text/plain keeps the
// response simple for curl-based CI pipelines.
func httpError(w http.ResponseWriter, msg string, code int) {
	http.Error(w, msg, code)
}

// maxJSONBody caps the size of JSON request bodies (/exec, /directories).
const maxJSONBody = 1 << 20 // 1 MiB

// decodeJSONBody decodes the size-capped request body into v.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	return json.NewDecoder(r.Body).Decode(v)
}

// stopStack stops a stack and removes its compose directory. It is also used
// as the scheduler's StopFunc.
//
//  1. When the compose file is present, docker compose down --remove-orphans
//     stops and removes the project's containers, networks included.
//  2. Every container of the stack still found by compose.StackContainers is
//     then stopped and removed (docker stop, docker rm --force): a stack
//     running without a compose file in COMPOSE_BASE/<key>/ (started from
//     another directory by an older workflow, or whose directory was removed)
//     is not touched by down, nor is a container named after the key without
//     the compose project label. Without
//     this sweep, such containers would keep blocking deploys (409, see
//     checkExistingMounts). Their networks and anonymous volumes are left.
//  3. The compose directory is removed.
//
// Bind-mount data under WEBSITES_BASE is never touched.
func stopStack(composeBase string) func(ctx context.Context, namespace, environment string) error {
	return func(ctx context.Context, namespace, environment string) error {
		stackDir, err := safeChild(composeBase, namespace+"-"+environment)
		if err != nil {
			return err
		}
		cs := compose.Stack{
			Key:         namespace + "-" + environment,
			Dir:         stackDir,
			ComposeFile: filepath.Join(stackDir, composeFileName),
		}

		if _, err := os.Stat(cs.ComposeFile); err == nil {
			// Down is detached from ctx once started (see compose.Down).
			if out, err := compose.Down(ctx, cs); err != nil {
				slog.Error("stop: compose down failed", "namespace", namespace, "environment", environment,
					"error", err, "stdout", tail(out.Stdout, logExcerptBytes), "stderr", tail(out.Stderr, logExcerptBytes))
				return fmt.Errorf("docker compose down: %w", err)
			}
		}

		if err := removeLeftoverContainers(ctx, cs.Key); err != nil {
			slog.Error("stop: remove leftover containers failed", "namespace", namespace, "environment", environment, "error", err)
			return err
		}

		if err := os.RemoveAll(stackDir); err != nil {
			return fmt.Errorf("remove stack dir %s: %w", stackDir, err)
		}
		slog.Info("stop: removed stack directory", "dir", stackDir)
		return nil
	}
}

// removeLeftoverContainers stops and removes every container of the stack key
// that is still there (see stopStack).
func removeLeftoverContainers(ctx context.Context, key string) error {
	containers, err := compose.StackContainers(ctx, key)
	if err != nil {
		return fmt.Errorf("inspect remaining containers: %w", err)
	}
	if len(containers) == 0 {
		return nil
	}
	ids := make([]string, 0, len(containers))
	names := make([]string, 0, len(containers))
	for _, c := range containers {
		ids = append(ids, c.ID)
		names = append(names, c.Name)
	}
	slog.Warn("stop: removing containers left outside docker compose", "stack", key, "containers", names)
	if out, err := compose.RemoveContainers(ctx, ids); err != nil {
		slog.Error("stop: docker rm failed", "stack", key, "error", err, "stderr", tail(out.Stderr, logExcerptBytes))
		return fmt.Errorf("remove remaining containers: %w", err)
	}
	return nil
}

// StopFunc returns a StopFunc suitable for the scheduler, using composeBase as
// the root directory for compose stacks. It takes the stack lock so an
// auto-stop never races a deploy of the same stack.
func StopFunc(composeBase string) func(ctx context.Context, namespace, environment string) error {
	stop := stopStack(composeBase)
	return func(ctx context.Context, namespace, environment string) error {
		unlock, err := stackLocks.lock(ctx, namespace+"-"+environment)
		if err != nil {
			return err
		}
		defer unlock()
		// The lock is held: no deploy can reschedule concurrently, so this is
		// the last point where a superseded auto-stop must be dropped.
		if !scheduler.StillDue(ctx) {
			return scheduler.ErrSuperseded
		}
		return stop(ctx, namespace, environment)
	}
}
