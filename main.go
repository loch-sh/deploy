// deploy-server is a lightweight HTTP deployment server that replaces the SSH
// copy/mkdir workflow used by GitLab CI / GitHub Actions.
//
// Instead of granting CI runners broad SSH access with sudo privileges, each
// pipeline issues authenticated HTTP requests to this server. The server
// manages Docker Compose stacks, bind-mount directories, and optional auto-stop
// timers in a controlled, auditable way.
//
// # Authentication
//
// There is no shared secret. Each CI job requests a short-lived GitLab OIDC ID
// token (the `id_tokens` block in .gitlab-ci.yml) and sends it as
// `Authorization: Bearer`. The server verifies it against the GitLab instance's
// JWKS (GITLAB_ISSUER / GITLAB_AUDIENCE) and derives the target stack from the
// token's project_path and environment claims.
//
// # Running
//
//	./deploy-server
//
// # Importing legacy stacks
//
//	./deploy-server -import-registry legacy.json
//
// merges legacy.json (same format as DATA_DIR/registry.json) into the
// ownership registry, then exits (0 on success, 1 on failure). Only DATA_DIR
// is read from the environment. Run it while the server is stopped: a running
// server keeps the registry in memory and would overwrite the import on its
// next write.
//
// Environment variables — see config/config.go for the full list.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"deploy-server/config"
	"deploy-server/handlers"
	"deploy-server/middleware"
	"deploy-server/registry"
	"deploy-server/scheduler"
)

// HTTP server limits.
const (
	// readHeaderTimeout bounds how long a client may take to send the request
	// headers (slowloris protection).
	readHeaderTimeout = 10 * time.Second
	// readTimeout bounds reading the whole request, body included: a
	// MAX_UPLOAD_MB upload from a slow CI runner must fit in it.
	readTimeout = 5 * time.Minute
	// writeTimeout bounds the whole request handling, since net/http starts
	// it when the headers have been read. It must stay above the longest
	// operation a handler runs (a deploy's container inspection, compose
	// config, pull and up, bounded to 15.5 minutes), otherwise the response
	// of a successful deploy is lost.
	writeTimeout = 16 * time.Minute
	idleTimeout  = 60 * time.Second
	// maxHeaderBytes caps request headers; an ID token is a few KiB.
	maxHeaderBytes = 64 << 10
)

func main() {
	os.Exit(runMain(os.Args[1:], os.Stderr))
}

// runMain installs the JSON logger on logOut and parses args. With
// -import-registry it imports the given file into the ownership registry and
// returns; otherwise it loads the configuration and runs the server until
// SIGINT/SIGTERM. It returns the process exit code.
func runMain(args []string, logOut io.Writer) int {
	slog.SetDefault(newLogger(logOut))

	fs := flag.NewFlagSet("deploy-server", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors are logged as JSON below
	importFile := fs.String("import-registry", "", "merge this JSON file (registry.json format) into DATA_DIR's ownership registry, then exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stderr)
			fs.PrintDefaults()
			return 0
		}
		slog.Error("invalid arguments", "error", err)
		return 2
	}
	if fs.NArg() > 0 {
		slog.Error("invalid arguments", "error", fmt.Sprintf("unexpected argument %q", fs.Arg(0)))
		return 2
	}
	if *importFile != "" {
		return importRegistry(config.DataDirFromEnv(), *importFile)
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		slog.Error("server failed", "error", err)
		return 1
	}
	return 0
}

// importRegistry merges path into the ownership registry stored in dataDir and
// returns the process exit code. The import is all-or-nothing (see
// registry.Import).
func importRegistry(dataDir, path string) int {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		slog.Error("registry import failed", "error", fmt.Errorf("mkdir data dir %s: %w", dataDir, err))
		return 1
	}
	reg, err := registry.Load(dataDir)
	if err != nil {
		slog.Error("registry import failed", "error", err)
		return 1
	}
	changed, err := reg.ImportFile(path)
	if err != nil {
		slog.Error("registry import failed", "file", path, "error", err)
		return 1
	}
	slog.Info("registry import done", "file", path, "changed", len(changed), "keys", changed)
	return 0
}

// run starts the server and blocks until ctx is cancelled (graceful shutdown)
// or the listener fails.
func run(ctx context.Context, cfg *config.Config) error {
	// Ensure the data directory exists.
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data dir %s: %w", cfg.DataDir, err)
	}

	// -- OIDC verifier setup --------------------------------------------------
	// Performs OIDC discovery against the GitLab instance; fails fast if it is
	// unreachable or misconfigured.
	verifier, err := middleware.NewVerifier(ctx, cfg.GitLabIssuer, cfg.GitLabAudience)
	if err != nil {
		return fmt.Errorf("oidc: %w", err)
	}

	// -- Registry setup -------------------------------------------------------
	reg, err := registry.Load(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}

	// -- Scheduler setup ------------------------------------------------------
	sched, err := scheduler.Load(cfg.DataDir, handlers.StopFunc(cfg.ComposeBase))
	if err != nil {
		return fmt.Errorf("scheduler: %w", err)
	}
	sched.Start(ctx)
	defer sched.Stop()

	if len(cfg.AllowedIPs) == 0 {
		slog.Warn("ALLOWED_IPS is empty — IP allowlist is DISABLED")
	} else {
		slog.Info("IP allowlist active", "networks", len(cfg.AllowedIPs))
	}

	if len(cfg.AllowedNamespaces) == 0 {
		slog.Warn("ALLOWED_NAMESPACES is empty — every project of the GitLab instance may call this server")
	} else {
		slog.Info("namespace allowlist active", "namespaces", cfg.AllowedNamespaces)
	}

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: newMux(cfg, verifier.OIDCAuth, slog.Default(), reg, sched),
		// Route net/http's internal errors (TLS handshakes, panics…) to slog.
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	// -- Start server ---------------------------------------------------------
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	slog.Info("deploy-server listening", "addr", ln.Addr().String())

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	// -- Graceful shutdown ----------------------------------------------------
	select {
	case err := <-serveErr:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown", "error", err)
	}
	slog.Info("stopped")
	return nil
}

// newLogger returns the server logger: one JSON object per line. Audit entries
// share it and are told apart by "msg":"audit".
func newLogger(w io.Writer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, nil))
}

// newMux wires the HTTP routes. auth is the token verification middleware
// (GitLab OIDC in production), applied inside the IP allowlist; it must store
// the verified claims with middleware.ContextWithClaims. Every protected
// request is written to auditLog.
func newMux(cfg *config.Config, auth func(http.Handler) http.Handler, auditLog *slog.Logger, reg *registry.Registry, sched *scheduler.Scheduler) *http.ServeMux {
	mux := http.NewServeMux()

	// Health is unauthenticated and exempt from the IP allowlist.
	mux.Handle("GET /health", handlers.Health())

	// protected wraps a handler with, from outer to inner: the audit log (so
	// rejected requests are recorded too), the IP allowlist (cheap early
	// rejection), token verification, then the claim-based authorisation
	// rules — the namespace allowlist and the protected-environment rule —
	// which therefore apply uniformly to every protected endpoint.
	audit := middleware.Audit(auditLog, cfg.TrustedProxies)
	ipAllow := middleware.IPAllowlist(cfg.AllowedIPs, cfg.TrustedProxies)
	nsAllow := middleware.RequireNamespace(cfg.AllowedNamespaces)
	protectedRef := middleware.RequireProtectedRef(cfg.ProtectedEnvironments)
	protected := func(h http.Handler) http.Handler {
		return audit(ipAllow(auth(nsAllow(protectedRef(h)))))
	}

	mux.Handle("POST /deploy", protected(handlers.Deploy(handlers.DeployConfig{
		ComposeBase:             cfg.ComposeBase,
		WebsitesBase:            cfg.WebsitesBase,
		MaxUploadMB:             cfg.MaxUploadMB,
		Registry:                reg,
		Scheduler:               sched,
		ProtectedEnvs:           cfg.ProtectedEnvironments,
		ForbiddenTraefikHosts:   cfg.ForbiddenTraefikHosts,
		AllowedExternalNetworks: cfg.AllowedExternalNetworks,
	})))

	mux.Handle("DELETE /stack", protected(handlers.Stop(handlers.StopConfig{
		ComposeBase: cfg.ComposeBase,
		Registry:    reg,
		Scheduler:   sched,
	})))

	mux.Handle("POST /directories", protected(handlers.Directories(handlers.DirsConfig{
		WebsitesBase: cfg.WebsitesBase,
		Registry:     reg,
	})))

	mux.Handle("POST /exec", protected(handlers.Exec(handlers.ExecConfig{
		ComposeBase: cfg.ComposeBase,
		Registry:    reg,
	})))

	return mux
}
