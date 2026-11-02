package handlers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"deploy-server/middleware"
	"deploy-server/registry"
	"deploy-server/scheduler"
)

// StopConfig holds the dependencies needed by the stop handler.
type StopConfig struct {
	ComposeBase string
	Registry    *registry.Registry
	Scheduler   *scheduler.Scheduler
}

// Stop handles DELETE /stack.
//
// The target stack is derived from the verified GitLab ID token (project_path +
// environment claims). It verifies ownership, stops the compose stack and any
// container of the stack docker compose down does not remove (see stopStack:
// e.g. a legacy stack without a compose file in COMPOSE_BASE), removes the
// compose directory, and cancels any pending auto-stop. A stack that no
// project has claimed (never deployed through this server, already stopped, or
// a legacy stack not yet imported into the registry) is rejected with 403.
func Stop(cfg StopConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, code, msg := stackFromClaims(r)
		if code != 0 {
			httpError(w, msg, code)
			return
		}
		owner := stackOwner(r, st)

		unlock, err := stackLocks.lock(r.Context(), st.Key)
		if err != nil {
			httpError(w, "request cancelled while waiting for another operation on this stack", http.StatusServiceUnavailable)
			return
		}
		defer unlock()

		// Verify ownership before doing anything destructive.
		if err := cfg.Registry.VerifyOwner(owner); err != nil {
			ownershipError(w, err)
			return
		}

		// Stop the stack.
		stopFn := stopStack(cfg.ComposeBase)
		if err := stopFn(r.Context(), st.Namespace, st.Environment); err != nil {
			slog.Error("stop: failed", "namespace", st.Namespace, "environment", st.Environment, "error", err)
			httpError(w, fmt.Sprintf("stop failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Remove the registry entry and cancel any pending auto-stop.
		if err := cfg.Registry.ReleaseOwner(owner); err != nil {
			slog.Error("stop: release registry entry", "namespace", st.Namespace, "environment", st.Environment, "error", err)
		}
		if err := cfg.Scheduler.Cancel(st.Namespace, st.Environment); err != nil {
			slog.Error("stop: cancel auto-stop", "namespace", st.Namespace, "environment", st.Environment, "error", err)
		}

		slog.Info("stop: stack stopped and removed", "namespace", st.Namespace, "environment", st.Environment)
		w.WriteHeader(http.StatusNoContent)
	}
}

// stackOwner builds the registry identity of the caller: the derived slugs and
// project_id from st, plus the exact (unslugged) project_path and environment
// claims so the registry can detect two deployments colliding on one key.
func stackOwner(r *http.Request, st stack) registry.Owner {
	o := registry.Owner{Namespace: st.Namespace, Environment: st.Environment, ProjectID: st.ProjectID}
	if claims, ok := middleware.ClaimsFromContext(r.Context()); ok {
		o.ProjectPath = claims.ProjectPath
		o.EnvironmentName = claims.Environment
	}
	return o
}

// ownershipError maps a registry ownership error to an HTTP response:
// not-claimed, collision and mismatch are 403s with distinct messages; any
// other error (e.g. a state write failure) is a 500.
func ownershipError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, registry.ErrNotClaimed):
		httpError(w, "this namespace/environment is not owned by any GitLab project: deploy it first (or import it into the ownership registry)", http.StatusForbidden)
	case errors.Is(err, registry.ErrKeyCollision):
		httpError(w, "this namespace/environment collides with a stack owned by a different GitLab project (distinct project_path/environment slugging to the same key)", http.StatusForbidden)
	case errors.Is(err, registry.ErrOwnerMismatch):
		httpError(w, "this namespace/environment is owned by a different GitLab project", http.StatusForbidden)
	default:
		slog.Error("ownership registry", "error", err)
		httpError(w, "ownership registry error", http.StatusInternalServerError)
	}
}
