package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"

	"deploy-server/compose"
	"deploy-server/middleware"
	"deploy-server/registry"
)

// ExecConfig holds the dependencies needed by the exec handler.
type ExecConfig struct {
	ComposeBase string
	Registry    *registry.Registry
}

// execRequest is the JSON body for POST /exec. The target stack is taken from
// the verified token; only the service and command are client-supplied.
type execRequest struct {
	Service string   `json:"service"`
	Command []string `json:"command"`
}

// execResponse is the JSON response body for POST /exec.
type execResponse struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// Exec handles POST /exec.
//
// It runs an arbitrary command inside a running compose service container and
// returns the captured stdout and stderr (each capped at
// compose.MaxOutputBytes). The command is passed as a []string to avoid any
// shell interpolation.
func Exec(cfg ExecConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, code, msg := stackFromClaims(r)
		if code != 0 {
			httpError(w, msg, code)
			return
		}

		var req execRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			httpError(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
			return
		}

		if err := validateSlug("service", req.Service); err != nil {
			httpError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.Command) == 0 {
			httpError(w, "command must not be empty", http.StatusBadRequest)
			return
		}
		middleware.AddAuditAttrs(r.Context(),
			slog.String("service", req.Service),
			slog.Any("command", req.Command),
		)

		if err := cfg.Registry.VerifyOwner(stackOwner(r, st)); err != nil {
			ownershipError(w, err)
			return
		}

		stackDir, err := safeChild(cfg.ComposeBase, st.Key)
		if err != nil {
			httpError(w, "invalid stack path", http.StatusBadRequest)
			return
		}
		cs := compose.Stack{Key: st.Key, Dir: stackDir, ComposeFile: filepath.Join(stackDir, composeFileName)}

		// Exec stays bound to the request context (and compose.ExecTimeout):
		// a cancelled pipeline interrupts its command.
		out, err := compose.Exec(r.Context(), cs, req.Service, req.Command)
		if err != nil {
			slog.Warn("exec: command failed", "namespace", st.Namespace, "environment", st.Environment, "service", req.Service,
				"error", err, "stderr", tail(out.Stderr, logExcerptBytes))
			// 504 when the command hit compose.ExecTimeout, 503 when the request
			// was cancelled; otherwise 422 so the caller knows the command ran
			// but exited non-zero. Captured stdout/stderr are returned either way.
			status := http.StatusUnprocessableEntity
			if c := contextStatus(err); c != 0 {
				status = c
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(execResponse{Stdout: out.Stdout, Stderr: out.Stderr})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(execResponse{Stdout: out.Stdout, Stderr: out.Stderr})
	}
}
