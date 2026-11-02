package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"deploy-server/compose"
	"deploy-server/middleware"
)

// maxReportedLegacyMounts caps how many refused mounts the 409 message lists.
const maxReportedLegacyMounts = 20

// legacyMount is a bind mount of an existing container of the stack that the
// deployment policy would refuse today. It is logged in the audit entry
// (legacy_mounts) with the full source path, which is never sent to clients.
type legacyMount struct {
	Container string `json:"container"`
	Target    string `json:"target"`
	Source    string `json:"source"`
	RW        bool   `json:"rw"`
	reason    string // client-safe description of the source and the violation
}

// checkExistingMounts inspects the existing containers of the stack (every
// state, see compose.StackContainers) before a deploy touches anything, and
// refuses the deploy with 409 when one of them has a bind mount that does not
// follow the WEBSITES_BASE/<key>/<service>/<name> layout.
//
// Why: such a container was started by an older deployment (the SSH workflow
// or a version of this server before the layout rule) and may have write
// access to <key>/ or <key>/<service>/. It keeps running during this deploy's
// pull, and could swap a component of a bind source the policy has just
// validated for a symlink before up creates the new containers (SECURITY.md,
// A2). A bind outside WEBSITES_BASE/<key>/ (the Docker socket, a host path) is
// refused too: it is precisely a legacy container with host access. Named
// volumes, tmpfs and image mounts are not concerned.
//
// A failure of the inspection itself is a 500, or a 504/503 when it timed out
// or the request was cancelled: the deploy never proceeds unchecked.
//
// It returns an HTTP status code and message on failure.
func checkExistingMounts(ctx context.Context, st stack, websitesDir string) (int, string) {
	containers, err := compose.StackContainers(ctx, st.Key)
	if err != nil {
		slog.Error("deploy: inspect existing containers", "namespace", st.Namespace, "environment", st.Environment, "error", err)
		if code := contextStatus(err); code != 0 {
			return code, "inspecting the stack's existing containers: " + strings.ToLower(http.StatusText(code))
		}
		return http.StatusInternalServerError, "failed to inspect the stack's existing containers"
	}

	var found []legacyMount
	for _, c := range containers {
		for _, m := range c.Mounts {
			if m.Type != "bind" {
				continue
			}
			if err := compose.CheckBindSourcePath(m.Source, websitesDir); err != nil {
				found = append(found, legacyMount{
					Container: c.Name, Target: m.Destination, Source: m.Source, RW: m.RW,
					reason: describeLegacySource(m.Source, websitesDir, st.Key, err),
				})
			}
		}
	}
	if len(found) == 0 {
		return 0, ""
	}

	middleware.AddAuditAttrs(ctx, slog.Any("legacy_mounts", found))
	slog.Warn("deploy: refused, existing containers have legacy bind mounts",
		"namespace", st.Namespace, "environment", st.Environment, "legacy_mounts", found)

	var b strings.Builder
	fmt.Fprintf(&b, "existing containers of this stack, started by an older deployment, have bind mounts the deployment policy no longer allows"+
		" (sources must be exactly WEBSITES_BASE/%s/<service>/<name>); while they exist they could tamper with this deploy's bind sources: ", st.Key)
	for i, lm := range found {
		if i == maxReportedLegacyMounts {
			fmt.Fprintf(&b, "; … and %d more", len(found)-i)
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "container %q, target %q: %s", lm.Container, lm.Target, lm.reason)
	}
	b.WriteString(". Remove them with DELETE /stack (move their data to the <service>/<name> layout), then deploy again")
	return http.StatusConflict, b.String()
}

// describeLegacySource describes a refused bind source for the client: only
// its part relative to WEBSITES_BASE/<key>/, prefixed with the key, or
// "outside the stack data directory"; never a server path.
func describeLegacySource(src, websitesDir, key string, err error) string {
	root := filepath.Clean(websitesDir)
	r, inside := strings.CutPrefix(src, root+string(filepath.Separator))
	if errors.Is(err, compose.ErrBindOutside) || (!inside && src != root) {
		return "source outside the stack data directory"
	}
	rel := key + "/"
	if inside { // CutPrefix returns src unchanged otherwise
		rel += r
	}
	if errors.Is(err, compose.ErrBindLayout) {
		return fmt.Sprintf("source %q is not at the <service>/<name> depth", rel)
	}
	return fmt.Sprintf("source %q: %v", rel, err)
}
