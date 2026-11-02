package handlers

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"deploy-server/middleware"
	"deploy-server/registry"
)

// DirsConfig holds the dependencies needed by the directories handler.
type DirsConfig struct {
	WebsitesBase string
	Registry     *registry.Registry
}

// dirEntry describes one directory to create under the websites base.
type dirEntry struct {
	// Service is the first layout segment (e.g. "api"), conventionally the
	// compose service that uses the directory; it is not checked against the
	// compose file.
	Service string `json:"service"`
	// Name is the bind-mount subdirectory name (e.g. "storage").
	Name string `json:"name"`
	// User is the numeric uid to assign ownership to (optional).
	User string `json:"user"`
	// Group is the numeric gid to assign ownership to (optional).
	Group string `json:"group"`
	// Mode is an optional octal permission string (e.g. "0750"), at most 0777.
	Mode string `json:"mode"`
}

// dirsRequest is the JSON body for POST /directories. The target stack is taken
// from the verified token; only the directory entries are client-supplied.
type dirsRequest struct {
	Entries []dirEntry `json:"entries"`
}

// dirPlan is a fully validated dirEntry, ready to be applied.
type dirPlan struct {
	service string
	rel     string // "{service}/{name}", relative to the stack directory
	mode    fs.FileMode
	setMode bool
	uid     int // -1 = unchanged
	gid     int // -1 = unchanged
}

// errSymlink reports a path component that is a symbolic link.
var errSymlink = errors.New("is a symbolic link")

// Directories handles POST /directories.
//
// It creates bind-mount directories under WebsitesBase/{namespace}-{environment}/{service}/{name}/
// and optionally applies custom ownership (uid/gid) and permissions (chmod).
//
// Those directories are bind-mounted into tenant containers, so their content
// is attacker-controlled: a container can plant a symlink (e.g. "api ->
// /data/compose") and wait for the server to chmod/chown through it. All
// filesystem access therefore goes through an os.Root opened on the stack
// directory, which refuses any path resolving outside of it, and every
// directory operated on must be a real directory, not a symlink. All entries
// are validated before the first write.
func Directories(cfg DirsConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, code, msg := stackFromClaims(r)
		if code != 0 {
			httpError(w, msg, code)
			return
		}

		var req dirsRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			httpError(w, fmt.Sprintf("invalid JSON body: %v", err), http.StatusBadRequest)
			return
		}

		dirs := make([]string, 0, len(req.Entries))
		for _, entry := range req.Entries {
			dirs = append(dirs, entry.Service+"/"+entry.Name)
		}
		middleware.AddAuditAttrs(r.Context(), slog.Any("directories", dirs))

		// An unclaimed stack is accepted: CI creates bind-mount directories
		// before the first /deploy, so the containers start with the right
		// permissions. What is created stays confined to WebsitesBase/<key>/;
		// pre-creating directories under a key that another project later
		// deploys to is the same first-come risk as /deploy's claim (see
		// SECURITY.md A1), and that project's first deploy still claims the key.
		if err := cfg.Registry.VerifyOwner(stackOwner(r, st)); err != nil && !errors.Is(err, registry.ErrNotClaimed) {
			ownershipError(w, err)
			return
		}

		// Pass 1: validate everything, so a bad entry never leaves a
		// half-applied request behind.
		plans := make([]dirPlan, 0, len(req.Entries))
		for _, entry := range req.Entries {
			p, err := planDir(entry)
			if err != nil {
				httpError(w, err.Error(), http.StatusBadRequest)
				return
			}
			plans = append(plans, p)
		}
		if len(plans) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Pass 2: apply, confined to the stack directory.
		stackRoot, err := openStackRoot(cfg.WebsitesBase, st.Key)
		if err != nil {
			slog.Error("directories: open stack directory", "base", cfg.WebsitesBase, "stack", st.Key, "error", err)
			httpError(w, fmt.Sprintf("failed to open stack directory: %v", err), statusForFSError(err))
			return
		}
		defer func() { _ = stackRoot.Close() }()

		for _, p := range plans {
			if err := applyDir(stackRoot, p); err != nil {
				slog.Error("directories: apply", "stack", st.Key, "dir", p.rel, "error", err)
				httpError(w, fmt.Sprintf("directory %s: %v", p.rel, err), statusForFSError(err))
				return
			}
			slog.Info("directories: created", "stack", st.Key, "dir", p.rel)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// planDir validates one entry and converts it into a dirPlan.
func planDir(entry dirEntry) (dirPlan, error) {
	if err := validateSlug("service", entry.Service); err != nil {
		return dirPlan{}, err
	}
	if err := validateDirName(entry.Name); err != nil {
		return dirPlan{}, err
	}
	p := dirPlan{service: entry.Service, rel: path.Join(entry.Service, entry.Name), uid: -1, gid: -1}

	if entry.Mode != "" {
		mode, err := parseOctal(entry.Mode)
		if err != nil {
			return dirPlan{}, fmt.Errorf("entry mode %q is invalid: %v", entry.Mode, err)
		}
		p.mode, p.setMode = mode, true
	}

	var err error
	if p.uid, err = parseID("user", entry.User); err != nil {
		return dirPlan{}, err
	}
	if p.gid, err = parseID("group", entry.Group); err != nil {
		return dirPlan{}, err
	}
	return p, nil
}

// openStackRoot creates WebsitesBase/key if needed and returns an os.Root
// confined to it. The stack directory itself must be a real directory: a
// symlink there (even one pointing inside the websites base) is refused, so
// one stack can never be redirected onto another.
func openStackRoot(websitesBase, key string) (*os.Root, error) {
	if err := os.MkdirAll(websitesBase, 0o755); err != nil {
		return nil, err
	}
	base, err := os.OpenRoot(websitesBase)
	if err != nil {
		return nil, err
	}
	defer func() { _ = base.Close() }()

	if err := base.Mkdir(key, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if err := requireRealDir(base, key); err != nil {
		return nil, err
	}
	return base.OpenRoot(key)
}

// applyDir creates p.rel inside root and applies its mode and ownership. Each
// component is created and checked one by one, so a symlink planted by a
// container (in the service directory or as the target itself) is refused
// rather than followed.
//
// Mode and ownership are applied to the {name} leaf only. The stack and
// service directories are created by the server (root:root 0755) and never
// chmod'ed or chown'ed: the compose policy only accepts bind sources at the
// {service}/{name} depth, so those intermediate levels are mounted by no
// container and must stay out of reach of the stack's uids (SECURITY.md A2).
func applyDir(root *os.Root, p dirPlan) error {
	for _, rel := range []string{p.service, p.rel} {
		if err := root.Mkdir(rel, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := requireRealDir(root, rel); err != nil {
			return err
		}
	}

	// os.Root guarantees the operations stay inside the stack directory even
	// if a component is swapped for a symlink after the check above (on Unix,
	// Root.Chmod may then act on the link itself, never on a path outside).
	if p.setMode {
		if err := root.Chmod(p.rel, p.mode); err != nil {
			return fmt.Errorf("chmod: %w", err)
		}
	}
	if p.uid != -1 || p.gid != -1 {
		if err := root.Lchown(p.rel, p.uid, p.gid); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	return nil
}

// requireRealDir returns an error unless rel (inside root) is a directory and
// not a symbolic link.
func requireRealDir(root *os.Root, rel string) error {
	info, err := root.Lstat(rel)
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s %w", rel, errSymlink)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory: %w", rel, fs.ErrExist)
	}
	return nil
}

// statusForFSError maps filesystem errors caused by the stack's own content
// (planted symlinks, escaping paths, files in the way) to 409 Conflict and
// everything else to 500.
func statusForFSError(err error) int {
	var pathErr *fs.PathError
	switch {
	case errors.Is(err, errSymlink), errors.Is(err, fs.ErrExist):
		return http.StatusConflict
	case errors.As(err, &pathErr) && strings.Contains(pathErr.Err.Error(), "escapes from parent"):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// parseOctal converts an octal string such as "0750" to a permission mode.
// Only the permission bits (at most 0777) are accepted: setuid, setgid and
// sticky bits are refused.
func parseOctal(s string) (fs.FileMode, error) {
	// Strip optional leading "0o" prefix for robustness.
	s = strings.TrimPrefix(s, "0o")
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("not a valid octal value: %w", err)
	}
	if n > 0o777 {
		return 0, fmt.Errorf("only permission bits (0000-0777) are allowed; setuid/setgid/sticky are refused")
	}
	return fs.FileMode(n), nil
}

// parseID parses an optional numeric uid/gid. Empty means "unchanged" (-1).
//
// Only numeric ids in 0..2^31-1 are accepted. Names are deliberately not
// resolved: a lookup would use the /etc/passwd and /etc/group of the
// deploy-server container, not those of the image that will use the
// directory, so "www-data" could silently map to a different (or privileged)
// id than the one the target container expects.
func parseID(kind, s string) (int, error) {
	if s == "" {
		return -1, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n > math.MaxInt32 {
		return 0, fmt.Errorf("%s %q is invalid: must be a numeric id between 0 and %d (names are not resolved)", kind, s, math.MaxInt32)
	}
	return int(n), nil
}
