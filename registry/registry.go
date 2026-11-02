// Package registry tracks deployment ownership.
//
// Each (namespace, environment) pair is owned by the first GitLab project_id
// that claims it. Subsequent requests must come from the same project_id or
// they are rejected with a 403. This prevents accidental or malicious takeover
// of an existing stack when two projects derive the same key.
//
// The key is derived from slugs ("{namespace}-{environment}"), and slugging is
// lossy: "acme-shop/api" and "acme/shop-api" both become "acme-shop-api". Each
// entry therefore also records the exact, unslugged project_path and
// environment it was claimed with, so a different tuple landing on the same key
// is detected, reported as ErrKeyCollision and logged.
//
// # On-disk format
//
// The state lives in DATA_DIR/registry.json, a JSON object keyed by the derived
// stack key. Each value is either an Entry object (current format) or a bare
// project_id string (legacy format, still accepted on load):
//
//	{
//	  "acme-shop-staging": {
//	    "project_id": "42",
//	    "project_path": "acme/shop",
//	    "environment": "staging",
//	    "claimed_at": "2026-10-16T09:00:00Z"
//	  },
//	  "legacy-app-production": "17"
//	}
//
// The file may be edited by hand while the server is stopped (e.g. to adopt
// stacks deployed before the registry existed); see also Import / ImportFile.
package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrOwnerMismatch is returned when a project_id does not match the registered owner.
var ErrOwnerMismatch = errors.New("registry: project_id does not match registered owner")

// ErrKeyCollision is returned when the derived key is owned by a different
// project whose exact (project_path, environment) also differs from the
// caller's: two distinct deployments collapsed onto the same slug key.
// errors.Is(ErrKeyCollision, ErrOwnerMismatch) is true, so callers that only
// test for an ownership failure keep working.
var ErrKeyCollision = fmt.Errorf("%w: derived key is already used by a different project_path/environment", ErrOwnerMismatch)

// ErrNotClaimed is returned by Verify when no project owns the key yet. Such a
// stack (e.g. one deployed by the legacy SSH workflow) must be adopted through
// a deploy or an import before it can be operated on.
var ErrNotClaimed = errors.New("registry: namespace/environment is not claimed by any project")

// keyRE matches a valid derived key: two slugs joined by "-".
var keyRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,125}[a-z0-9])?$`)

// Entry is the ownership record stored for one derived key.
type Entry struct {
	// ProjectID is the GitLab project_id that owns the key. Required.
	ProjectID string `json:"project_id"`
	// ProjectPath is the exact project_path claim (before slugging). Optional
	// for legacy entries; filled in on the owner's next claim.
	ProjectPath string `json:"project_path,omitempty"`
	// Environment is the exact environment claim (before slugging). Optional.
	Environment string `json:"environment,omitempty"`
	// ClaimedAt is when the key was first claimed (or imported).
	ClaimedAt time.Time `json:"claimed_at,omitzero"`
}

// Owner identifies a caller acting on a stack.
type Owner struct {
	// Namespace and Environment are the slugs the key is derived from.
	Namespace   string
	Environment string
	// ProjectID is the verified project_id claim.
	ProjectID string
	// ProjectPath and EnvironmentName are the exact, unslugged claims. They
	// are optional; when empty, collision detection is skipped.
	ProjectPath     string
	EnvironmentName string
}

// Key returns the derived registry key for o.
func (o Owner) Key() string { return makeKey(o.Namespace, o.Environment) }

// Registry maps "{namespace}-{environment}" keys to the project that owns them.
type Registry struct {
	mu   sync.RWMutex
	path string
	data map[string]Entry
}

// Load reads (or creates) the registry JSON file at dataDir/registry.json.
func Load(dataDir string) (*Registry, error) {
	path := filepath.Join(dataDir, "registry.json")

	r := &Registry{
		path: path,
		data: make(map[string]Entry),
	}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return r, nil // first run — empty registry is fine
	}
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	data, err := ParseEntries(raw)
	if err != nil {
		return nil, fmt.Errorf("registry: corrupt %s: %w", path, err)
	}
	r.data = data
	return r, nil
}

// ParseEntries decodes a registry/import document. Values may be Entry objects
// or bare project_id strings (legacy format). Keys must be valid derived keys
// and every entry must carry a non-empty project_id.
func ParseEntries(raw []byte) (map[string]Entry, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]Entry, len(doc))
	for key, val := range doc {
		if !keyRE.MatchString(key) {
			return nil, fmt.Errorf("key %q is not a valid namespace-environment key", key)
		}
		var e Entry
		var legacy string
		if err := json.Unmarshal(val, &legacy); err == nil {
			e.ProjectID = legacy
		} else if err := json.Unmarshal(val, &e); err != nil {
			return nil, fmt.Errorf("key %q: %w", key, err)
		}
		if strings.TrimSpace(e.ProjectID) == "" {
			return nil, fmt.Errorf("key %q: missing project_id", key)
		}
		out[key] = e
	}
	return out, nil
}

// Claim attempts to register projectID as the owner of the (namespace, environment) pair.
// It is ClaimOwner without the exact project_path/environment (no collision detection).
func (r *Registry) Claim(namespace, environment, projectID string) error {
	return r.ClaimOwner(Owner{Namespace: namespace, Environment: environment, ProjectID: projectID})
}

// ClaimOwner attempts to register o as the owner of its derived key.
//
//   - If the key is unregistered, it is registered and the call succeeds.
//   - If the key is registered with the same project_id, the call succeeds and
//     missing project_path/environment metadata is filled in. A changed exact
//     tuple (project renamed, or two environments of one project slugging to
//     the same value) is logged as a warning and recorded.
//   - If the key is registered with a different project_id, ErrKeyCollision is
//     returned when both exact tuples are known and differ, ErrOwnerMismatch
//     otherwise.
//
// The change is persisted before returning; if the write fails, the in-memory
// state is rolled back and the write error is returned (it does not wrap
// ErrOwnerMismatch).
func (r *Registry) ClaimOwner(o Owner) error {
	key := o.Key()

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.data[key]
	if ok {
		if err := checkOwner(key, existing, o, "claim"); err != nil {
			return err
		}
	}

	next := existing
	if !ok {
		next = Entry{ProjectID: o.ProjectID, ClaimedAt: time.Now().UTC()}
	}
	if o.ProjectPath != "" {
		next.ProjectPath = o.ProjectPath
	}
	if o.EnvironmentName != "" {
		next.Environment = o.EnvironmentName
	}
	if ok && next == existing {
		return nil // nothing changed — no need to touch the disk
	}

	r.data[key] = next
	if err := r.flush(); err != nil {
		if ok {
			r.data[key] = existing
		} else {
			delete(r.data, key)
		}
		return err
	}
	return nil
}

// Release removes the ownership entry for the (namespace, environment) pair.
// It validates that the caller owns the entry first; returns ErrOwnerMismatch otherwise.
func (r *Registry) Release(namespace, environment, projectID string) error {
	return r.ReleaseOwner(Owner{Namespace: namespace, Environment: environment, ProjectID: projectID})
}

// ReleaseOwner removes the ownership entry for o's key after checking that o
// owns it (same rules as VerifyOwner). Releasing an absent key is a no-op. On
// a write failure the entry is restored in memory and the error returned.
func (r *Registry) ReleaseOwner(o Owner) error {
	key := o.Key()

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.data[key]
	if !ok {
		return nil // already gone — idempotent
	}
	if err := checkOwner(key, existing, o, "release"); err != nil {
		return err
	}

	delete(r.data, key)
	if err := r.flush(); err != nil {
		r.data[key] = existing
		return err
	}
	return nil
}

// Verify checks whether projectID is the current owner without modifying state.
// Returns ErrNotClaimed if no project owns the pair and ErrOwnerMismatch if
// another project does.
func (r *Registry) Verify(namespace, environment, projectID string) error {
	return r.VerifyOwner(Owner{Namespace: namespace, Environment: environment, ProjectID: projectID})
}

// VerifyOwner checks whether o owns its derived key without modifying state.
// It returns ErrNotClaimed for an unregistered key, ErrKeyCollision or
// ErrOwnerMismatch for a key owned by another project, and nil otherwise.
func (r *Registry) VerifyOwner(o Owner) error {
	key := o.Key()

	r.mu.RLock()
	defer r.mu.RUnlock()

	existing, ok := r.data[key]
	if !ok {
		return ErrNotClaimed
	}
	return checkOwner(key, existing, o, "verify")
}

// Lookup returns the entry registered for the (namespace, environment) pair.
func (r *Registry) Lookup(namespace, environment string) (Entry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.data[makeKey(namespace, environment)]
	return e, ok
}

// Import merges entries (keyed by derived key) into the registry, typically
// to adopt stacks deployed before ownership tracking existed. It is
// all-or-nothing:
//
//   - a key that is not registered yet is added;
//   - a key registered to the same project_id is kept, and missing
//     project_path/environment metadata is filled in from the import;
//   - a key registered to a different project_id aborts the whole import with
//     an error wrapping ErrOwnerMismatch, and nothing is changed.
//
// It returns the keys that were added or updated, sorted.
func (r *Registry) Import(entries map[string]Entry) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := make(map[string]Entry, len(r.data)+len(entries))
	for k, v := range r.data {
		next[k] = v
	}

	var changed, conflicts []string
	for key, in := range entries {
		if !keyRE.MatchString(key) {
			return nil, fmt.Errorf("registry: import: key %q is not a valid namespace-environment key", key)
		}
		if strings.TrimSpace(in.ProjectID) == "" {
			return nil, fmt.Errorf("registry: import: key %q: missing project_id", key)
		}
		cur, ok := next[key]
		switch {
		case !ok:
			if in.ClaimedAt.IsZero() {
				in.ClaimedAt = time.Now().UTC()
			}
			next[key] = in
			changed = append(changed, key)
		case cur.ProjectID != in.ProjectID:
			conflicts = append(conflicts, fmt.Sprintf("%s (owned by %s, import says %s)", key, cur.ProjectID, in.ProjectID))
		default:
			upd := cur
			if upd.ProjectPath == "" {
				upd.ProjectPath = in.ProjectPath
			}
			if upd.Environment == "" {
				upd.Environment = in.Environment
			}
			if upd != cur {
				next[key] = upd
				changed = append(changed, key)
			}
		}
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return nil, fmt.Errorf("registry: import: %w: %s", ErrOwnerMismatch, strings.Join(conflicts, ", "))
	}
	if len(changed) == 0 {
		return nil, nil
	}

	prev := r.data
	r.data = next
	if err := r.flush(); err != nil {
		r.data = prev
		return nil, err
	}
	sort.Strings(changed)
	return changed, nil
}

// ImportFile reads an import document (same format as registry.json) from
// path and merges it with Import.
func (r *Registry) ImportFile(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: import: %w", err)
	}
	entries, err := ParseEntries(raw)
	if err != nil {
		return nil, fmt.Errorf("registry: import %s: %w", path, err)
	}
	return r.Import(entries)
}

// checkOwner applies the ownership rule (key ↔ project_id) to an existing
// entry, and logs any mismatch between the exact tuples. op names the caller
// for the log.
func checkOwner(key string, existing Entry, o Owner, op string) error {
	tupleDiffers := tupleKnown(existing, o) &&
		(existing.ProjectPath != o.ProjectPath ||
			(existing.Environment != "" && o.EnvironmentName != "" && existing.Environment != o.EnvironmentName))

	if existing.ProjectID != o.ProjectID {
		if tupleDiffers {
			slog.Warn("registry: key collision between distinct deployments",
				"op", op, "key", key,
				"owner_project_id", existing.ProjectID, "owner_project_path", existing.ProjectPath, "owner_environment", existing.Environment,
				"caller_project_id", o.ProjectID, "caller_project_path", o.ProjectPath, "caller_environment", o.EnvironmentName)
			return ErrKeyCollision
		}
		return ErrOwnerMismatch
	}
	if tupleDiffers {
		// Same project, different exact tuple: a renamed/moved project, or two
		// environments of one project that slug to the same value.
		slog.Warn("registry: same owner reached key with a different project_path/environment",
			"op", op, "key", key, "project_id", o.ProjectID,
			"recorded_project_path", existing.ProjectPath, "recorded_environment", existing.Environment,
			"caller_project_path", o.ProjectPath, "caller_environment", o.EnvironmentName)
	}
	return nil
}

// tupleKnown reports whether both sides carry an exact project_path, which is
// the minimum needed to compare tuples.
func tupleKnown(e Entry, o Owner) bool {
	return e.ProjectPath != "" && o.ProjectPath != ""
}

// flush writes r.data to disk atomically. Caller must hold r.mu (write lock).
func (r *Registry) flush() error {
	raw, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return fmt.Errorf("registry: marshal: %w", err)
	}
	if err := writeFileAtomic(r.path, raw); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	return nil
}

// writeFileAtomic replaces path with data durably: it writes a temp file in
// the same directory, fsyncs it, renames it over path and fsyncs the
// directory so the rename itself survives a crash.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename to %s: %w", path, err)
	}
	committed = true

	// The new content is now visible; a failing directory fsync only weakens
	// crash durability, so it is logged rather than reported (reporting it
	// would make callers roll back state that is already on disk).
	if d, err := os.Open(dir); err != nil {
		slog.Warn("registry: open state dir for fsync", "dir", dir, "error", err)
	} else {
		if err := d.Sync(); err != nil {
			slog.Warn("registry: fsync state dir", "dir", dir, "error", err)
		}
		d.Close()
	}
	return nil
}

func makeKey(namespace, environment string) string {
	return namespace + "-" + environment
}
