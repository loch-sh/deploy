// Package handlers implements the HTTP endpoint handlers for the deploy server.
package handlers

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"deploy-server/compose"
	"deploy-server/internal/slug"
)

// slugRE matches safe namespace/environment/service identifiers.
// Must start and end with a lowercase letter or digit, may contain hyphens in
// between, and must be no longer than 63 characters total.
// Leading and trailing hyphens are not permitted. It is shared with the compose
// policy, which requires the <service> segment of every bind source to match
// it, so /directories can only create directories the policy accepts.
var slugRE = compose.SlugRE

// gitlabSlug reproduces GitLab's CI_PROJECT_PATH_SLUG algorithm so the on-disk
// stack directory derived from the verified `project_path` claim matches the
// directory GitLab pipelines reference elsewhere. It delegates to slug.GitLab,
// shared with config and middleware, so every component slugifies identically.
func gitlabSlug(s string) string { return slug.GitLab(s) }

// composeFileName is the name of the compose file inside every stack directory.
const composeFileName = "docker-compose.yml"

// envFileRE matches uploaded env file names: a plain file name (no path
// separators), optionally starting with a dot so ".env" is allowed.
var envFileRE = regexp.MustCompile(`^\.?[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// dirNameRE matches bind-mount directory names. The leading character cannot be
// a dot, which rules out "." and ".." as well as hidden directories. Shared with
// the compose policy (the <name> segment of every bind source).
var dirNameRE = compose.DirNameRE

// validateEnvFileName rejects env file names that are not plain file names or
// that would clobber the compose file or a temp file used by atomic writes.
func validateEnvFileName(name string) error {
	if !envFileRE.MatchString(name) {
		return fmt.Errorf("env file name %q is invalid: must match %s", name, envFileRE)
	}
	if name == composeFileName || strings.HasSuffix(name, ".tmp") {
		return fmt.Errorf("env file name %q is reserved", name)
	}
	return nil
}

// validateDirName returns an error if name is not a valid bind-mount directory name.
func validateDirName(name string) error {
	if !dirNameRE.MatchString(name) {
		return fmt.Errorf("entry name %q is invalid: must match %s", name, dirNameRE)
	}
	return nil
}

// parseAutoStopDays parses the optional auto_stop_days form value. An empty
// value yields 0 (no auto-stop).
func parseAutoStopDays(v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("auto_stop_days must be a positive integer")
	}
	return n, nil
}

// validateSlug returns an error if s is not a valid namespace or environment slug.
func validateSlug(field, s string) error {
	if !slugRE.MatchString(s) {
		return fmt.Errorf("%s %q is invalid: must match %s", field, s, slugRE)
	}
	return nil
}

// safeChild builds an absolute path by joining base and rel, then verifies that
// the result is actually inside base. This prevents path traversal attacks where
// rel contains ".." components.
func safeChild(base, rel string) (string, error) {
	joined := filepath.Join(base, rel)
	// filepath.Join cleans the path; verify the result is rooted under base.
	if !strings.HasPrefix(joined+string(filepath.Separator), filepath.Clean(base)+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes base directory %q", rel, base)
	}
	return joined, nil
}
