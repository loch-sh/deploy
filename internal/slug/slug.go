// Package slug reproduces GitLab's slugification so that every component of the
// server (handlers, middleware, configuration) normalises project paths and
// environment names identically.
package slug

import "strings"

// MaxLen is the maximum length of a slug, in bytes.
const MaxLen = 63

// GitLab reproduces GitLab's CI_PROJECT_PATH_SLUG algorithm:
//
//  1. Lowercase.
//  2. Replace every character that is not a-z or 0-9 with a single hyphen
//     (per rune, so a multi-byte character becomes one hyphen, matching Ruby).
//  3. Trim leading/trailing hyphens, truncate to 63 bytes, trim again.
//
// Consecutive hyphens are NOT collapsed — GitLab does not collapse them.
//
// For simple environment names (letters/digits, ≤24 chars, starting with a
// letter) the output also equals CI_ENVIRONMENT_SLUG.
//
// handlers/validate.go carries an identical copy (gitlabSlug); a test in
// handlers asserts that both stay in sync.
func GitLab(s string) string {
	s = strings.ToLower(s)

	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}

	out := strings.Trim(b.String(), "-")
	if len(out) > MaxLen {
		out = out[:MaxLen]
	}
	return strings.Trim(out, "-")
}
