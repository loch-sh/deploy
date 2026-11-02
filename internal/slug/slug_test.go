package slug

import (
	"strings"
	"testing"
)

func TestGitLab(t *testing.T) {
	cases := map[string]string{
		"production":                   "production",
		"Production":                   "production",
		"My-Group/My_App":              "my-group-my-app",
		"a//b":                         "a--b", // hyphens are not collapsed
		"--x--":                        "x",
		"é":                            "",
		"review/feature-1":             "review-feature-1",
		strings.Repeat("a", 70):        strings.Repeat("a", 63),
		strings.Repeat("a", 62) + "-b": strings.Repeat("a", 62),
		"":                             "",
	}
	for in, want := range cases {
		if got := GitLab(in); got != want {
			t.Errorf("GitLab(%q) = %q, want %q", in, got, want)
		}
	}
}
