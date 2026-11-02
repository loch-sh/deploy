// Package testutil provides test doubles shared across packages: a fake
// `docker` binary and a fake GitLab OIDC issuer.
package testutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDockerScript records each invocation's arguments (one line per call) and
// fails when FAKE_DOCKER_FAIL_ON names a word present in the arguments.
// `docker ps` and `docker inspect` print the fixture files named by
// FAKE_DOCKER_PS and FAKE_DOCKER_INSPECT (nothing when unset: no container);
// every other command prints "fake stdout" and "fake stderr".
const fakeDockerScript = `#!/bin/sh
echo "$*" >> "$FAKE_DOCKER_LOG"
if [ -n "$FAKE_DOCKER_FAIL_ON" ]; then
  for a in "$@"; do
    if [ "$a" = "$FAKE_DOCKER_FAIL_ON" ]; then
      echo "fake failure on $a" >&2
      exit 1
    fi
  done
fi
case "$1" in
  ps)      [ -n "$FAKE_DOCKER_PS" ] && cat "$FAKE_DOCKER_PS"; exit 0 ;;
  inspect) [ -n "$FAKE_DOCKER_INSPECT" ] && cat "$FAKE_DOCKER_INSPECT"; exit 0 ;;
esac
echo "fake stdout"
echo "fake stderr" >&2
`

// FakeDocker installs a fake `docker` executable first in PATH for the duration
// of the test. Its calls are observable through the returned *DockerLog.
func FakeDocker(t *testing.T) *DockerLog {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(fakeDockerScript), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	log := &DockerLog{path: filepath.Join(dir, "calls.log"), dir: dir}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_LOG", log.path)
	t.Setenv("FAKE_DOCKER_FAIL_ON", "")
	t.Setenv("FAKE_DOCKER_PS", "")
	t.Setenv("FAKE_DOCKER_INSPECT", "")
	return log
}

// Containers makes the fake docker report existing containers: every
// `docker ps` call (whatever its filters) prints ids, one per line, and
// `docker inspect` prints inspect verbatim (one JSON object per line, as
// produced by compose.StackContainers' --format).
func (l *DockerLog) Containers(t *testing.T, ids []string, inspect string) {
	t.Helper()
	ps := filepath.Join(l.dir, "ps.out")
	in := filepath.Join(l.dir, "inspect.out")
	if err := os.WriteFile(ps, []byte(strings.Join(ids, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write ps fixture: %v", err)
	}
	if err := os.WriteFile(in, []byte(inspect), 0o600); err != nil {
		t.Fatalf("write inspect fixture: %v", err)
	}
	t.Setenv("FAKE_DOCKER_PS", ps)
	t.Setenv("FAKE_DOCKER_INSPECT", in)
}

// FailOn makes the fake docker exit non-zero whenever word is one of its arguments
// (e.g. "pull", "up", "down", "exec", "ps", "inspect", "rm").
func (l *DockerLog) FailOn(t *testing.T, word string) {
	t.Helper()
	t.Setenv("FAKE_DOCKER_FAIL_ON", word)
}

// DockerLog gives access to the arguments the fake docker was called with.
type DockerLog struct {
	path string
	dir  string
}

// Calls returns one entry per docker invocation, each being the space-joined
// argument list.
func (l *DockerLog) Calls() []string {
	raw, err := os.ReadFile(l.path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}
