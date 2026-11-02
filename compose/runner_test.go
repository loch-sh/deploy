package compose

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"deploy-server/internal/testutil"
)

var testStack = Stack{
	Key:         "app-staging",
	Dir:         "/data/compose/app-staging",
	ComposeFile: "/data/compose/app-staging/docker-compose.yml",
}

const pinned = "compose -p app-staging --project-directory /data/compose/app-staging -f /data/compose/app-staging/docker-compose.yml "

func TestCommandsBuildExpectedArgs(t *testing.T) {
	docker := testutil.FakeDocker(t)
	ctx := context.Background()

	steps := []struct {
		name string
		run  func() (*Output, error)
		want string
	}{
		{"pull", func() (*Output, error) { return Pull(ctx, testStack) }, pinned + "pull"},
		{"up", func() (*Output, error) { return Up(ctx, testStack) }, pinned + "up -d --remove-orphans --no-build"},
		{"down", func() (*Output, error) { return Down(ctx, testStack) }, pinned + "down --remove-orphans"},
		{"config", func() (*Output, error) { return Config(ctx, testStack) }, pinned + "config --format json --no-env-resolution"},
		{"exec", func() (*Output, error) {
			return Exec(ctx, testStack, "api", []string{"php", "bin/console", "a b; rm -rf /"})
		}, pinned + "exec -T api php bin/console a b; rm -rf /"},
	}

	for i, s := range steps {
		out, err := s.run()
		if err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		if strings.TrimSpace(out.Stdout) != "fake stdout" || strings.TrimSpace(out.Stderr) != "fake stderr" {
			t.Errorf("%s: output = %+v", s.name, out)
		}
		if calls := docker.Calls(); len(calls) != i+1 || calls[i] != s.want {
			t.Errorf("%s: calls = %q, want last %q", s.name, calls, s.want)
		}
	}
}

func TestRunFailureKeepsOutput(t *testing.T) {
	docker := testutil.FakeDocker(t)
	docker.FailOn(t, "pull")

	out, err := Pull(context.Background(), testStack)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "docker compose pull") {
		t.Errorf("error = %v", err)
	}
	if strings.Contains(err.Error(), "fake failure") {
		t.Errorf("error must not embed stderr: %v", err)
	}
	if !strings.Contains(StderrOf(out), "fake failure on pull") {
		t.Errorf("stderr not captured: %+v", out)
	}
}

func TestExecRejectsEmptyCommand(t *testing.T) {
	docker := testutil.FakeDocker(t)

	out, err := Exec(context.Background(), testStack, "api", nil)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
	if out == nil {
		t.Error("output must never be nil")
	}
	if docker.Calls() != nil {
		t.Error("docker must not be invoked")
	}
}

// scriptDocker installs a `docker` executable running script first in PATH.
func scriptDocker(t *testing.T, script string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestRunTimeout(t *testing.T) {
	scriptDocker(t, "exec sleep 10")

	start := time.Now()
	_, err := run(context.Background(), context.Background(), 100*time.Millisecond, testStack, "pull")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("timed-out command was not interrupted promptly")
	}
}

func TestUpIsDetachedFromCancellation(t *testing.T) {
	scriptDocker(t, "sleep 0.3; echo done")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	out, err := Up(ctx, testStack)
	if err != nil {
		t.Fatalf("up must survive request cancellation once started: %v", err)
	}
	if strings.TrimSpace(out.Stdout) != "done" {
		t.Errorf("stdout = %q", out.Stdout)
	}
}

func TestPullIsCancelledWithRequest(t *testing.T) {
	scriptDocker(t, "exec sleep 10")

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	if _, err := Pull(ctx, testStack); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	docker := testutil.FakeDocker(t)

	// Occupy every slot.
	for range MaxConcurrent {
		slots <- struct{}{}
	}
	t.Cleanup(func() {
		for range MaxConcurrent {
			<-slots
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Up(ctx, testStack); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want to give up waiting for a slot", err)
	}

	cancelled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := Down(cancelled, testStack); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}

	if docker.Calls() != nil {
		t.Errorf("docker must not run without a slot: %q", docker.Calls())
	}
}

func TestOutputIsCapped(t *testing.T) {
	scriptDocker(t, `head -c 3000000 /dev/zero | tr '\0' 'a'; head -c 10 /dev/zero >&2`)

	out, err := Pull(context.Background(), testStack)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Stdout) != MaxOutputBytes+len(truncatedMarker) || !strings.HasSuffix(out.Stdout, truncatedMarker) {
		t.Errorf("stdout length = %d, want capped with marker", len(out.Stdout))
	}
	if len(out.Stderr) != 10 {
		t.Errorf("stderr length = %d, want 10 (not truncated)", len(out.Stderr))
	}
}

func TestCappedBuffer(t *testing.T) {
	c := &cappedBuffer{max: 5}
	for _, p := range []string{"abc", "def", "ghi"} {
		if n, err := c.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", p, n, err)
		}
	}
	if got := c.String(); got != "abcde"+truncatedMarker {
		t.Errorf("String() = %q", got)
	}

	exact := &cappedBuffer{max: 3}
	_, _ = exact.Write([]byte("abc"))
	if got := exact.String(); got != "abc" {
		t.Errorf("String() = %q, want no marker at exactly max", got)
	}
}
