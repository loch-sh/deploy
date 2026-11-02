// Package compose wraps the docker compose CLI (and the few plain docker
// commands used to inspect a stack's containers) as a subprocess.
//
// All commands are built with explicit argument slices — no shell interpolation —
// which prevents command injection from user-supplied values.
//
// Every command is pinned to its stack with -p (project name) and
// --project-directory, so neither a `name:` in the compose file nor a
// COMPOSE_PROJECT_NAME in an uploaded .env can make a stack act on another
// project's containers, networks or volumes (-p takes precedence over both).
package compose

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Per-operation timeouts. A docker call that exceeds its timeout is
// interrupted (SIGINT), then killed after waitDelay. A deploy runs the
// container inspection + config + pull + up, i.e. at most 15.5 minutes of
// docker time, which the HTTP server's WriteTimeout (main.go) must exceed.
const (
	PullTimeout   = 7 * time.Minute
	UpTimeout     = 7 * time.Minute
	DownTimeout   = 10 * time.Minute
	ExecTimeout   = 5 * time.Minute
	ConfigTimeout = 1 * time.Minute
	// InspectTimeout bounds StackContainers as a whole (two docker ps and
	// one docker inspect).
	InspectTimeout = 30 * time.Second
	// RemoveTimeout bounds RemoveContainers as a whole (docker stop with a
	// 10 second grace period, then docker rm -f).
	RemoveTimeout = 2 * time.Minute
)

// MaxOutputBytes caps the captured stdout and stderr of each command. Output
// beyond the cap is discarded and the captured text ends with truncatedMarker.
const MaxOutputBytes = 1 << 20 // 1 MiB

// MaxConcurrent is the maximum number of docker processes (docker compose,
// docker ps, inspect, stop, rm) running at once, server-wide. Further calls
// wait for a free slot (or for their context).
const MaxConcurrent = 4

// waitDelay bounds how long a cancelled command may keep running (and keep its
// output pipes open) after it has been interrupted.
const waitDelay = 10 * time.Second

// truncatedMarker is appended to captured output that hit MaxOutputBytes.
const truncatedMarker = "\n[truncated]"

// slots is the global semaphore limiting concurrent docker processes.
var slots = make(chan struct{}, MaxConcurrent)

// Stack identifies the compose project a command acts on.
type Stack struct {
	Key         string // compose project name: "{namespace}-{environment}"
	Dir         string // project directory: relative paths and .env resolve here
	ComposeFile string // compose file passed with -f
}

// Output holds captured stdout and stderr from a compose command.
//
// Every function of this package that returns an *Output returns a non-nil
// one, even alongside an error (it is then empty or holds whatever the
// command printed before failing). Callers may still use StderrOf to read it
// nil-safely.
type Output struct {
	Stdout string
	Stderr string
}

// StderrOf returns o.Stderr, or "" when o is nil.
func StderrOf(o *Output) string {
	if o == nil {
		return ""
	}
	return o.Stderr
}

// Pull runs: docker compose -p <key> --project-directory <dir> -f <file> pull
//
// Pull is bound to ctx: aborting a pull leaves the running stack untouched.
func Pull(ctx context.Context, s Stack) (*Output, error) {
	return run(ctx, ctx, PullTimeout, s, "pull")
}

// Up runs: docker compose ... up -d --remove-orphans --no-build
//
// ctx only bounds the wait for a free slot: once started, up is detached from
// ctx (it still has UpTimeout) so a cancelled pipeline cannot leave a
// half-applied deployment behind.
func Up(ctx context.Context, s Stack) (*Output, error) {
	return run(ctx, context.WithoutCancel(ctx), UpTimeout, s, "up", "-d", "--remove-orphans", "--no-build")
}

// Down runs: docker compose ... down --remove-orphans
//
// --remove-orphans also removes the project's containers whose service is no
// longer in the compose file (e.g. left by an older deployment). Like Up, a
// started down is detached from ctx and bounded by DownTimeout.
func Down(ctx context.Context, s Stack) (*Output, error) {
	return run(ctx, context.WithoutCancel(ctx), DownTimeout, s, "down", "--remove-orphans")
}

// Config renders the fully resolved compose model as JSON:
//
//	docker compose ... config --format json --no-env-resolution
//
// The output is the canonical model docker compose will actually run (after
// interpolation, merges and path resolution), which is what the deployment
// policy must be checked against. --no-env-resolution keeps env_file entries
// (instead of inlining their content) so their paths can be checked too.
func Config(ctx context.Context, s Stack) (*Output, error) {
	return run(ctx, ctx, ConfigTimeout, s, "config", "--format", "json", "--no-env-resolution")
}

// Exec runs a command inside a running service container:
//
//	docker compose ... exec -T <service> <command...>
//
// The -T flag disables pseudo-TTY allocation, which is required for
// non-interactive use (equivalent to SSH with no tty).
func Exec(ctx context.Context, s Stack, service string, command []string) (*Output, error) {
	if len(command) == 0 {
		return &Output{}, fmt.Errorf("compose exec: command must not be empty")
	}
	args := append([]string{"exec", "-T", service}, command...)
	return run(ctx, ctx, ExecTimeout, s, args...)
}

// run is the common entry point for all docker compose sub-commands: it pins
// the command to s and hands it to runDocker.
func run(waitCtx, runCtx context.Context, timeout time.Duration, s Stack, subArgs ...string) (*Output, error) {
	args := append([]string{"compose", "-p", s.Key, "--project-directory", s.Dir, "-f", s.ComposeFile}, subArgs...)
	return runDocker(waitCtx, runCtx, timeout, "docker compose "+subArgs[0], args)
}

// runDocker runs `docker <args...>`. It waits for a free slot using waitCtx,
// then runs the command under runCtx bounded by timeout. name prefixes the
// returned errors (e.g. "docker compose pull", "docker ps"). The returned
// *Output is never nil, whether or not an error is returned.
func runDocker(waitCtx, runCtx context.Context, timeout time.Duration, name string, args []string) (*Output, error) {
	// Never start a command for a request that is already gone (select would
	// otherwise pick a free slot or Done at random).
	if err := waitCtx.Err(); err != nil {
		return &Output{}, fmt.Errorf("%s: %w", name, err)
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	case <-waitCtx.Done():
		return &Output{}, fmt.Errorf("%s: waiting for a free slot: %w", name, waitCtx.Err())
	}

	ctx, cancel := context.WithTimeout(runCtx, timeout)
	defer cancel()

	// #nosec G204 — args are constructed entirely from validated, internal values;
	// no user-supplied string is ever interpolated into a shell command.
	cmd := exec.CommandContext(ctx, "docker", args...)
	// Interrupt first so compose can stop cleanly; WaitDelay then kills the
	// process and closes its pipes if it does not exit in time.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = waitDelay

	stdout := &cappedBuffer{max: MaxOutputBytes}
	stderr := &cappedBuffer{max: MaxOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	out := &Output{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return out, fmt.Errorf("%s: %w (%v)", name, ctxErr, err)
		}
		return out, fmt.Errorf("%s: %w", name, err)
	}
	return out, nil
}

// cappedBuffer is an io.Writer that keeps at most max bytes and silently
// discards the rest, so a chatty or hostile command cannot exhaust memory.
// Writes always report success so the command is not killed by EPIPE.
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := c.max - c.buf.Len(); n > room {
		c.truncated = true
		p = p[:max(room, 0)]
	}
	c.buf.Write(p)
	return n, nil
}

// String returns the captured output, marked when it was truncated.
func (c *cappedBuffer) String() string {
	if c.truncated {
		return c.buf.String() + truncatedMarker
	}
	return c.buf.String()
}
