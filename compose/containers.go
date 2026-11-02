package compose

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// ProjectLabel is the label docker compose puts on every container it creates,
// holding the compose project name.
const ProjectLabel = "com.docker.compose.project"

// Container is an existing container of a stack, as found by StackContainers.
type Container struct {
	ID      string
	Name    string // container name, without Docker's leading "/"
	Project string // value of ProjectLabel, "" when the container has none
	Mounts  []Mount
}

// Mount is one entry of a container's Mounts, as reported by docker inspect.
// Type is "bind", "volume", "tmpfs", "image", "npipe" or "cluster". Source is
// the host path of a bind mount, as it was given when the container was
// created (Docker does not resolve symlinks in it).
type Mount struct {
	Type        string
	Source      string
	Destination string
	RW          bool
}

// containerIDRE matches a full or short container ID, as printed by docker ps.
var containerIDRE = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// inspectFormat makes docker inspect print one JSON object per container.
const inspectFormat = `{"Id":{{json .Id}},"Name":{{json .Name}},"Labels":{{json .Config.Labels}},"Mounts":{{json .Mounts}}}`

// StackContainers lists every container of the stack key, whatever its state
// (running, exited, created, paused…): a stopped container can be restarted,
// with its mounts, at any time. A container belongs to the stack when:
//
//   - its ProjectLabel is key: every container docker compose created for
//     the project key, whoever ran compose (this server, the SSH workflow
//     that ran it from COMPOSE_BASE/<key>/, whose default project name is the
//     directory name, i.e. key);
//   - or its name starts with "<key>-" or "<key>_" (compose v2 and v1 default
//     names, container_name values allowed by the policy, docker run by
//     hand), unless that name is explained by another compose project of its
//     own: "<key>-api-1" labelled "<key>-api" belongs to the stack
//     "<key>-api", not to key.
//
// It runs `docker ps -a` once per filter, then `docker inspect` on the union,
// all within InspectTimeout. Any failure is returned: callers must fail
// closed. A container removed between ps and inspect makes inspect fail; the
// caller simply retries.
func StackContainers(ctx context.Context, key string) ([]Container, error) {
	ctx, cancel := context.WithTimeout(ctx, InspectTimeout)
	defer cancel()

	var ids []string
	for _, filter := range []string{
		"label=" + ProjectLabel + "=" + key,
		// Docker matches name filters as regular expressions; a stack key
		// only holds [a-z0-9-], none of which is special outside brackets.
		"name=^/?" + key + "[-_]",
	} {
		out, err := runDocker(ctx, ctx, InspectTimeout, "docker ps",
			[]string{"ps", "--all", "--no-trunc", "--filter", filter, "--format", "{{.ID}}"})
		if err != nil {
			return nil, err
		}
		for _, id := range strings.Fields(out.Stdout) {
			if !containerIDRE.MatchString(id) {
				return nil, fmt.Errorf("docker ps: unexpected container ID %q", truncate(id, 80))
			}
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}

	out, err := runDocker(ctx, ctx, InspectTimeout, "docker inspect",
		append([]string{"inspect", "--type", "container", "--format", inspectFormat, "--"}, ids...))
	if err != nil {
		return nil, err
	}
	containers, err := parseInspect(out.Stdout)
	if err != nil {
		return nil, err
	}
	if len(containers) != len(ids) {
		return nil, fmt.Errorf("docker inspect: %d containers listed, %d inspected", len(ids), len(containers))
	}

	kept := containers[:0]
	for _, c := range containers {
		if belongsTo(c, key) {
			kept = append(kept, c)
		}
	}
	slices.SortFunc(kept, func(a, b Container) int { return strings.Compare(a.Name, b.Name) })
	return kept, nil
}

// parseInspect decodes the output of docker inspect --format inspectFormat.
func parseInspect(stdout string) ([]Container, error) {
	var containers []Container
	for line := range strings.SplitSeq(stdout, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var raw struct {
			ID     string            `json:"Id"`
			Name   string            `json:"Name"`
			Labels map[string]string `json:"Labels"`
			Mounts []Mount           `json:"Mounts"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return nil, fmt.Errorf("docker inspect: unexpected output: %v", err)
		}
		containers = append(containers, Container{
			ID:      raw.ID,
			Name:    strings.TrimPrefix(raw.Name, "/"),
			Project: raw.Labels[ProjectLabel],
			Mounts:  raw.Mounts,
		})
	}
	return containers, nil
}

// belongsTo reports whether c, found by label or by name, is a container of
// the stack key (see StackContainers).
func belongsTo(c Container, key string) bool {
	if c.Project == key || c.Project == "" {
		return true
	}
	return !strings.HasPrefix(c.Name, c.Project+"-") && !strings.HasPrefix(c.Name, c.Project+"_")
}

// RemoveContainers stops (10 second grace period) then force-removes the
// given containers:
//
//	docker stop --timeout 10 -- <ids...>
//	docker rm --force -- <ids...>
//
// It is meant for containers StackContainers found and that docker compose
// down cannot remove (no compose file, or not labelled with the project). A
// docker stop failure is not fatal (rm --force kills what is still running);
// the error of docker rm is returned. Anonymous volumes are kept, as with
// docker compose down. Like Down, the commands are detached from ctx once
// started; ctx only bounds the wait for a free slot.
func RemoveContainers(ctx context.Context, ids []string) (*Output, error) {
	if len(ids) == 0 {
		return &Output{}, nil
	}
	for _, id := range ids {
		if !containerIDRE.MatchString(id) {
			return &Output{}, fmt.Errorf("docker rm: invalid container ID %q", truncate(id, 80))
		}
	}
	runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RemoveTimeout)
	defer cancel()

	stopOut, stopErr := runDocker(ctx, runCtx, RemoveTimeout, "docker stop",
		append([]string{"stop", "--timeout", "10", "--"}, ids...))
	out, err := runDocker(ctx, runCtx, RemoveTimeout, "docker rm",
		append([]string{"rm", "--force", "--"}, ids...))
	if stopErr != nil && stopOut != nil && out != nil {
		out.Stderr = stopOut.Stderr + out.Stderr
	}
	return out, err
}

// truncate returns at most n bytes of s, for error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
