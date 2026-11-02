package compose

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy describes what a stack's compose model is allowed to do. It is checked
// against the canonical model rendered by Config, i.e. after interpolation,
// YAML merges and path resolution — exactly what docker compose will run.
type Policy struct {
	// Key is the stack key, also the compose project name. container_name
	// must start with "<Key>-" and volume/network names with "<Key>_".
	Key string
	// ProjectDir is the project directory the model was rendered with: env_file,
	// configs and secrets files must be directly inside it (files uploaded with
	// the deploy).
	ProjectDir string
	// WebsitesDir is WEBSITES_BASE/<Key>: every bind-mount source must be
	// exactly WebsitesDir/<service>/<name>, each component an existing real
	// directory (see checkBindSource).
	WebsitesDir string
	// ForbiddenHosts are host names no Traefik router of the stack may claim
	// (e.g. the deploy server's own host). Compared case-insensitively.
	ForbiddenHosts []string
	// AllowedExternalNetworks are the pre-existing networks (e.g. Traefik's
	// shared network) a stack may join with `external: true`. A network is
	// matched on its name, or on its key when it has no name; exact match.
	AllowedExternalNetworks []string
}

// Violation is one policy breach, located by scope (e.g. `service "web"`) and
// field. Messages never contain server-side paths.
type Violation struct {
	Scope  string
	Field  string
	Reason string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: %s: %s", v.Scope, v.Field, v.Reason)
}

// maxReportedViolations caps how many violations PolicyError.Error lists.
const maxReportedViolations = 20

// PolicyError lists the violations found in a compose model.
type PolicyError struct {
	Violations []Violation
}

func (e *PolicyError) Error() string {
	var b strings.Builder
	b.WriteString("compose file rejected by deployment policy: ")
	for i, v := range e.Violations {
		if i == maxReportedViolations {
			b.WriteString(fmt.Sprintf("; … and %d more", len(e.Violations)-i))
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(v.String())
	}
	return b.String()
}

// violations accumulates Violations; err returns nil when there are none.
type violations []Violation

func (vs *violations) add(scope, field, format string, args ...any) {
	*vs = append(*vs, Violation{Scope: scope, Field: field, Reason: fmt.Sprintf(format, args...)})
}

func (vs *violations) err() error {
	if len(*vs) == 0 {
		return nil
	}
	return &PolicyError{Violations: *vs}
}

// forbiddenServiceFields are service attributes that grant host access or
// escape the stack's isolation. Any non-empty value is rejected.
var forbiddenServiceFields = []string{
	"build",               // images must come from a registry (up runs --no-build)
	"cap_add",             // extra kernel capabilities
	"cgroup",              // cgroup: host
	"cgroup_parent",       // place containers in arbitrary host cgroups
	"credential_spec",     // reads host files / registry
	"device_cgroup_rules", // device access
	"devices",             // host devices
	"extends",             // may read arbitrary server files
	"external_links",      // link to containers of other projects
	"gpus",                // host GPUs
	"ipc",                 // shared/host IPC namespace
	"label_file",          // reads arbitrary server files
	"pid",                 // host or foreign PID namespace
	"privileged",          // full host access
	"provider",            // runs a provider binary on the server
	"runtime",             // alternative OCI runtime
	"security_opt",        // disables seccomp/apparmor/selinux
	"sysctls",             // kernel parameters
	"use_api_socket",      // mounts the Docker socket
	"userns_mode",         // userns_mode: host
	"uts",                 // uts: host
}

// CheckSource inspects the raw uploaded compose file, before docker compose
// renders it. It rejects constructs that make `docker compose config` itself
// read other server files or fetch remote resources (include, extends,
// label_file), so they are refused before the CLI ever processes them.
func CheckSource(raw []byte) error {
	var vs violations
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("compose file is not a valid YAML mapping: %v", err)
		}
		if _, ok := doc["include"]; ok {
			vs.add("compose file", "include", "not allowed")
		}
		services, _ := doc["services"].(map[string]any)
		for _, name := range sortedKeys(services) {
			svc, _ := services[name].(map[string]any)
			for _, f := range []string{"extends", "label_file"} {
				if _, ok := svc[f]; ok {
					vs.add(serviceScope(name), f, "not allowed")
				}
			}
		}
	}
	return vs.err()
}

// CheckDotEnv inspects an uploaded `.env` file. docker compose reads it for
// interpolation and also honours COMPOSE_* / DOCKER_* settings from it, which
// must stay under the server's control.
func CheckDotEnv(raw []byte) error {
	var vs violations
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(nil, len(raw)+1)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		key, _, _ := strings.Cut(line, "=")
		key = strings.ToUpper(strings.TrimSpace(key))
		if strings.HasPrefix(key, "COMPOSE_") || strings.HasPrefix(key, "DOCKER_") {
			vs.add(`env file ".env"`, key, "COMPOSE_* and DOCKER_* settings are reserved")
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf(".env: %v", err)
	}
	return vs.err()
}

// ParseModel decodes the JSON rendered by Config.
func ParseModel(raw []byte) (map[string]any, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unexpected docker compose config output: %v", err)
	}
	return doc, nil
}

// ValidatePolicy checks a canonical compose model (as returned by ParseModel)
// against p. It returns a *PolicyError listing every violation, or nil.
func ValidatePolicy(doc map[string]any, p Policy) error {
	var vs violations
	c := checker{p: p, vs: &vs}

	if isSet(doc["include"]) {
		vs.add("compose file", "include", "not allowed")
	}
	if name := str(doc["name"]); name != "" && name != p.Key {
		vs.add("compose file", "name", "project name is set by the server")
	}

	services, _ := doc["services"].(map[string]any)
	for _, name := range sortedKeys(services) {
		svc, ok := services[name].(map[string]any)
		if !ok {
			vs.add(serviceScope(name), "-", "service must be a mapping")
			continue
		}
		c.service(name, svc)
	}

	c.volumes(asMap(doc["volumes"]))
	c.networks(asMap(doc["networks"]))
	c.files("config", asMap(doc["configs"]))
	c.files("secret", asMap(doc["secrets"]))

	return vs.err()
}

// checker carries the policy and the violations being collected.
type checker struct {
	p  Policy
	vs *violations
}

func (c checker) service(name string, svc map[string]any) {
	scope := serviceScope(name)

	for _, f := range forbiddenServiceFields {
		if isSet(svc[f]) {
			c.vs.add(scope, f, "not allowed")
		}
	}

	switch nm := str(svc["network_mode"]); {
	case nm == "", nm == "none", nm == "bridge", nm == "default", strings.HasPrefix(nm, "service:"):
	default:
		c.vs.add(scope, "network_mode", "only none, bridge or service:<name> are allowed")
	}

	for _, v := range asList(svc["volumes_from"]) {
		if strings.HasPrefix(str(v), "container:") {
			c.vs.add(scope, "volumes_from", "containers outside the stack are not allowed")
		}
	}

	if cn := str(svc["container_name"]); cn != "" && !strings.HasPrefix(cn, c.p.Key+"-") {
		c.vs.add(scope, "container_name", "must start with %q", c.p.Key+"-")
	}

	if devs := asMap(asMap(asMap(svc["deploy"])["resources"])["reservations"])["devices"]; isSet(devs) {
		c.vs.add(scope, "deploy.resources.reservations.devices", "not allowed")
	}

	for _, v := range asList(svc["volumes"]) {
		c.serviceVolume(scope, v)
	}

	for _, v := range asList(svc["env_file"]) {
		path := str(v)
		if m, ok := v.(map[string]any); ok {
			path = str(m["path"])
		}
		if !c.inProjectDir(path) {
			c.vs.add(scope, "env_file", "only plain names of files uploaded with the deploy are allowed")
		}
	}

	// Lifecycle hooks run inside the service container but carry their own
	// privileged flag, which would bypass the service-level check. user,
	// working_dir and environment stay allowed (no more than exec gives).
	for _, hook := range []string{"post_start", "pre_stop"} {
		for i, h := range asList(svc[hook]) {
			if isSet(asMap(h)["privileged"]) {
				c.vs.add(scope, fmt.Sprintf("%s[%d].privileged", hook, i), "not allowed")
			}
		}
	}

	// Not inspected on purpose: develop.watch is only acted upon by
	// `docker compose watch`, which this server never runs; deploy.* other
	// than resources (placement, replicas, update_config…) only matters to
	// Swarm or is harmless scheduling.

	c.labels(scope, svc["labels"])
}

func (c checker) serviceVolume(scope string, v any) {
	m, ok := v.(map[string]any)
	if !ok {
		c.vs.add(scope, "volumes", "unexpected volume definition")
		return
	}
	field := fmt.Sprintf("volumes (target %q)", str(m["target"]))
	switch t := str(m["type"]); t {
	case "volume", "tmpfs", "image":
	case "bind":
		if err := c.checkBindSource(str(m["source"])); err != nil {
			c.vs.add(scope, field, "%v", err)
		}
	default:
		c.vs.add(scope, field, "volume type %q is not allowed", t)
	}
}

// SlugRE matches the <service> segment of a bind-mount directory
// (WEBSITES_BASE/<key>/<service>/<name>). handlers uses the same expression for
// namespace, environment and service identifiers, so POST /directories and the
// policy agree on what a valid segment is. Must start and end with a lowercase
// letter or digit, may contain hyphens in between, at most 63 characters.
var SlugRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// DirNameRE matches the <name> segment of a bind-mount directory. The leading
// character cannot be a dot, which rules out "." and ".." as well as hidden
// directories.
var DirNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// checkBindSource enforces the bind-mount layout: a source must be exactly
// WebsitesDir/<service>/<name> (i.e. WEBSITES_BASE/<key>/<service>/<name>, the
// layout POST /directories creates), and <key>, <service> and <name> must each
// be an existing, real directory — not a symlink, not a file.
//
// Why a fixed depth rather than "anywhere below WebsitesDir": the Docker daemon
// resolves the source again when `up` creates the containers, possibly minutes
// after this check (pull). Any path component a container can write to could
// be swapped for a symlink (e.g. "api -> /") in between, and the daemon would
// follow it. With this layout:
//
//   - a container only ever gets write access to <name>/ (the mount itself);
//     <name>/ is never a path component of another allowed source, because
//     every allowed source stops at depth 2 — whatever a container plants in
//     <name>/ (symlinks included) is below every source the policy accepts;
//   - <key>/ and <key>/<service>/ are never mounted by anyone, so no container
//     can rename or replace their entries, <name> included (the mount point is
//     also busy while mounted). /directories creates them root:root 0755 and
//     only ever chmods/chowns the <name> leaf.
//
// The components above WebsitesDir (WEBSITES_BASE and its parents) are under
// the operator's control and are not checked: they may legitimately be
// symlinks.
//
// <service> is a layout segment only: it does not have to name a service of
// the compose file (a "worker" service may mount api/storage).
//
// The source must exist: Lstat cannot vouch for a path that does not exist, and
// Docker would otherwise create the missing directories itself (root:root 0755,
// following any symlink on the way). CI calls POST /directories before /deploy.
func (c checker) checkBindSource(src string) error {
	return checkBind(src, c.p.WebsitesDir, false)
}

// CheckBindSourcePath applies the bind-source rule of the deployment policy
// to the source of a bind mount of an existing container (as reported by
// docker inspect), websitesDir being WEBSITES_BASE/<key>. It is used before a
// deploy to detect containers started under an older, laxer policy (a bind on
// <key>/ or <key>/<service>/, or outside WEBSITES_BASE/<key>/ altogether):
// while they run, such containers could swap a component of the new deploy's
// bind sources for a symlink between validation and up.
//
// The layout rules are the same as for a compose file (clean absolute path,
// exactly <service>/<name> below websitesDir, segment rules). The components
// are checked with Lstat like checkBindSource, except that a missing one is
// tolerated: the directory may have been removed or moved since the container
// was created, which gives the container no handle on the new sources. A
// symlink or a file in place of a component is refused.
func CheckBindSourcePath(src, websitesDir string) error {
	return checkBind(src, websitesDir, true)
}

// checkBind implements checkBindSource and CheckBindSourcePath.
func checkBind(src, websitesDir string, allowMissing bool) error {
	if !filepath.IsAbs(src) {
		return errors.New("relative bind sources are not allowed")
	}
	if websitesDir == "" {
		return ErrBindOutside
	}
	// A non-clean path ("x/../y") is resolved by the kernel component by
	// component, symlinks included, which lexical checks cannot predict.
	if filepath.Clean(src) != src {
		return errors.New("bind source must be a clean absolute path (no \".\", \"..\", duplicate or trailing separators)")
	}
	root := filepath.Clean(websitesDir)
	rel, ok := strings.CutPrefix(src, root+string(filepath.Separator))
	if !ok {
		if src == root {
			return ErrBindLayout
		}
		return ErrBindOutside
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 {
		return ErrBindLayout
	}
	service, name := parts[0], parts[1]
	if !SlugRE.MatchString(service) {
		return fmt.Errorf("bind source service segment %q is invalid: must match %s", service, SlugRE)
	}
	if !DirNameRE.MatchString(name) {
		return fmt.Errorf("bind source name segment %q is invalid: must match %s", name, DirNameRE)
	}

	for _, comp := range []struct{ path, label string }{
		{root, "the stack's websites directory"},
		{filepath.Join(root, service), fmt.Sprintf("bind source component %q", service)},
		{src, fmt.Sprintf("bind source %q", service+"/"+name)},
	} {
		if err := requireRealDir(comp.path, comp.label, allowMissing); err != nil {
			return err
		}
	}
	return nil
}

// ErrBindOutside and ErrBindLayout are the bind-source layout violations.
var (
	ErrBindOutside = errors.New("bind source must be inside the stack's websites directory")
	ErrBindLayout  = errors.New("bind source must be exactly <service>/<name> below the stack's websites directory (WEBSITES_BASE/<key>/<service>/<name>, as created by POST /directories)")
)

// requireRealDir returns an error unless path exists and is a directory, not a
// symbolic link. With allowMissing, a path that does not exist is accepted.
// label names path in the error without exposing server paths.
func requireRealDir(path, label string, allowMissing bool) error {
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && allowMissing:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s does not exist: create it with POST /directories before deploying", label)
	case err != nil:
		return fmt.Errorf("%s cannot be inspected", label)
	case info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is a symbolic link", label)
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory (only directories can be bind-mounted)", label)
	}
	return nil
}

// inProjectDir reports whether path names a file directly inside ProjectDir.
func (c checker) inProjectDir(path string) bool {
	if path == "" || !filepath.IsAbs(path) {
		return false
	}
	return filepath.Dir(filepath.Clean(path)) == filepath.Clean(c.p.ProjectDir)
}

func (c checker) volumes(vols map[string]any) {
	for _, name := range sortedKeys(vols) {
		v := asMap(vols[name])
		scope := fmt.Sprintf("volume %q", name)
		if isSet(v["external"]) {
			c.vs.add(scope, "external", "not allowed")
		}
		if d := str(v["driver"]); d != "" && d != "local" {
			c.vs.add(scope, "driver", "only the local driver is allowed")
		}
		if isSet(v["driver_opts"]) {
			c.vs.add(scope, "driver_opts", "not allowed")
		}
		c.resourceName(scope, v)
	}
}

func (c checker) networks(nets map[string]any) {
	for _, name := range sortedKeys(nets) {
		n := asMap(nets[name])
		scope := fmt.Sprintf("network %q", name)
		if isSet(n["external"]) {
			// An external network is only declared, not created: driver
			// settings do not apply and its name is outside the stack's
			// namespace by definition, so only the allowlist matters.
			ext := str(n["name"])
			if ext == "" {
				ext = name
			}
			if !slices.Contains(c.p.AllowedExternalNetworks, ext) {
				c.vs.add(scope, "external", "network %q is not in the allowed external networks", ext)
			}
			continue
		}
		if d := str(n["driver"]); d != "" && d != "bridge" {
			c.vs.add(scope, "driver", "only the bridge driver is allowed")
		}
		if isSet(n["driver_opts"]) {
			c.vs.add(scope, "driver_opts", "not allowed")
		}
		c.resourceName(scope, n)
	}
}

// resourceName rejects explicit volume/network names outside the stack's
// namespace, which would attach to another project's volume or network.
func (c checker) resourceName(scope string, m map[string]any) {
	if name := str(m["name"]); name != "" && !strings.HasPrefix(name, c.p.Key+"_") {
		c.vs.add(scope, "name", "must start with %q", c.p.Key+"_")
	}
}

// files checks top-level configs or secrets.
func (c checker) files(kind string, defs map[string]any) {
	for _, name := range sortedKeys(defs) {
		d := asMap(defs[name])
		scope := fmt.Sprintf("%s %q", kind, name)
		if isSet(d["external"]) {
			c.vs.add(scope, "external", "not allowed")
		}
		if f, ok := d["file"]; ok && !c.inProjectDir(str(f)) {
			c.vs.add(scope, "file", "only plain names of files uploaded with the deploy are allowed")
		}
	}
}

func (c checker) labels(scope string, raw any) {
	labels := map[string]string{}
	switch l := raw.(type) {
	case map[string]any:
		for k, v := range l {
			labels[k] = str(v)
		}
	case []any:
		for _, item := range l {
			k, v, _ := strings.Cut(str(item), "=")
			labels[k] = v
		}
	}

	for _, key := range sortedKeys(labels) {
		lk := strings.ToLower(key) // Traefik label keys are case-insensitive
		field := fmt.Sprintf("labels.%s", key)
		switch {
		case strings.HasPrefix(lk, "com.docker.compose."):
			c.vs.add(scope, field, "reserved label")
		case strings.HasPrefix(lk, "traefik.tcp."), strings.HasPrefix(lk, "traefik.udp."):
			c.vs.add(scope, field, "Traefik TCP/UDP routing is not allowed")
		case strings.HasPrefix(lk, "traefik.http.routers.") && strings.HasSuffix(lk, ".priority"):
			c.vs.add(scope, field, "router priority is not allowed")
		case strings.HasPrefix(lk, "traefik.http.routers.") && strings.HasSuffix(lk, ".rule"):
			if err := checkRule(labels[key], c.p.ForbiddenHosts); err != nil {
				c.vs.add(scope, field, "%v", err)
			}
		}
	}
}

// -- Traefik rules --------------------------------------------------------------

// maxRuleLen and maxRuleDepth bound the rule parser.
const (
	maxRuleLen   = 4096
	maxRuleDepth = 32
)

// checkRule requires a Traefik router rule to only match explicit Host()
// names, none of which is forbidden. Without that, a rule such as
// PathPrefix(`/`) (or one negating Host) would capture traffic for every host,
// including other stacks' and the deploy server's own.
func checkRule(rule string, forbidden []string) error {
	if len(rule) > maxRuleLen {
		return errors.New("rule is too long")
	}
	p := &ruleParser{s: rule}
	hc, err := p.parse()
	if err != nil {
		return fmt.Errorf("invalid rule: %v", err)
	}
	if !hc.ok {
		return errors.New("rule must restrict the router to explicit Host() names")
	}
	for _, h := range hc.hosts {
		h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
		if h == "" {
			return errors.New("empty Host() name")
		}
		for _, f := range forbidden {
			if h == strings.TrimSuffix(strings.ToLower(f), ".") {
				return fmt.Errorf("host %q is reserved", h)
			}
		}
	}
	return nil
}

// hostConstraint describes a rule sub-expression: ok means every request it
// matches has a Host among hosts (an over-approximation is fine).
type hostConstraint struct {
	ok    bool
	hosts []string
}

// ruleParser is a small recursive-descent parser for Traefik rule
// expressions: Matcher(`arg`, ...), &&, ||, ! and parentheses.
type ruleParser struct {
	s     string
	pos   int
	depth int
}

func (p *ruleParser) parse() (hostConstraint, error) {
	hc, err := p.or()
	if err != nil {
		return hc, err
	}
	p.space()
	if p.pos != len(p.s) {
		return hc, fmt.Errorf("unexpected input at offset %d", p.pos)
	}
	return hc, nil
}

func (p *ruleParser) or() (hostConstraint, error) {
	left, err := p.and()
	for err == nil && p.consume("||") {
		var right hostConstraint
		if right, err = p.and(); err == nil {
			left = hostConstraint{ok: left.ok && right.ok, hosts: slices.Concat(left.hosts, right.hosts)}
		}
	}
	return left, err
}

func (p *ruleParser) and() (hostConstraint, error) {
	left, err := p.unary()
	for err == nil && p.consume("&&") {
		var right hostConstraint
		if right, err = p.unary(); err == nil {
			var hosts []string
			if left.ok {
				hosts = append(hosts, left.hosts...)
			}
			if right.ok {
				hosts = append(hosts, right.hosts...)
			}
			left = hostConstraint{ok: left.ok || right.ok, hosts: hosts}
		}
	}
	return left, err
}

func (p *ruleParser) unary() (hostConstraint, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxRuleDepth {
		return hostConstraint{}, errors.New("rule is nested too deeply")
	}
	if p.consume("!") {
		// A negation matches "everything but…": never host-constrained.
		_, err := p.unary()
		return hostConstraint{}, err
	}
	if p.consume("(") {
		hc, err := p.or()
		if err == nil && !p.consume(")") {
			err = errors.New("missing )")
		}
		return hc, err
	}
	return p.matcher()
}

func (p *ruleParser) matcher() (hostConstraint, error) {
	p.space()
	start := p.pos
	for p.pos < len(p.s) && isIdentChar(p.s[p.pos]) {
		p.pos++
	}
	name := p.s[start:p.pos]
	if name == "" {
		return hostConstraint{}, fmt.Errorf("expected a matcher at offset %d", start)
	}
	if !p.consume("(") {
		return hostConstraint{}, fmt.Errorf("expected ( after %s", name)
	}
	var args []string
	if !p.consume(")") {
		for {
			arg, err := p.str()
			if err != nil {
				return hostConstraint{}, err
			}
			args = append(args, arg)
			if p.consume(",") {
				continue
			}
			if !p.consume(")") {
				return hostConstraint{}, fmt.Errorf("expected ) after %s arguments", name)
			}
			break
		}
	}
	if strings.EqualFold(name, "Host") && len(args) > 0 {
		return hostConstraint{ok: true, hosts: args}, nil
	}
	return hostConstraint{}, nil
}

// str parses a backtick- or double-quote-delimited string.
func (p *ruleParser) str() (string, error) {
	p.space()
	if p.pos >= len(p.s) || (p.s[p.pos] != '`' && p.s[p.pos] != '"') {
		return "", fmt.Errorf("expected a quoted string at offset %d", p.pos)
	}
	quote := p.s[p.pos]
	end := strings.IndexByte(p.s[p.pos+1:], quote)
	if end < 0 {
		return "", errors.New("unterminated string")
	}
	v := p.s[p.pos+1 : p.pos+1+end]
	p.pos += end + 2
	return v, nil
}

func (p *ruleParser) consume(tok string) bool {
	p.space()
	if strings.HasPrefix(p.s[p.pos:], tok) {
		p.pos += len(tok)
		return true
	}
	return false
}

func (p *ruleParser) space() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t' || p.s[p.pos] == '\n' || p.s[p.pos] == '\r') {
		p.pos++
	}
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// -- helpers ------------------------------------------------------------------

func serviceScope(name string) string { return fmt.Sprintf("service %q", name) }

// isSet reports whether a decoded value is present and non-empty.
func isSet(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

// str returns v as a string ("" for nil, fmt formatting for scalars).
func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// asList returns v as a list, wrapping a lone scalar (compose accepts both).
func asList(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	default:
		return []any{x}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
