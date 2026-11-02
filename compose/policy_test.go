package compose

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "app-staging"

// testPolicy returns a policy rooted in temp directories.
func testPolicy(t *testing.T) Policy {
	t.Helper()
	root := t.TempDir()
	p := Policy{
		Key:                     testKey,
		ProjectDir:              filepath.Join(root, "compose", testKey),
		WebsitesDir:             filepath.Join(root, "websites", testKey),
		ForbiddenHosts:          []string{"deploy.example.com"},
		AllowedExternalNetworks: []string{"traefik", "shared_proxy"},
	}
	// The nominal bind-mount directory, as POST /directories creates it.
	if err := os.MkdirAll(filepath.Join(p.WebsitesDir, "web", "storage"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// model decodes a JSON compose model, replacing $PROJECT and $WEBSITES with the
// policy's directories.
func model(t *testing.T, p Policy, js string) map[string]any {
	t.Helper()
	js = strings.NewReplacer("$PROJECT", p.ProjectDir, "$WEBSITES", p.WebsitesDir).Replace(js)
	doc, err := ParseModel([]byte(js))
	if err != nil {
		t.Fatalf("model %s: %v", js, err)
	}
	return doc
}

// svc wraps a single service definition into a model.
func svc(def string) string {
	return `{"name":"app-staging","services":{"web":` + def + `}}`
}

func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string // substring of the error; "" means allowed
	}{
		// -- allowed ---------------------------------------------------------
		{"unprivileged hooks", svc(`{"post_start":[{"command":["sh"],"user":"root","privileged":false,"environment":{"A":"1"}}],"pre_stop":[{"command":["sh"]}]}`), ""},
		{"minimal", svc(`{"image":"nginx"}`), ""},
		{"empty model", `{}`, ""},
		{"falsy forbidden fields", svc(`{"image":"nginx","privileged":false,"cap_add":[],"sysctls":{},"pid":"","command":null}`), ""},
		{"named, tmpfs and image volumes", `{"services":{"web":{"volumes":[
			{"type":"volume","source":"data","target":"/data"},
			{"type":"tmpfs","target":"/tmp"},
			{"type":"image","source":"busybox","target":"/img"}]}},
			"volumes":{"data":{"name":"app-staging_data","driver":"local"}}}`, ""},
		{"bind on service/name directory", svc(`{"volumes":[{"type":"bind","source":"$WEBSITES/web/storage","target":"/s"}]}`), ""},
		{"env_file in project dir", svc(`{"env_file":[{"path":"$PROJECT/api.env","required":true},"$PROJECT/.env"]}`), ""},
		{"config and secret files in project dir", `{"configs":{"c":{"file":"$PROJECT/c.conf"},"i":{"content":"x"}},"secrets":{"s":{"file":"$PROJECT/s.txt"}}}`, ""},
		{"prefixed container_name", svc(`{"container_name":"app-staging-web"}`), ""},
		{"network modes", `{"services":{"a":{"network_mode":"none"},"b":{"network_mode":"bridge"},"c":{"network_mode":"service:a"}}}`, ""},
		{"volumes_from service", svc(`{"volumes_from":["db","db:ro"]}`), ""},
		{"stack networks", `{"networks":{"default":{"name":"app-staging_default","ipam":{}},"back":{"driver":"bridge"}}}`, ""},
		{"traefik host rule", svc(`{"labels":{"traefik.enable":"true","traefik.http.routers.web.rule":"Host(` + "`app.example.com`" + `) && PathPrefix(` + "`/api`" + `)"}}`), ""},
		{"traefik multi-host rule", svc(`{"labels":["traefik.http.routers.web.rule=(Host(` + "`a.example.com`" + `) || Host(\"b.example.com\")) && Method(` + "`GET`" + `)"]}`), ""},
		{"traefik v2 host list", svc(`{"labels":{"traefik.http.routers.web.rule":"Host(` + "`a.example.com`, `b.example.com`" + `)"}}`), ""},
		{"deploy resources without devices", svc(`{"deploy":{"resources":{"limits":{"memory":"1g"}}}}`), ""},

		// -- forbidden service fields ---------------------------------------
		{"privileged", svc(`{"privileged":true}`), `service "web": privileged: not allowed`},
		{"cap_add", svc(`{"cap_add":["SYS_ADMIN"]}`), `service "web": cap_add`},
		{"devices", svc(`{"devices":[{"source":"/dev/sda","target":"/dev/sda"}]}`), `service "web": devices`},
		{"pid", svc(`{"pid":"host"}`), `service "web": pid`},
		{"ipc", svc(`{"ipc":"host"}`), `service "web": ipc`},
		{"userns_mode", svc(`{"userns_mode":"host"}`), `service "web": userns_mode`},
		{"security_opt", svc(`{"security_opt":["seccomp:unconfined"]}`), `service "web": security_opt`},
		{"sysctls", svc(`{"sysctls":{"net.ipv4.ip_forward":"1"}}`), `service "web": sysctls`},
		{"build", svc(`{"build":{"context":"."}}`), `service "web": build`},
		{"extends", svc(`{"extends":{"service":"x"}}`), `service "web": extends`},
		{"cgroup host", svc(`{"cgroup":"host"}`), `service "web": cgroup`},
		{"uts host", svc(`{"uts":"host"}`), `service "web": uts`},
		{"runtime", svc(`{"runtime":"runc-unsafe"}`), `service "web": runtime`},
		{"api socket", svc(`{"use_api_socket":true}`), `service "web": use_api_socket`},
		{"provider", svc(`{"provider":{"type":"x"}}`), `service "web": provider`},
		{"gpus", svc(`{"gpus":"all"}`), `service "web": gpus`},
		{"external_links", svc(`{"external_links":["other-db-1:db"]}`), `service "web": external_links`},
		{"device reservations", svc(`{"deploy":{"resources":{"reservations":{"devices":[{"capabilities":["gpu"]}]}}}}`), `deploy.resources.reservations.devices`},
		{"network_mode host", svc(`{"network_mode":"host"}`), `service "web": network_mode`},
		{"network_mode container", svc(`{"network_mode":"container:other"}`), `service "web": network_mode`},
		{"volumes_from container", svc(`{"volumes_from":["container:other-db-1"]}`), `service "web": volumes_from`},
		{"privileged post_start hook", svc(`{"post_start":[{"command":["sh"],"privileged":true}]}`), `service "web": post_start[0].privileged: not allowed`},
		{"privileged pre_stop hook", svc(`{"pre_stop":[{"command":["sh"]},{"command":["sh"],"privileged":true}]}`), `pre_stop[1].privileged`},
		{"service not a mapping", `{"services":{"web":"x"}}`, `service "web"`},

		// -- volumes ---------------------------------------------------------
		{"bind outside websites", svc(`{"volumes":[{"type":"bind","source":"/etc","target":"/e"}]}`), `volumes (target "/e"): bind source must be inside`},
		{"bind on websites root", svc(`{"volumes":[{"type":"bind","source":"$WEBSITES/..","target":"/e"}]}`), `bind source must be a clean absolute path`},
		{"bind on websites dir itself", svc(`{"volumes":[{"type":"bind","source":"$WEBSITES","target":"/s"}]}`), `bind source must be exactly <service>/<name>`},
		{"bind on sibling stack", svc(`{"volumes":[{"type":"bind","source":"$WEBSITES-other/x","target":"/e"}]}`), `bind source must be inside`},
		{"bind traversal", svc(`{"volumes":[{"type":"bind","source":"$WEBSITES/../../etc","target":"/e"}]}`), `bind source must be a clean absolute path`},
		{"bind in project dir (relative)", svc(`{"volumes":[{"type":"bind","source":"$PROJECT/data","target":"/e"}]}`), `bind source must be inside`},
		{"relative bind", svc(`{"volumes":[{"type":"bind","source":"./data","target":"/e"}]}`), `relative bind sources are not allowed`},
		{"docker socket", svc(`{"volumes":[{"type":"bind","source":"/var/run/docker.sock","target":"/var/run/docker.sock"}]}`), `bind source must be inside`},
		{"npipe volume", svc(`{"volumes":[{"type":"npipe","source":"x","target":"/e"}]}`), `volume type "npipe" is not allowed`},
		{"short volume syntax", svc(`{"volumes":["/etc:/e"]}`), `unexpected volume definition`},
		{"external volume", `{"volumes":{"v":{"external":true}}}`, `volume "v": external: not allowed`},
		{"volume driver", `{"volumes":{"v":{"driver":"nfs"}}}`, `volume "v": driver`},
		{"volume driver_opts bind", `{"volumes":{"v":{"driver_opts":{"type":"none","o":"bind","device":"/etc"}}}}`, `volume "v": driver_opts`},
		{"foreign volume name", `{"volumes":{"v":{"name":"other-prod_db"}}}`, `volume "v": name: must start with "app-staging_"`},

		// -- networks --------------------------------------------------------
		{"allowed external network", `{"networks":{"traefik":{"external":true}}}`, ""},
		{"allowed external network by name", `{"networks":{"proxy":{"name":"shared_proxy","external":true}}}`, ""},
		{"allowed external network with driver ignored", `{"networks":{"traefik":{"name":"traefik","external":true,"driver":"overlay"}}}`, ""},
		{"external network not listed", `{"networks":{"db":{"external":true}}}`, `network "db": external: network "db" is not in the allowed external networks`},
		{"external name differs from listed key", `{"networks":{"traefik":{"name":"other-prod_default","external":true}}}`, `network "other-prod_default" is not in the allowed external networks`},
		{"listed name used without external", `{"networks":{"n":{"name":"traefik"}}}`, `network "n": name: must start with`},
		{"foreign network name", `{"networks":{"n":{"name":"traefik"}}}`, `network "n": name`},
		{"macvlan network", `{"networks":{"n":{"driver":"macvlan"}}}`, `network "n": driver`},
		{"network driver_opts", `{"networks":{"n":{"driver_opts":{"com.docker.network.bridge.name":"docker0"}}}}`, `network "n": driver_opts`},

		// -- files -----------------------------------------------------------
		{"env_file outside project", svc(`{"env_file":[{"path":"/etc/shadow"}]}`), `service "web": env_file`},
		{"env_file in subdirectory", svc(`{"env_file":["$PROJECT/sub/a.env"]}`), `service "web": env_file`},
		{"env_file relative", svc(`{"env_file":"a.env"}`), `service "web": env_file`},
		{"config file outside project", `{"configs":{"c":{"file":"/etc/passwd"}}}`, `config "c": file`},
		{"secret file outside project", `{"secrets":{"s":{"file":"/root/.docker/config.json"}}}`, `secret "s": file`},
		{"external secret", `{"secrets":{"s":{"external":true}}}`, `secret "s": external`},

		// -- naming ----------------------------------------------------------
		{"foreign container_name", svc(`{"container_name":"other-prod-db"}`), `container_name: must start with "app-staging-"`},
		{"project name override", `{"name":"other"}`, `name: project name is set by the server`},
		{"include", `{"include":[{"path":["/x.yml"]}]}`, `include: not allowed`},

		// -- labels ----------------------------------------------------------
		{"compose label", svc(`{"labels":{"com.docker.compose.project":"other"}}`), `reserved label`},
		{"router priority", svc(`{"labels":{"traefik.http.routers.web.priority":"9999"}}`), `router priority is not allowed`},
		{"router priority mixed case", svc(`{"labels":{"Traefik.HTTP.Routers.web.Priority":"9999"}}`), `router priority is not allowed`},
		{"tcp router", svc(`{"labels":{"traefik.tcp.routers.x.rule":"HostSNI(` + "`*`" + `)"}}`), `TCP/UDP routing is not allowed`},
		{"udp router", svc(`{"labels":{"traefik.udp.routers.x.entrypoints":"dns"}}`), `TCP/UDP routing is not allowed`},
		{"forbidden host", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(` + "`Deploy.Example.com.`" + `)"}}`), `host "deploy.example.com" is reserved`},
		{"forbidden host in disjunction", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(` + "`a.example.com`" + `) || Host(` + "`deploy.example.com`" + `)"}}`), `is reserved`},
		{"path-only rule", svc(`{"labels":{"traefik.http.routers.x.rule":"PathPrefix(` + "`/`" + `)"}}`), `explicit Host() names`},
		{"host or path rule", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(` + "`a.example.com`" + `) || PathPrefix(` + "`/`" + `)"}}`), `explicit Host() names`},
		{"negated host", svc(`{"labels":{"traefik.http.routers.x.rule":"!Host(` + "`a.example.com`" + `)"}}`), `explicit Host() names`},
		{"host regexp", svc(`{"labels":{"traefik.http.routers.x.rule":"HostRegexp(` + "`.+`" + `)"}}`), `explicit Host() names`},
		{"empty host", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(` + "``" + `)"}}`), `empty Host() name`},
		{"host without args", svc(`{"labels":{"traefik.http.routers.x.rule":"Host()"}}`), `explicit Host() names`},
		{"unparseable rule", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(` + "`a`" + `"}}`), `invalid rule`},
		{"trailing garbage", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(` + "`a`" + `) junk"}}`), `invalid rule`},
		{"unterminated string", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(` + "`a" + `)"}}`), `unterminated string`},
		{"unquoted argument", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(a)"}}`), `expected a quoted string`},
		{"missing paren", svc(`{"labels":{"traefik.http.routers.x.rule":"(Host(` + "`a`" + `)"}}`), `missing )`},
		{"missing matcher", svc(`{"labels":{"traefik.http.routers.x.rule":"&& Host(` + "`a`" + `)"}}`), `expected a matcher`},
		{"matcher without paren", svc(`{"labels":{"traefik.http.routers.x.rule":"Host"}}`), `expected ( after Host`},
		{"too deep", svc(`{"labels":{"traefik.http.routers.x.rule":"` + strings.Repeat("(", 40) + "Host(`a`)" + strings.Repeat(")", 40) + `"}}`), `nested too deeply`},
		{"too long", svc(`{"labels":{"traefik.http.routers.x.rule":"Host(` + "`" + strings.Repeat("a", 5000) + "`" + `)"}}`), `rule is too long`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(t)
			err := ValidatePolicy(model(t, p, tc.doc), p)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected violation: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), p.ProjectDir) || strings.Contains(err.Error(), p.WebsitesDir) {
				t.Errorf("error leaks a server path: %v", err)
			}
		})
	}
}

func TestValidatePolicy_reportsEveryViolation(t *testing.T) {
	p := testPolicy(t)
	doc := model(t, p, `{"services":{"a":{"privileged":true,"pid":"host"},"b":{"cap_add":["ALL"]}}}`)

	err := ValidatePolicy(doc, p)
	var pe *PolicyError
	if !errors.As(err, &pe) || len(pe.Violations) != 3 {
		t.Fatalf("error = %#v, want 3 violations", err)
	}
	if pe.Violations[0].Scope != `service "a"` || pe.Violations[2].Scope != `service "b"` {
		t.Errorf("violations not ordered by service: %+v", pe.Violations)
	}
}

func TestPolicyError_capsReportedViolations(t *testing.T) {
	var vs violations
	for range maxReportedViolations + 5 {
		vs.add("s", "f", "r")
	}
	err := vs.err()
	if err == nil {
		t.Fatal("err() = nil, want a *PolicyError")
	}
	msg := err.Error()
	if !strings.Contains(msg, "and 5 more") || strings.Count(msg, "s: f: r") != maxReportedViolations {
		t.Errorf("message = %q", msg)
	}
}

// TestValidatePolicy_bindLayout covers the bind-source layout rule: exactly
// WebsitesDir/<service>/<name>, every component an existing real directory.
func TestValidatePolicy_bindLayout(t *testing.T) {
	mkdir := func(t *testing.T, p string) {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	symlink := func(t *testing.T, target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	writeFile := func(t *testing.T, p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name   string
		setup  func(t *testing.T, w string) // w is WebsitesDir; web/storage already exists
		source string                       // relative to WebsitesDir unless absolute
		want   string                       // substring of the error; "" means allowed
	}{
		// -- nominal -----------------------------------------------------------
		{"depth 2", nil, "web/storage", ""},
		{"service segment need not be a compose service", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "api", "storage")) }, "api/storage", ""},
		{"name with dots and dashes", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "web", "v1.2_cache-x")) }, "web/v1.2_cache-x", ""},

		// -- depth ------------------------------------------------------------
		{"depth 0 (key)", nil, ".", "must be exactly <service>/<name>"},
		{"depth 1 (service)", nil, "web", "must be exactly <service>/<name>"},
		{"depth 3", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "web", "storage", "sub")) }, "web/storage/sub", "must be exactly <service>/<name>"},
		{"depth 4", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "web", "storage", "a", "b")) }, "web/storage/a/b", "must be exactly <service>/<name>"},
		{"trailing separator", nil, "web/storage/", "clean absolute path"},
		{"dot component", nil, "web/./storage", "clean absolute path"},
		{"dot-dot through a real directory", nil, "web/storage/../storage", "clean absolute path"},
		{"duplicate separator", nil, "web//storage", "clean absolute path"},

		// -- outside ------------------------------------------------------------
		{"sibling stack sharing the prefix", nil, "$W-other/web/storage", "must be inside the stack's websites directory"},
		{"host path", nil, "/etc/ssl", "must be inside the stack's websites directory"},

		// -- symlinks ---------------------------------------------------------
		{"key directory is a symlink", func(t *testing.T, w string) {
			realDir := w + "-real"
			if err := os.Rename(w, realDir); err != nil {
				t.Fatal(err)
			}
			symlink(t, realDir, w)
		}, "web/storage", "the stack's websites directory is a symbolic link"},
		{"service directory is a symlink to the host root", func(t *testing.T, w string) { symlink(t, "/", filepath.Join(w, "evil")) }, "evil/etc", `component "evil" is a symbolic link`},
		{"service directory is a symlink inside the tree", func(t *testing.T, w string) { symlink(t, filepath.Join(w, "web"), filepath.Join(w, "alias")) }, "alias/storage", `component "alias" is a symbolic link`},
		{"name is a symlink inside the tree", func(t *testing.T, w string) {
			symlink(t, filepath.Join(w, "web", "storage"), filepath.Join(w, "web", "link"))
		}, "web/link", `bind source "web/link" is a symbolic link`},
		{"name is a symlink to the host", func(t *testing.T, w string) { symlink(t, "/etc", filepath.Join(w, "web", "etc")) }, "web/etc", `bind source "web/etc" is a symbolic link`},
		{"name is a dangling symlink", func(t *testing.T, w string) { symlink(t, "/nonexistent-a2", filepath.Join(w, "web", "dangling")) }, "web/dangling", `bind source "web/dangling" is a symbolic link`},

		// -- not a directory / missing -----------------------------------------
		{"file instead of the name directory", func(t *testing.T, w string) { writeFile(t, filepath.Join(w, "web", "app.conf")) }, "web/app.conf", `bind source "web/app.conf" is not a directory`},
		{"file instead of the service directory", func(t *testing.T, w string) { writeFile(t, filepath.Join(w, "api")) }, "api/storage", `component "api" is not a directory`},
		{"missing name directory", nil, "web/missing", `bind source "web/missing" does not exist`},
		{"missing service directory", nil, "api/storage", `component "api" does not exist`},
		{"missing key directory", func(t *testing.T, w string) {
			if err := os.RemoveAll(w); err != nil {
				t.Fatal(err)
			}
		}, "web/storage", "the stack's websites directory does not exist"},

		// -- invalid segments --------------------------------------------------
		{"uppercase service", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "Web", "storage")) }, "Web/storage", `service segment "Web" is invalid`},
		{"underscore in service", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "my_api", "storage")) }, "my_api/storage", `service segment "my_api" is invalid`},
		{"leading hyphen in service", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "-web", "storage")) }, "-web/storage", `service segment "-web" is invalid`},
		{"hidden name", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "web", ".git")) }, "web/.git", `name segment ".git" is invalid`},
		{"name with a space", func(t *testing.T, w string) { mkdir(t, filepath.Join(w, "web", "a b")) }, "web/a b", `name segment "a b" is invalid`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := testPolicy(t)
			if tc.setup != nil {
				tc.setup(t, p.WebsitesDir)
			}
			src := strings.ReplaceAll(tc.source, "$W", p.WebsitesDir)
			if !filepath.IsAbs(src) {
				// Plain concatenation: filepath.Join would clean the path.
				src = p.WebsitesDir + "/" + src
				if tc.source == "." {
					src = p.WebsitesDir
				}
			}
			raw, _ := json.Marshal(map[string]any{"services": map[string]any{"web": map[string]any{
				"volumes": []any{map[string]any{"type": "bind", "source": src, "target": "/x"}},
			}}})
			doc, _ := ParseModel(raw)
			err := ValidatePolicy(doc, p)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected violation: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), p.WebsitesDir) {
				t.Errorf("error leaks a server path: %v", err)
			}
		})
	}
}

// The levels above the stack directory (WEBSITES_BASE and its parents) belong
// to the operator and may be symlinks: only <key>, <service> and <name> are
// checked.
func TestValidatePolicy_bindBaseSymlink(t *testing.T) {
	root := t.TempDir()
	realBase := filepath.Join(root, "real-websites")
	if err := os.MkdirAll(filepath.Join(realBase, testKey, "web", "storage"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realBase, filepath.Join(root, "websites")); err != nil {
		t.Fatal(err)
	}
	p := Policy{Key: testKey, WebsitesDir: filepath.Join(root, "websites", testKey)}
	doc := model(t, p, svc(`{"volumes":[{"type":"bind","source":"$WEBSITES/web/storage","target":"/s"}]}`))
	if err := ValidatePolicy(doc, p); err != nil {
		t.Errorf("unexpected violation: %v", err)
	}
}

func TestValidatePolicy_noWebsitesDir(t *testing.T) {
	p := testPolicy(t)
	doc := model(t, p, svc(`{"volumes":[{"type":"bind","source":"$WEBSITES/x","target":"/x"}]}`))
	p.WebsitesDir = ""
	if err := ValidatePolicy(doc, p); err == nil {
		t.Error("binds must be refused when no websites directory is configured")
	}
}

func TestCheckSource(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{"plain", "services:\n  web:\n    image: nginx\n", ""},
		{"empty", "", ""},
		{"json", `{"services":{"web":{"image":"nginx"}}}`, ""},
		{"include", "include:\n  - /etc/hosts\nservices: {}\n", "include: not allowed"},
		{"extends", "services:\n  web:\n    extends:\n      file: /etc/passwd\n      service: a\n", `service "web": extends`},
		{"extends through merge key", "x-base: &b\n  extends: {service: a}\nservices:\n  web:\n    <<: *b\n", `service "web": extends`},
		{"label_file", "services:\n  web:\n    label_file: /etc/shadow\n", `service "web": label_file`},
		{"second document", "services: {}\n---\ninclude: [/etc/hosts]\n", "include: not allowed"},
		{"not a mapping", "- a\n- b\n", "not a valid YAML mapping"},
		{"invalid yaml", "services: [\n", "not a valid YAML mapping"},
		{"compose tags", "services:\n  web:\n    ports: !reset []\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertErrContains(t, CheckSource([]byte(tc.src)), tc.want)
		})
	}
}

func TestCheckDotEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want string
	}{
		{"plain", "TAG=1.2\n# COMPOSE_PROJECT_NAME=x\n\nAPP_DEBUG=0\n", ""},
		{"project name", "COMPOSE_PROJECT_NAME=other\n", "COMPOSE_PROJECT_NAME"},
		{"exported docker host", "export DOCKER_HOST=tcp://evil:2375\n", "DOCKER_HOST"},
		{"lowercase", "compose_file=/etc/x.yml", "COMPOSE_FILE"},
		{"spaces", "  COMPOSE_PROFILES = all ", "COMPOSE_PROFILES"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertErrContains(t, CheckDotEnv([]byte(tc.env)), tc.want)
		})
	}
}

func TestParseModel_invalid(t *testing.T) {
	if _, err := ParseModel([]byte("fake stdout")); err == nil {
		t.Error("expected error for non-JSON output")
	}
}

func TestHelpers(t *testing.T) {
	for v, want := range map[any]bool{nil: false, "": false, "x": true, 0.0: false, 1.0: true, true: true, false: false, 3: true} {
		if got := isSet(v); got != want {
			t.Errorf("isSet(%#v) = %v", v, got)
		}
	}
	if str(nil) != "" || str(1.0) != "1" {
		t.Error("str")
	}
	if l := asList("a"); len(l) != 1 {
		t.Error("asList scalar")
	}
}

// assertErrContains fails t unless err is nil when want is empty, or err's
// message contains want otherwise.
func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}
