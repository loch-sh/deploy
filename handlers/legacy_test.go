package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deploy-server/registry"
)

const (
	legacyID  = "0123456789ab0123456789ab0123456789ab0123456789ab0123456789ab0123"
	legacyID2 = "fedcba987654"
)

// inspectLine renders one docker inspect line (compose.StackContainers'
// format) for a container of testKey with the given Mounts JSON array.
func inspectLine(id, name, mounts string) string {
	return fmt.Sprintf(`{"Id":%q,"Name":"/%s","Labels":{"com.docker.compose.project":%q},"Mounts":%s}`+"\n", id, name, testKey, mounts)
}

// bindMount renders a bind mount entry of docker inspect's Mounts.
func bindMount(src, dst string) string {
	return fmt.Sprintf(`{"Type":"bind","Source":%q,"Destination":%q,"Mode":"","RW":true,"Propagation":"rprivate"}`, src, dst)
}

// withContainer makes the fake docker report one existing container of
// testKey with the given mounts.
func (e *testEnv) withContainer(t *testing.T, mounts ...string) {
	t.Helper()
	e.docker.Containers(t, []string{legacyID}, inspectLine(legacyID, testKey+"-web-1", "["+strings.Join(mounts, ",")+"]"))
}

func TestDeploy_existingContainers(t *testing.T) {
	allowed := []struct {
		name   string
		mounts func(e *testEnv) []string
	}{
		{"conforming bind", func(e *testEnv) []string {
			src := filepath.Join(e.websitesBase, testKey, "web", "storage")
			os.MkdirAll(src, 0o755)
			return []string{bindMount(src, "/s")}
		}},
		{"named volume and tmpfs", func(e *testEnv) []string {
			return []string{
				`{"Type":"volume","Name":"group-app-staging_db","Source":"/var/lib/docker/volumes/group-app-staging_db/_data","Destination":"/db","Driver":"local","RW":true}`,
				`{"Type":"tmpfs","Source":"","Destination":"/tmp","RW":true}`,
			}
		}},
		{"no mounts", func(*testEnv) []string { return nil }},
	}
	for _, tc := range allowed {
		t.Run(tc.name, func(t *testing.T) {
			e := newDeployEnv(t)
			e.withContainer(t, tc.mounts(e)...)
			r := multipartRequest(t, "/deploy", []upload{composeUpload}, nil)
			assertStatus(t, serve(e.deploy(), r, defaultClaims()), http.StatusNoContent)
			if calls := e.docker.Calls(); len(calls) < 3 || !strings.HasPrefix(calls[2], "inspect ") {
				t.Errorf("docker calls = %q, want ps, ps, inspect first", calls)
			}
		})
	}

	refused := []struct {
		name  string
		src   func(e *testEnv) string
		dst   string
		want  string
		leaks string // must not appear in the body
	}{
		{"bind on the stack directory", func(e *testEnv) string { return filepath.Join(e.websitesBase, testKey) },
			"/data", `source \"group-app-staging/\" is not at the <service>/<name> depth`, ""},
		{"bind on a service directory", func(e *testEnv) string { return filepath.Join(e.websitesBase, testKey, "web") },
			"/data", `source \"group-app-staging/web\" is not at the <service>/<name> depth`, ""},
		{"bind outside WEBSITES_BASE", func(*testEnv) string { return "/var/run/docker.sock" },
			"/var/run/docker.sock", "source outside the stack data directory", ""},
		{"bind on another stack", func(e *testEnv) string { return filepath.Join(e.websitesBase, "other-prod", "web", "storage") },
			"/s", "source outside the stack data directory", "other-prod"},
		{"symlinked service component", func(e *testEnv) string {
			d := filepath.Join(e.websitesBase, testKey)
			os.MkdirAll(d, 0o755)
			os.Symlink("/", filepath.Join(d, "evil"))
			return filepath.Join(d, "evil", "etc")
		}, "/etc", `source \"group-app-staging/evil/etc\": bind source component \"evil\" is a symbolic link`, ""},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			e := newDeployEnv(t)
			e.withContainer(t, bindMount(tc.src(e), tc.dst))
			// A previous deploy left files the refused one must not touch.
			os.MkdirAll(e.stackDir(), 0o700)
			os.WriteFile(filepath.Join(e.stackDir(), "docker-compose.yml"), []byte("previous"), 0o600)

			rec := serve(e.deploy(), multipartRequest(t, "/deploy", []upload{composeUpload}, nil), defaultClaims())
			assertStatus(t, rec, http.StatusConflict)
			body := fmt.Sprintf("%q", rec.Body.String())
			for _, want := range []string{tc.want, `container \"group-app-staging-web-1\"`, `target \"` + tc.dst + `\"`, "DELETE /stack"} {
				if !strings.Contains(body, want) {
					t.Errorf("body = %s, want %q", body, want)
				}
			}
			if strings.Contains(body, e.websitesBase) || (tc.leaks != "" && strings.Contains(body, tc.leaks)) {
				t.Errorf("body leaks a server path: %s", body)
			}

			if calls := composeCalls(e.docker.Calls()); calls != nil {
				t.Errorf("nothing but the inspection may run: %q", calls)
			}
			if got, _ := os.ReadFile(filepath.Join(e.stackDir(), "docker-compose.yml")); string(got) != "previous" {
				t.Errorf("previous compose file was modified: %q", got)
			}
			e.assertNoStaging(t)
			if err := e.reg.Verify("group-app", "staging", "1"); !errors.Is(err, registry.ErrNotClaimed) {
				t.Errorf("a refused deploy must not claim the stack: %v", err)
			}
		})
	}
}

func TestDeploy_existingContainersReportCap(t *testing.T) {
	e := newDeployEnv(t)
	mounts := make([]string, maxReportedLegacyMounts+3)
	for i := range mounts {
		mounts[i] = bindMount(fmt.Sprintf("/host/%d", i), fmt.Sprintf("/m%d", i))
	}
	e.withContainer(t, mounts...)

	rec := serve(e.deploy(), multipartRequest(t, "/deploy", []upload{composeUpload}, nil), defaultClaims())
	assertStatus(t, rec, http.StatusConflict)
	if body := rec.Body.String(); !strings.Contains(body, "… and 3 more") || strings.Contains(body, `"/m20"`) {
		t.Errorf("body = %q", body)
	}
}

func TestDeploy_inspectionFailure(t *testing.T) {
	for _, word := range []string{"ps", "inspect"} {
		t.Run(word, func(t *testing.T) {
			e := newDeployEnv(t)
			e.withContainer(t)
			e.docker.FailOn(t, word)

			rec := serve(e.deploy(), multipartRequest(t, "/deploy", []upload{composeUpload}, nil), defaultClaims())
			assertStatus(t, rec, http.StatusInternalServerError)
			if !strings.Contains(rec.Body.String(), "failed to inspect the stack's existing containers") {
				t.Errorf("body = %q", rec.Body.String())
			}
			if calls := composeCalls(e.docker.Calls()); calls != nil {
				t.Errorf("deploy must stop after a failed inspection: %q", calls)
			}
		})
	}
}

func TestCheckExistingMounts_contextErrors(t *testing.T) {
	st := stack{Key: testKey}

	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	if code, msg := checkExistingMounts(expired, st, "/w"); code != http.StatusGatewayTimeout || !strings.Contains(msg, "gateway timeout") {
		t.Errorf("expired context: %d %q, want 504", code, msg)
	}

	cancelled, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if code, _ := checkExistingMounts(cancelled, st, "/w"); code != http.StatusServiceUnavailable {
		t.Errorf("cancelled context: code = %d, want 503", code)
	}
}

func TestDeploy_auditsLegacyMounts(t *testing.T) {
	e := newDeployEnv(t)
	e.withContainer(t, bindMount("/var/run/docker.sock", "/var/run/docker.sock"))

	entry := auditedEntry(t, e.deploy(), multipartRequest(t, "/deploy", []upload{composeUpload}, nil))
	got, _ := entry["legacy_mounts"].([]any)
	if entry["status"] != float64(http.StatusConflict) || len(got) != 1 {
		t.Fatalf("entry = %v", entry)
	}
	m, _ := got[0].(map[string]any)
	if m["container"] != testKey+"-web-1" || m["target"] != "/var/run/docker.sock" || m["source"] != "/var/run/docker.sock" || m["rw"] != true {
		t.Errorf("legacy_mounts = %v", got)
	}
}

func TestStop_legacyStackWithoutComposeFile(t *testing.T) {
	e := newTestEnv(t)
	// Imported into the registry, but never deployed by this server: no
	// compose file in COMPOSE_BASE/<key>/.
	if err := e.reg.Claim("group-app", "staging", "1"); err != nil {
		t.Fatal(err)
	}
	e.docker.Containers(t, []string{legacyID, legacyID2},
		inspectLine(legacyID, testKey+"-web-1", "[]")+inspectLine(legacyID2, testKey+"_db_1", "[]"))

	assertStatus(t, serve(e.stopHandler(), stopRequest(), defaultClaims()), http.StatusNoContent)

	ids := legacyID + " " + legacyID2
	want := []string{psCalls()[0], psCalls()[1], "", "stop --timeout 10 -- " + ids, "rm --force -- " + ids}
	calls := e.docker.Calls()
	if len(calls) != len(want) || calls[0] != want[0] || calls[1] != want[1] || !strings.HasPrefix(calls[2], "inspect ") ||
		calls[3] != want[3] || calls[4] != want[4] {
		t.Errorf("docker calls = %q, want ps, ps, inspect, %q, %q", calls, want[3], want[4])
	}
	if _, ok := e.reg.Lookup("group-app", "staging"); ok {
		t.Error("registry entry should be released")
	}
}

func TestStop_leftoverContainersAfterDown(t *testing.T) {
	e := newTestEnv(t)
	e.seedStack(t)
	e.docker.Containers(t, []string{legacyID2}, inspectLine(legacyID2, testKey+"-manual", "[]"))

	assertStatus(t, serve(e.stopHandler(), stopRequest(), defaultClaims()), http.StatusNoContent)
	calls := e.docker.Calls()
	if len(calls) != 6 || !strings.HasSuffix(calls[0], " down --remove-orphans") || calls[5] != "rm --force -- "+legacyID2 {
		t.Errorf("docker calls = %q", calls)
	}
}

func TestStop_leftoverContainerFailures(t *testing.T) {
	for _, word := range []string{"ps", "rm"} {
		t.Run(word, func(t *testing.T) {
			e := newTestEnv(t)
			e.seedStack(t)
			e.docker.Containers(t, []string{legacyID2}, inspectLine(legacyID2, testKey+"-manual", "[]"))
			e.docker.FailOn(t, word)

			assertStatus(t, serve(e.stopHandler(), stopRequest(), defaultClaims()), http.StatusInternalServerError)
			if _, err := os.Stat(e.stackDir()); err != nil {
				t.Error("stack dir must be kept when the stack could not be fully removed")
			}
			if _, ok := e.reg.Lookup("group-app", "staging"); !ok {
				t.Error("ownership must be kept when the stack could not be fully removed")
			}
		})
	}
}
