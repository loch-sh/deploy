package compose

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"deploy-server/internal/testutil"
)

// Container IDs used by the fixtures (docker ps --no-trunc prints 64 hex
// characters; short IDs are accepted too).
var (
	idLabelled = strings.Repeat("a", 64)
	idNamed    = strings.Repeat("b", 12)
	idOther    = strings.Repeat("c", 64)
)

const inspectFixture = `{"Id":"` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `","Name":"/app-staging-web-1","Labels":{"com.docker.compose.project":"app-staging"},"Mounts":[{"Type":"bind","Source":"/data/websites/app-staging","Destination":"/data","Mode":"","RW":true,"Propagation":"rprivate"},{"Type":"volume","Name":"v","Source":"/var/lib/docker/volumes/v/_data","Destination":"/v","Driver":"local","Mode":"z","RW":true,"Propagation":""}]}
{"Id":"bbbbbbbbbbbb","Name":"/app-staging_manual","Labels":null,"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":false}]}
{"Id":"` + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" + `","Name":"/app-staging-api-web-1","Labels":{"com.docker.compose.project":"app-staging-api"},"Mounts":[]}
`

func TestStackContainers_none(t *testing.T) {
	docker := testutil.FakeDocker(t)

	got, err := StackContainers(context.Background(), testKey)
	if err != nil || got != nil {
		t.Fatalf("StackContainers = %v, %v; want nothing", got, err)
	}
	want := []string{
		"ps --all --no-trunc --filter label=com.docker.compose.project=app-staging --format {{.ID}}",
		"ps --all --no-trunc --filter name=^/?app-staging[-_] --format {{.ID}}",
	}
	if calls := docker.Calls(); len(calls) != 2 || calls[0] != want[0] || calls[1] != want[1] {
		t.Errorf("calls = %q, want %q (and no inspect)", calls, want)
	}
}

func TestStackContainers_inspectsAndFilters(t *testing.T) {
	docker := testutil.FakeDocker(t)
	// Both ps filters report every ID: the union must be deduplicated.
	docker.Containers(t, []string{idLabelled, idNamed, idOther}, inspectFixture)

	got, err := StackContainers(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	// app-staging-api-web-1 is named after its own project (another stack
	// whose key extends app-staging): excluded. Sorted by name.
	if len(got) != 2 || got[0].Name != "app-staging-web-1" || got[1].Name != "app-staging_manual" {
		t.Fatalf("containers = %+v", got)
	}
	web := got[0]
	if web.ID != idLabelled || web.Project != testKey || len(web.Mounts) != 2 {
		t.Errorf("web = %+v", web)
	}
	if m := web.Mounts[0]; m.Type != "bind" || m.Source != "/data/websites/app-staging" || m.Destination != "/data" || !m.RW {
		t.Errorf("bind mount = %+v", m)
	}
	if m := got[1].Mounts[0]; got[1].Project != "" || m.RW || m.Source != "/var/run/docker.sock" {
		t.Errorf("manual container = %+v", got[1])
	}

	calls := docker.Calls()
	wantInspect := "inspect --type container --format " + inspectFormat + " -- " + idLabelled + " " + idNamed + " " + idOther
	if len(calls) != 3 || calls[2] != wantInspect {
		t.Errorf("calls = %q, want last %q", calls, wantInspect)
	}
}

func TestStackContainers_failures(t *testing.T) {
	tests := []struct {
		name    string
		failOn  string
		ids     []string
		inspect string
		want    string
	}{
		{"ps fails", "ps", nil, "", "docker ps: exit status 1"},
		{"inspect fails", "inspect", []string{idNamed}, "", "docker inspect: exit status 1"},
		{"unexpected ID", "", []string{"--format=x"}, "", "unexpected container ID"},
		{"unexpected inspect output", "", []string{idNamed}, "not json\n", "unexpected output"},
		{"container gone before inspect", "", []string{idLabelled, idNamed}, `{"Id":"bbbbbbbbbbbb","Name":"/x"}` + "\n", "2 containers listed, 1 inspected"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			docker := testutil.FakeDocker(t)
			if tc.ids != nil {
				docker.Containers(t, tc.ids, tc.inspect)
			}
			if tc.failOn != "" {
				docker.FailOn(t, tc.failOn)
			}
			got, err := StackContainers(context.Background(), testKey)
			if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Errorf("StackContainers = %v, %v; want error containing %q", got, err, tc.want)
			}
		})
	}

	t.Run("cancelled context", func(t *testing.T) {
		testutil.FakeDocker(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := StackContainers(ctx, testKey); !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
	})
}

func TestBelongsTo(t *testing.T) {
	for _, tc := range []struct {
		c    Container
		want bool
	}{
		{Container{Name: "x", Project: testKey}, true},
		{Container{Name: "app-staging-web"}, true},
		{Container{Name: "app-staging-web", Project: "legacy"}, true},
		{Container{Name: "app-staging-api-1", Project: "app-staging-api"}, false},
		{Container{Name: "app-staging_api_1", Project: "app-staging"}, true},
		{Container{Name: "app-staging_db_1", Project: "app"}, false},
		{Container{Name: "app-staging-db", Project: "app"}, false},
	} {
		if got := belongsTo(tc.c, testKey); got != tc.want {
			t.Errorf("belongsTo(%+v) = %v, want %v", tc.c, got, tc.want)
		}
	}
}

func TestRemoveContainers(t *testing.T) {
	t.Run("stops then removes", func(t *testing.T) {
		docker := testutil.FakeDocker(t)
		if _, err := RemoveContainers(context.Background(), []string{idLabelled, idNamed}); err != nil {
			t.Fatal(err)
		}
		want := []string{
			"stop --timeout 10 -- " + idLabelled + " " + idNamed,
			"rm --force -- " + idLabelled + " " + idNamed,
		}
		if calls := docker.Calls(); len(calls) != 2 || calls[0] != want[0] || calls[1] != want[1] {
			t.Errorf("calls = %q, want %q", calls, want)
		}
	})

	t.Run("stop failure is not fatal", func(t *testing.T) {
		docker := testutil.FakeDocker(t)
		docker.FailOn(t, "stop")
		out, err := RemoveContainers(context.Background(), []string{idNamed})
		if err != nil || !strings.Contains(out.Stderr, "fake failure on stop") {
			t.Errorf("RemoveContainers = %+v, %v", out, err)
		}
	})

	t.Run("rm failure", func(t *testing.T) {
		docker := testutil.FakeDocker(t)
		docker.FailOn(t, "rm")
		if _, err := RemoveContainers(context.Background(), []string{idNamed}); err == nil || !strings.Contains(err.Error(), "docker rm") {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("invalid ID or nothing to do", func(t *testing.T) {
		docker := testutil.FakeDocker(t)
		if _, err := RemoveContainers(context.Background(), []string{"-f"}); err == nil {
			t.Error("expected an error for an invalid ID")
		}
		if _, err := RemoveContainers(context.Background(), nil); err != nil {
			t.Error(err)
		}
		if docker.Calls() != nil {
			t.Errorf("docker must not be called: %q", docker.Calls())
		}
	})
}

func TestCheckBindSourcePath(t *testing.T) {
	websites := filepath.Join(t.TempDir(), testKey)
	if err := os.MkdirAll(filepath.Join(websites, "web", "storage"), 0o755); err != nil {
		t.Fatal(err)
	}
	must(t, os.WriteFile(filepath.Join(websites, "web", "file"), nil, 0o600))
	must(t, os.Symlink("/", filepath.Join(websites, "evil")))

	tests := []struct {
		name, src string
		want      error  // sentinel, or nil
		wantMsg   string // substring; "" with want == nil means allowed
	}{
		{"conforming", filepath.Join(websites, "web", "storage"), nil, ""},
		{"conforming, since removed", filepath.Join(websites, "gone", "data"), nil, ""},
		{"stack directory", websites, ErrBindLayout, ""},
		{"service directory", filepath.Join(websites, "web"), ErrBindLayout, ""},
		{"too deep", filepath.Join(websites, "web", "storage", "x"), ErrBindLayout, ""},
		{"outside", "/var/run/docker.sock", ErrBindOutside, ""},
		{"sibling stack", websites + "-prod/web/storage", ErrBindOutside, ""},
		{"symlinked service component", filepath.Join(websites, "evil", "etc"), nil, "is a symbolic link"},
		{"file", filepath.Join(websites, "web", "file"), nil, "is not a directory"},
		{"not clean", websites + "/web/../web/storage", nil, "clean absolute path"},
		{"relative", "web/storage", nil, "relative"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckBindSourcePath(tc.src, websites)
			switch {
			case tc.want != nil:
				if !errors.Is(err, tc.want) {
					t.Errorf("err = %v, want %v", err, tc.want)
				}
			case tc.wantMsg == "":
				if err != nil {
					t.Errorf("err = %v, want nil", err)
				}
			case err == nil || !strings.Contains(err.Error(), tc.wantMsg):
				t.Errorf("err = %v, want %q", err, tc.wantMsg)
			}
		})
	}

	if err := CheckBindSourcePath("/x/y", ""); !errors.Is(err, ErrBindOutside) {
		t.Errorf("no websites dir: err = %v", err)
	}
}

// must fails the test immediately when err is not nil.
func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
