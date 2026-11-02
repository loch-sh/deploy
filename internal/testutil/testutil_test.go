package testutil

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestFakeDocker(t *testing.T) {
	log := FakeDocker(t)

	if log.Calls() != nil {
		t.Fatal("expected no calls before docker is run")
	}

	out, err := exec.Command("docker", "compose", "pull").Output()
	if err != nil {
		t.Fatalf("fake docker: %v", err)
	}
	if strings.TrimSpace(string(out)) != "fake stdout" {
		t.Errorf("stdout = %q", out)
	}

	log.FailOn(t, "up")
	if err := exec.Command("docker", "compose", "up").Run(); err == nil {
		t.Error("expected failure on up")
	}

	calls := log.Calls()
	if len(calls) != 2 || calls[0] != "compose pull" || calls[1] != "compose up" {
		t.Errorf("calls = %q", calls)
	}
}

func TestFakeDockerContainers(t *testing.T) {
	log := FakeDocker(t)

	// Without fixtures, ps and inspect report no container.
	for _, sub := range []string{"ps", "inspect"} {
		if out, err := exec.Command("docker", sub).Output(); err != nil || len(out) != 0 {
			t.Errorf("docker %s = %q, %v; want empty output", sub, out, err)
		}
	}

	log.Containers(t, []string{"aaa", "bbb"}, `{"Id":"aaa"}`+"\n")
	if out, _ := exec.Command("docker", "ps", "-a").Output(); string(out) != "aaa\nbbb\n" {
		t.Errorf("ps = %q", out)
	}
	if out, _ := exec.Command("docker", "inspect", "aaa").Output(); string(out) != `{"Id":"aaa"}`+"\n" {
		t.Errorf("inspect = %q", out)
	}
	log.FailOn(t, "ps")
	if err := exec.Command("docker", "ps").Run(); err == nil {
		t.Error("expected failure on ps")
	}
	if calls := log.Calls(); len(calls) != 5 || calls[2] != "ps -a" {
		t.Errorf("calls = %q", calls)
	}
}

func TestIssuerToken(t *testing.T) {
	iss := NewIssuer(t)
	token := iss.Token(t, "aud", map[string]any{"project_id": "7"})

	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !strings.Contains(string(jws.UnsafePayloadWithoutVerification()), `"project_id":"7"`) {
		t.Errorf("payload missing custom claim")
	}
}

func TestIssuerEndpoints(t *testing.T) {
	iss := NewIssuer(t)

	for _, path := range []string{"/.well-known/openid-configuration", "/jwks"} {
		resp, err := http.Get(iss.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		var body map[string]any
		err = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if err != nil || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("GET %s: content-type %q, decode err %v", path, resp.Header.Get("Content-Type"), err)
		}
	}
}
