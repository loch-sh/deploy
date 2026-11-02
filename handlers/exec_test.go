package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func (e *testEnv) execHandler() http.Handler {
	return Exec(ExecConfig{ComposeBase: e.composeBase, Registry: e.reg})
}

func decodeExecResponse(t *testing.T, body string) execResponse {
	t.Helper()
	var resp execResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	return resp
}

func TestExec_success(t *testing.T) {
	e := newTestEnv(t)
	e.claimTestStack(t)

	r := jsonRequest("POST", "/exec", `{"service":"api","command":["php","bin/console","app:install","acme"]}`)
	rec := serve(e.execHandler(), r, defaultClaims())
	assertStatus(t, rec, http.StatusOK)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	resp := decodeExecResponse(t, rec.Body.String())
	if strings.TrimSpace(resp.Stdout) != "fake stdout" || strings.TrimSpace(resp.Stderr) != "fake stderr" {
		t.Errorf("response = %+v", resp)
	}

	want := pinnedArgs(e.stackDir()) + "exec -T api php bin/console app:install acme"
	if calls := e.docker.Calls(); len(calls) != 1 || calls[0] != want {
		t.Errorf("docker calls = %q, want %q", calls, want)
	}
}

func TestExec_nonZeroExitReturns422WithOutput(t *testing.T) {
	e := newTestEnv(t)
	e.claimTestStack(t)
	e.docker.FailOn(t, "exec")

	r := jsonRequest("POST", "/exec", `{"service":"api","command":["false"]}`)
	rec := serve(e.execHandler(), r, defaultClaims())
	assertStatus(t, rec, http.StatusUnprocessableEntity)

	if resp := decodeExecResponse(t, rec.Body.String()); !strings.Contains(resp.Stderr, "fake failure on exec") {
		t.Errorf("stderr not returned: %+v", resp)
	}
}

func TestExec_rejections(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"invalid JSON", `{`, http.StatusBadRequest},
		{"invalid service", `{"service":"../api","command":["ls"]}`, http.StatusBadRequest},
		{"empty command", `{"service":"api","command":[]}`, http.StatusBadRequest},
		{"body over 1 MiB", `{"service":"api","command":["` + strings.Repeat("x", maxJSONBody) + `"]}`, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			assertStatus(t, serve(e.execHandler(), jsonRequest("POST", "/exec", tc.body), defaultClaims()), tc.want)
			if e.docker.Calls() != nil {
				t.Error("docker must not be called")
			}
		})
	}

	t.Run("no claims", func(t *testing.T) {
		e := newTestEnv(t)
		r := jsonRequest("POST", "/exec", `{"service":"api","command":["ls"]}`)
		assertStatus(t, serve(e.execHandler(), r, nil), http.StatusUnauthorized)
	})

	t.Run("owned by another project", func(t *testing.T) {
		e := newTestEnv(t)
		e.reg.Claim("group-app", "staging", "99")
		r := jsonRequest("POST", "/exec", `{"service":"api","command":["ls"]}`)
		assertStatus(t, serve(e.execHandler(), r, defaultClaims()), http.StatusForbidden)
	})
}

func TestExec_cancelledOrTimedOut(t *testing.T) {
	t.Run("request cancelled", func(t *testing.T) {
		e := newTestEnv(t)
		e.claimTestStack(t)
		r := cancelledRequest(jsonRequest("POST", "/exec", `{"service":"api","command":["ls"]}`))
		rec := serve(e.execHandler(), r, defaultClaims())
		assertStatus(t, rec, http.StatusServiceUnavailable)
		decodeExecResponse(t, rec.Body.String())
		if e.docker.Calls() != nil {
			t.Error("docker must not be called for a cancelled request")
		}
	})

	t.Run("deadline exceeded", func(t *testing.T) {
		e := newTestEnv(t)
		e.claimTestStack(t)
		ctx, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		r := jsonRequest("POST", "/exec", `{"service":"api","command":["ls"]}`).WithContext(ctx)
		assertStatus(t, serve(e.execHandler(), r, defaultClaims()), http.StatusGatewayTimeout)
	})

	t.Run("not claimed", func(t *testing.T) {
		e := newTestEnv(t)
		r := jsonRequest("POST", "/exec", `{"service":"api","command":["ls"]}`)
		assertStatus(t, serve(e.execHandler(), r, defaultClaims()), http.StatusForbidden)
	})
}
