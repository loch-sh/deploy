package middleware

import (
	"context"
	"encoding/json"
	"testing"
)

func TestFlexBool(t *testing.T) {
	cases := map[string]bool{
		`"true"`:  true, // GitLab serialises ref_protected as a string
		`"false"`: false,
		`true`:    true, // tolerate a real JSON boolean too
		`false`:   false,
		`""`:      false,
		`"TRUE"`:  false, // strict: only lowercase "true" is truthy
	}
	for raw, want := range cases {
		var b flexBool
		if err := json.Unmarshal([]byte(raw), &b); err != nil {
			t.Fatalf("unmarshal %s: %v", raw, err)
		}
		if bool(b) != want {
			t.Errorf("flexBool(%s) = %v, want %v", raw, bool(b), want)
		}
	}
}

func TestClaimsRoundTripThroughContext(t *testing.T) {
	want := &Claims{ProjectPath: "g/p", ProjectID: "7", Environment: "staging", RefProtected: true}
	ctx := ContextWithClaims(context.Background(), want)

	got, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("claims not found in context")
	}
	if got != want {
		t.Errorf("claims pointer mismatch")
	}

	if _, ok := ClaimsFromContext(context.Background()); ok {
		t.Error("expected no claims in a bare context")
	}
}
