package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const keyID = "test-key"

// Issuer is a fake GitLab OIDC issuer: it serves the discovery document and the
// JWKS, and mints RS256-signed ID tokens.
type Issuer struct {
	URL    string
	signer jose.Signer
}

// NewIssuer starts a fake OIDC issuer for the duration of the test.
func NewIssuer(t *testing.T) *Issuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	iss := &Issuer{signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                iss.URL,
			"jwks_uri":                              iss.URL + "/jwks",
			"authorization_endpoint":                iss.URL + "/authorize",
			"token_endpoint":                        iss.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig"},
		}})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	iss.URL = srv.URL
	return iss
}

// Token mints a signed ID token for audience aud. Standard claims (iss, aud,
// sub, iat, exp) are filled in unless overridden in claims.
func (i *Issuer) Token(t *testing.T, aud string, claims map[string]any) string {
	t.Helper()

	now := time.Now()
	payload := map[string]any{
		"iss": i.URL,
		"aud": aud,
		"sub": "project_path:group/project:ref_type:branch:ref:main",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	maps.Copy(payload, claims)

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := i.signer.Sign(raw)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}
	return token
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
