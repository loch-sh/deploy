package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func cidrs(t *testing.T, items ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, s := range items {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		} else {
			ip := net.ParseIP(s)
			if ip == nil {
				t.Fatalf("bad test cidr/ip %q", s)
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
		}
	}
	return out
}

// run sends a request through IPAllowlist and returns the status code.
func run(allowed, proxies []*net.IPNet, remoteAddr, xff string) int {
	h := IPAllowlist(allowed, proxies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest("POST", "/deploy", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

func TestIPAllowlist(t *testing.T) {
	gitlab := "203.0.113.10"
	allowed := cidrs(t, gitlab)
	proxies := cidrs(t, "10.0.0.0/8") // Traefik on the docker network

	t.Run("disabled when allowlist empty", func(t *testing.T) {
		if code := run(nil, proxies, "198.51.100.1:1234", ""); code != http.StatusNoContent {
			t.Errorf("empty allowlist should allow all, got %d", code)
		}
	})

	t.Run("direct peer in allowlist", func(t *testing.T) {
		if code := run(allowed, nil, gitlab+":1234", ""); code != http.StatusNoContent {
			t.Errorf("allowed direct peer should pass, got %d", code)
		}
	})

	t.Run("direct peer not in allowlist", func(t *testing.T) {
		if code := run(allowed, proxies, "198.51.100.1:1234", ""); code != http.StatusForbidden {
			t.Errorf("non-allowed peer should be forbidden, got %d", code)
		}
	})

	t.Run("via trusted proxy with allowed XFF", func(t *testing.T) {
		// Peer is Traefik (trusted); real client (GitLab) is in XFF.
		if code := run(allowed, proxies, "10.0.0.5:1234", gitlab); code != http.StatusNoContent {
			t.Errorf("trusted proxy forwarding allowed client should pass, got %d", code)
		}
	})

	t.Run("via trusted proxy with disallowed XFF", func(t *testing.T) {
		if code := run(allowed, proxies, "10.0.0.5:1234", "198.51.100.1"); code != http.StatusForbidden {
			t.Errorf("trusted proxy forwarding non-allowed client should be forbidden, got %d", code)
		}
	})

	t.Run("spoofed XFF from untrusted peer is ignored", func(t *testing.T) {
		// Attacker connects directly (not via a trusted proxy) and forges XFF
		// claiming to be GitLab. The header must be ignored; peer IP decides.
		if code := run(allowed, proxies, "198.51.100.1:1234", gitlab); code != http.StatusForbidden {
			t.Errorf("spoofed XFF must not bypass the allowlist, got %d", code)
		}
	})

	t.Run("rightmost non-proxy is chosen in a chain", func(t *testing.T) {
		// XFF: client, then an extra hop. Real client is GitLab, last hop a proxy.
		if code := run(allowed, proxies, "10.0.0.5:1234", gitlab+", 10.0.0.9"); code != http.StatusNoContent {
			t.Errorf("rightmost non-proxy should resolve to GitLab, got %d", code)
		}
	})
}

// runXFF is run with several X-Forwarded-For header lines.
func runXFF(allowed, proxies []*net.IPNet, remoteAddr string, xff ...string) int {
	h := IPAllowlist(allowed, proxies)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest("POST", "/deploy", nil)
	r.RemoteAddr = remoteAddr
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code
}

func TestIPAllowlist_xffHardening(t *testing.T) {
	gitlab := "203.0.113.10"
	allowed := cidrs(t, gitlab, "2001:db8::10/128")
	proxies := cidrs(t, "10.0.0.0/8")
	const peer = "10.0.0.5:1234"

	tests := []struct {
		name string
		xff  []string
		want int
	}{
		{"multiple header lines: last line wins", []string{gitlab, "198.51.100.1"}, http.StatusForbidden},
		{"multiple header lines: client spoof on first line ignored", []string{"198.51.100.1", gitlab}, http.StatusNoContent},
		{"multiple header lines with proxy hop", []string{gitlab, "10.0.0.9"}, http.StatusNoContent},
		{"garbage on the right refuses instead of skipping left", []string{gitlab + ", garbage"}, http.StatusForbidden},
		{"garbage line on the right refuses", []string{gitlab, "garbage"}, http.StatusForbidden},
		{"empty entry on the right refuses", []string{gitlab + ","}, http.StatusForbidden},
		{"garbage left of the client is irrelevant", []string{"garbage, " + gitlab}, http.StatusNoContent},
		{"ipv4 with port", []string{gitlab + ":5555"}, http.StatusNoContent},
		{"ipv6 with port", []string{"[2001:db8::10]:443"}, http.StatusNoContent},
		{"bare ipv6", []string{"2001:db8::10"}, http.StatusNoContent},
		{"disallowed ip with port", []string{"198.51.100.1:5555"}, http.StatusForbidden},
		{"only proxies falls back to peer", []string{"10.0.0.7, 10.0.0.8"}, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if code := runXFF(allowed, proxies, peer, tc.xff...); code != tc.want {
				t.Errorf("status = %d, want %d", code, tc.want)
			}
		})
	}

	t.Run("unparsable peer is refused", func(t *testing.T) {
		if code := runXFF(allowed, proxies, "not-an-addr"); code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", code)
		}
	})
}

func TestParseXFFEntry(t *testing.T) {
	cases := map[string]string{
		"203.0.113.10":       "203.0.113.10",
		"203.0.113.10:80":    "203.0.113.10",
		"[2001:db8::1]:8080": "2001:db8::1",
		"2001:db8::1":        "2001:db8::1",
		"":                   "",
		"unknown":            "",
		"host.example:80":    "",
		"[2001:db8::1]":      "",
	}
	for in, want := range cases {
		got := parseXFFEntry(in)
		if (got == nil && want != "") || (got != nil && got.String() != want) {
			t.Errorf("parseXFFEntry(%q) = %v, want %q", in, got, want)
		}
	}
}
