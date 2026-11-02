package middleware

import (
	"net"
	"net/http"
	"slices"
	"strings"
)

// IPAllowlist restricts access to a set of allowed networks. The real client IP
// is resolved with care for reverse proxies:
//
//   - The direct socket peer (RemoteAddr) is the starting point.
//   - If that peer is one of the trustedProxies, the client IP is taken from the
//     X-Forwarded-For header instead — specifically the right-most address that
//     is not itself a trusted proxy. This is the only case where the header is
//     trusted, which prevents a direct attacker from spoofing X-Forwarded-For.
//     All X-Forwarded-For header lines are considered, in order. An entry that
//     cannot be parsed while walking from the right makes the client IP
//     unresolvable and the request is refused: skipping it would hand the
//     decision to an entry further left, which the client controls.
//   - Otherwise the socket peer address is used as-is.
//
// When allowed is empty the middleware is a no-op (allowlist disabled).
func IPAllowlist(allowed, trustedProxies []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(allowed) == 0 {
			return next // disabled
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r, trustedProxies)
			if ip == nil || !ipInAny(ip, allowed) {
				// Logged by the Audit middleware (status 403 + client_ip).
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP resolves the effective client IP for r, honouring trusted proxies.
// It returns nil when the IP cannot be resolved safely.
func clientIP(r *http.Request, trustedProxies []*net.IPNet) net.IP {
	peer := peerIP(r.RemoteAddr)
	if peer == nil {
		return nil
	}
	// Only consult X-Forwarded-For when the direct peer is a trusted proxy.
	if !ipInAny(peer, trustedProxies) {
		return peer
	}
	// Walk X-Forwarded-For right-to-left, returning the first non-proxy address
	// (the closest real client the proxy chain reported). Multiple header lines
	// are equivalent to one comma-joined list (RFC 9110 §5.3).
	entries := splitXFF(strings.Join(r.Header.Values("X-Forwarded-For"), ","))
	for _, raw := range slices.Backward(entries) {
		ip := parseXFFEntry(raw)
		if ip == nil {
			// Unparsable hop: refuse rather than trust what lies to its left.
			return nil
		}
		if !ipInAny(ip, trustedProxies) {
			return ip
		}
	}
	// Header absent or only proxies in it: fall back to the peer.
	return peer
}

// parseXFFEntry parses one X-Forwarded-For entry: a bare IPv4/IPv6 address, or
// the "ip:port" / "[ipv6]:port" forms some proxies emit. It returns nil for
// anything else (including an empty entry).
func parseXFFEntry(s string) net.IP {
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// peerIP extracts the IP from a "host:port" RemoteAddr.
func peerIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // no port present
	}
	return net.ParseIP(host)
}

func splitXFF(h string) []string {
	if h == "" {
		return nil
	}
	parts := strings.Split(h, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
