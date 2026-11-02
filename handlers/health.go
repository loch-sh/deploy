package handlers

import "net/http"

// Health handles GET /health. It is intentionally unauthenticated and exempt
// from the IP allowlist so external uptime/load-balancer probes can reach it.
// It exposes no sensitive information.
func Health() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	}
}
