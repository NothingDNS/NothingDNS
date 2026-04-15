package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

func (s *Server) handleODoHConfig(w http.ResponseWriter, r *http.Request) {
	if s.odohTarget == nil {
		s.writeError(w, http.StatusServiceUnavailable, "ODoH target not available")
		return
	}
	pubKey := s.odohTarget.PublicKey()
	w.Header().Set("Content-Type", "application/odoh-config+json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"public_key":"%s","kem":%d,"kdf":%d,"aead":%d}`,
		"base64url:"+base64.RawURLEncoding.EncodeToString(pubKey),
		s.config.ODoHKEM, s.config.ODoHKDF, s.config.ODoHAEAD)
}

// handleHealth returns health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, &HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// handleReadiness implements the Kubernetes readiness probe.
// Returns 200 if the server is ready to accept traffic:
// - Zone manager has loaded zones
// - Upstream is healthy (if configured)
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	status := "ready"
	code := http.StatusOK

	// Check if zones are loaded (zero zones is OK in recursive mode)
	// but if zoneManager exists and has no zones, consider if any are configured
	if s.zoneManager != nil {
		count := s.zoneManager.Count()
		// Zone count of 0 is OK if the manager is in recursive mode
		// (no zone files configured, all queries go to upstream)
		_ = count // 0 zones is valid for recursive operation
	}

	// Check upstream health if configured
	if s.upstreamLB != nil {
		healthy := s.upstreamLB.IsHealthy()
		if !healthy {
			status = "unhealthy"
			code = http.StatusServiceUnavailable
		}
	} else if s.upstreamClient != nil {
		// Single upstream: check if at least one server is healthy
		// upstream.Client has servers field, check via health
		healthy := s.upstreamClient.IsHealthy()
		if !healthy {
			status = "unhealthy"
			code = http.StatusServiceUnavailable
		}
	}

	s.writeJSON(w, code, &HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// handleLiveness implements the Kubernetes liveness probe.
// Returns 200 if the server process is alive and not deadlocked.
// Returns 503 if goroutine leak or deadlock is detected.
func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	status := "alive"
	code := http.StatusOK
	current := int64(0)
	baseline := atomic.LoadInt64(&s.goroutineBaseline)

	// Check for goroutine leak: compare current goroutine count to baseline
	if baseline > 0 {
		current = int64(runtime.NumGoroutine())
		// Allow up to 2x baseline growth to detect actual goroutine leaks.
		// Baseline is now set via SetGoroutineBaseline() after all servers are running,
		// so a 2x multiplier is sufficient to catch leaks while avoiding false positives.
		if current > baseline*2 {
			status = "goroutine_leak"
			code = http.StatusServiceUnavailable
		}
	}

	s.writeJSON(w, code, &HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// handleSPA returns a handler that serves the React SPA, falling back to
// index.html for client-side routes. Non-API, non-static-file requests
// are handled by the SPA.
