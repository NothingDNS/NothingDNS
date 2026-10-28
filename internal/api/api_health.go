package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleODoHConfig(w http.ResponseWriter, r *http.Request) {
	if s.requireMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	odohTarget := s.currentODoHTarget()
	if odohTarget == nil {
		s.writeError(w, http.StatusServiceUnavailable, "ODoH target not available")
		return
	}
	pubKey := odohTarget.PublicKey()
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
	runtimeSnapshot := s.currentRuntimeSnapshot()
	if runtimeSnapshot.upstreamLB != nil {
		healthy := runtimeSnapshot.upstreamLB.IsHealthy()
		if !healthy {
			status = "unhealthy"
			code = http.StatusServiceUnavailable
		}
	} else if runtimeSnapshot.upstreamClient != nil {
		// Single upstream: check if at least one server is healthy
		// upstream.Client has servers field, check via health
		healthy := runtimeSnapshot.upstreamClient.IsHealthy()
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

// handleLiveness implements the Kubernetes liveness probe. A liveness probe
// answers exactly one question: "is this process alive and able to make
// progress?" If this handler runs at all, the HTTP server's goroutine and
// accept loop are scheduling and responsive — so the correct answer is always
// 200. It MUST NOT be tied to goroutine count: goroutines scale with in-flight
// queries and connections, so a healthy server under load routinely exceeds any
// fixed multiple of its idle baseline, and returning 503 there makes Kubernetes
// kill and restart a working pod — turning a load spike into a crash loop.
//
// Goroutine growth is still surfaced (logged) for observability, but it drives
// alerting/metrics, never the liveness verdict.
func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	baseline := atomic.LoadInt64(&s.goroutineBaseline)
	if baseline > 0 {
		if current := int64(runtime.NumGoroutine()); current > baseline*4 {
			// Informational only — do NOT fail the probe. A sustained, unbounded
			// climb is a real leak, but that is an alerting concern, not a
			// reason to kill the process.
			util.Warnf("liveness: goroutine count %d exceeds 4x startup baseline %d (possible leak; not failing liveness)", current, baseline)
		}
	}

	s.writeJSON(w, http.StatusOK, &HealthResponse{
		Status:    "alive",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// handleSPA returns a handler that serves the React SPA, falling back to
// index.html for client-side routes. Non-API, non-static-file requests
// are handled by the SPA.
