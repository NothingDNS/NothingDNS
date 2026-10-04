package api

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/util"
)

// rateLimitMiddleware applies per-IP rate limiting before auth runs.
// This ensures that unauthenticated scan/brute-force attempts also consume
// rate-limit budget (VULN-055). Rate-limited responses use writeErrorJSON
// for consistent JSON shape.
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply rate limit to all /api/ requests regardless of auth status.
		// DoWS has its own in-path rate limit (see authMiddleware).
		if strings.HasPrefix(r.URL.Path, "/api/") {
			ip := s.clientIP(r)
			if s.apiRateLimiter.checkRateLimit(ip) {
				resetTime := s.apiRateLimiter.getResetTime(ip)
				w.Header().Set("Retry-After", retryAfterSeconds(resetTime))
				writeErrorJSON(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs every HTTP request: method, path, status, latency.
// Management/API requests log at Info; health probes and the DNS query
// transports (DoH/DoWS/ODoH/dashboard-WS) log at Debug — those carry
// per-query traffic and would otherwise flood the log at query rate on a
// resolver taking real DoH load.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		latency := time.Since(start)
		status := wrapped.status
		path := r.URL.Path
		if s.isHotPathRequest(path) {
			util.Debugf("%s %s %d %v", r.Method, path, status, latency)
		} else {
			util.Infof("%s %s %d %v", r.Method, path, status, latency)
		}
	})
}

// isHotPathRequest reports whether a path is a health probe or a DNS query
// transport — i.e. request classes that arrive at traffic rate and must not
// be logged at Info.
func (s *Server) isHotPathRequest(path string) bool {
	switch path {
	case "/health", "/livez", "/readyz", "/ws":
		return true
	}
	if s.config.DoHPath != "" && path == s.config.DoHPath {
		return true
	}
	if s.config.DoWSPath != "" && path == s.config.DoWSPath {
		return true
	}
	if s.config.ODoHPath != "" && path == s.config.ODoHPath {
		return true
	}
	return false
}

// statusRecorder wraps http.ResponseWriter to capture the actual status code
// written, since the status may be set after the call to WriteHeader.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		r.ResponseWriter.WriteHeader(code)
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}
