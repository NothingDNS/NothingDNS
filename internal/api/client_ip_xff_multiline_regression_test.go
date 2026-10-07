package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/auth"
	"github.com/nothingdns/nothingdns/internal/config"
)

// TestClientIP_XFFMultipleFieldLines is the F262 regression: a trusted proxy
// that records the client in its own X-Forwarded-For field line (HAProxy
// `option forwardfor`) leaves a client-supplied line first. clientIP must treat
// all lines as one list (RFC 9110 §5.3) so the client cannot pick its own IP
// (e.g. "::1" to pass the localhost bootstrap gate, or rotating values to
// evade per-IP limits).
func TestClientIP_XFFMultipleFieldLines(t *testing.T) {
	tests := []struct {
		name    string
		trusted []string
		peer    string
		lines   []string
		xRealIP string
		want    string
	}{
		{"spoofed first line, proxy line second", []string{"127.0.0.1/32"}, "127.0.0.1:1", []string{"::1", "203.0.113.9"}, "", "203.0.113.9"},
		{"spoofed list line, proxy line second", []string{"127.0.0.1/32"}, "127.0.0.1:1", []string{"10.0.0.1, ::1", "203.0.113.9"}, "", "203.0.113.9"},
		{"chain across lines skips trusted hops", []string{"127.0.0.1/32", "10.0.0.0/8"}, "127.0.0.1:1", []string{"198.51.100.7", "10.1.2.3"}, "", "198.51.100.7"},
		{"single line unchanged", []string{"127.0.0.1/32"}, "127.0.0.1:1", []string{"::1, 203.0.113.9"}, "", "203.0.113.9"},
		{"all lines trusted falls back to X-Real-IP", []string{"127.0.0.1/32", "10.0.0.0/8"}, "127.0.0.1:1", []string{"10.0.0.1", "10.0.0.2"}, "192.0.2.50", "192.0.2.50"},
		{"untrusted peer ignores every line", []string{"10.0.0.0/8"}, "203.0.113.5:1", []string{"::1", "1.2.3.4"}, "", "203.0.113.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer(config.HTTPConfig{Enabled: true, TrustedProxies: tc.trusted}, nil, nil, nil, nil, nil, nil)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer
			for _, l := range tc.lines {
				req.Header.Add("X-Forwarded-For", l)
			}
			if tc.xRealIP != "" {
				req.Header.Set("X-Real-IP", tc.xRealIP)
			}
			if got := s.clientIP(req); got != tc.want {
				t.Errorf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestBootstrap_XFFMultipleFieldLinesCannotClaimLoopback checks the gate end
// to end: a remote client behind a loopback proxy that adds its own XFF line
// must get 403, not reach the bootstrap body (401 on a wrong old password).
func TestBootstrap_XFFMultipleFieldLinesCannotClaimLoopback(t *testing.T) {
	store := newAuthStoreWithUser(t, "alice", "correct-horse-1", auth.RoleAdmin)
	s := NewServer(config.HTTPConfig{Enabled: true, TrustedProxies: []string{"127.0.0.1/32"}}, nil, nil, nil, nil, nil, nil)
	s.authStore = store
	for _, spoof := range []string{"::1", "127.0.0.1"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/bootstrap",
			strings.NewReader(`{"username":"alice","password":"new-password-1","old_password":"wrong"}`))
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Add("X-Forwarded-For", spoof)
		req.Header.Add("X-Forwarded-For", "203.0.113.9")
		rec := httptest.NewRecorder()
		s.handleBootstrap(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("spoofed XFF line %q: bootstrap status = %d, want 403", spoof, rec.Code)
		}
	}
}
