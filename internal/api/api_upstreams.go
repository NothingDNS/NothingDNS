package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/nothingdns/nothingdns/internal/util"
)

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.requireOperator(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.runtimeMu.RLock()
		upstreamLB := s.upstreamLB
		upstreamClient := s.upstreamClient
		s.runtimeMu.RUnlock()

		var upstreams []UpstreamStatus
		if upstreamLB != nil {
			queries, failed, failovers := upstreamLB.Stats()
			upstreams = append(upstreams, UpstreamStatus{
				Address:   "load-balancer",
				Healthy:   upstreamLB.IsHealthy(),
				Queries:   queries,
				Failed:    failed,
				Failovers: failovers,
			})
		}
		if upstreamClient != nil {
			queries, failed, _ := upstreamClient.Stats()
			upstreams = append(upstreams, UpstreamStatus{
				Address: "direct-upstream",
				Healthy: upstreamClient.IsHealthy(),
				Queries: queries,
				Failed:  failed,
			})
		}
		s.writeJSON(w, http.StatusOK, &UpstreamsResponse{Upstreams: upstreams})
	case http.MethodPut:
		// Swapping the upstream lets an operator MITM every recursive query
		// served by this resolver — admin-only (VULN-009).
		if s.requireAdmin(w, r) {
			return
		}
		// Update upstream configuration (add/remove servers)
		var req UpstreamUpdateRequest
		if !s.decode(w, r, &req) {
			return
		}

		switch req.Action {
		case "add":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			// Validate upstream server is not a private/internal IP (SSRF protection)
			// and pin the resolved IP to prevent DNS rebinding TOCTOU.
			pinnedAddr, err := validateAndPinUpstream(req.Server)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, sanitizeError(err, "Invalid upstream address"))
				return
			}
			s.runtimeMu.RLock()
			upstreamClient := s.upstreamClient
			s.runtimeMu.RUnlock()
			if upstreamClient == nil {
				s.writeError(w, http.StatusServiceUnavailable, "Upstream client not configured")
				return
			}
			if err := upstreamClient.AddServer(pinnedAddr); err != nil {
				s.writeError(w, http.StatusConflict, sanitizeError(err, "Operation failed"))
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server added: " + pinnedAddr + " (resolved from " + req.Server + ")"})

		case "remove":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			s.runtimeMu.RLock()
			upstreamClient := s.upstreamClient
			s.runtimeMu.RUnlock()
			if upstreamClient == nil {
				s.writeError(w, http.StatusServiceUnavailable, "Upstream client not configured")
				return
			}
			if err := upstreamClient.RemoveServer(req.Server); err != nil {
				s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server removed: " + req.Server})

		default:
			s.writeError(w, http.StatusBadRequest, "Invalid action: must be 'add' or 'remove'")
		}
	}
}

// validateAndPinUpstream validates that an upstream server address does not
// resolve to a private/internal IP address, then returns a pinned address that
// uses a resolved IP literal instead of a hostname. This closes the DNS
// rebinding TOCTOU gap: without pinning, a hostname resolves to a public IP at
// validation time but could be re-resolved to a private IP by the time the
// upstream client dials it.
//
// For IP literals (e.g. "8.8.8.8:53") the address is returned unchanged.
// For hostnames (e.g. "dns.google:53") the first resolved public IP is pinned,
// preserving the original port: "8.8.8.8:53".
func validateAndPinUpstream(addr string) (string, error) {
	host := addr
	port := ""
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	// Strip brackets from IPv6 addresses
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	// Check if it's an IP literal — already pinned, no DNS involved.
	if ip := net.ParseIP(host); ip != nil {
		if util.IsPrivateIP(ip) {
			return "", fmt.Errorf("upstream server must not use a private/internal IP address")
		}
		return addr, nil
	}

	// Fail-closed: if we cannot resolve the hostname, we cannot verify it
	// doesn't point to a private/internal IP. This prevents DNS rebinding
	// attacks where a hostname resolves to a public IP at validation time
	// but rebinds to a private IP before the actual connection.
	ips, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("cannot resolve upstream hostname %q: %w", host, err)
	}

	// Validate ALL resolved IPs — reject if any is private/internal.
	// Defense in depth: a hostname that resolves to even one private IP is
	// suspicious and should be rejected outright.
	var pinnedIP string
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if util.IsPrivateIP(ip) {
			return "", fmt.Errorf("upstream server hostname %q resolves to private/internal IP %s", host, ipStr)
		}
		if pinnedIP == "" {
			pinnedIP = ipStr // Pin to first valid public IP
		}
	}
	if pinnedIP == "" {
		return "", fmt.Errorf("upstream server hostname %q resolved to no valid IP addresses", host)
	}

	// Reattach port if one was provided.
	if port != "" {
		return net.JoinHostPort(pinnedIP, port), nil
	}
	return pinnedIP, nil
}

// handleACL returns ACL rules or updates them.
