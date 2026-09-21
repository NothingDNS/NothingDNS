package api

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/upstream"
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
		servers := []UpstreamServerStatus{}
		if upstreamClient != nil {
			for _, srv := range upstreamClient.Servers() {
				servers = append(servers, UpstreamServerStatus{
					Address:   srv.Address,
					Healthy:   srv.IsHealthy(),
					LatencyMs: float64(srv.Latency().Microseconds()) / 1000,
				})
			}
		}
		s.writeJSON(w, http.StatusOK, &UpstreamsResponse{Upstreams: upstreams, Servers: servers})
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
			if err := s.persistUpstreamServers(upstreamClient); err != nil {
				// Roll the pool back so the running server and the persisted
				// list cannot disagree (same contract as an ACL update).
				if rbErr := upstreamClient.RemoveServer(pinnedAddr); rbErr != nil {
					util.Warnf("api: failed to roll back upstream %s after a persist failure: %v", pinnedAddr, rbErr)
				}
				s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to save runtime overrides"))
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server added: " + pinnedAddr + " (resolved from " + req.Server + ")"})

		case "remove":
			if req.Server == "" {
				s.writeError(w, http.StatusBadRequest, "Server address required")
				return
			}
			// Mirror the add path: resolve and pin hostnames so the address
			// matches what is actually stored in the pool. Without this,
			// removing a server that was added by hostname would fail with
			// "not found" because the pool stores the pinned IP, not the
			// raw input.
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
			if err := upstreamClient.RemoveServer(pinnedAddr); err != nil {
				s.writeError(w, http.StatusNotFound, sanitizeError(err, "Not found"))
				return
			}
			if err := s.persistUpstreamServers(upstreamClient); err != nil {
				if rbErr := upstreamClient.AddServer(pinnedAddr); rbErr != nil {
					util.Warnf("api: failed to restore upstream %s after a persist failure: %v", pinnedAddr, rbErr)
				}
				s.writeError(w, http.StatusInternalServerError, sanitizeError(err, "Failed to save runtime overrides"))
				return
			}
			s.writeJSON(w, http.StatusOK, &MessageResponse{Message: "Server removed: " + pinnedAddr + " (resolved from " + req.Server + ")"})

		default:
			s.writeError(w, http.StatusBadRequest, "Invalid action: must be 'add' or 'remove'")
		}
	}
}

// persistUpstreamServers records the pool's current server list as a runtime
// override, so an add/remove made from the dashboard survives a restart
// instead of reverting to upstream.servers from the config file. The full list
// is stored rather than a delta: the pool is the source of truth.
func (s *Server) persistUpstreamServers(client *upstream.Client) error {
	if client == nil {
		return nil
	}
	servers := client.Servers()
	addresses := make([]string, 0, len(servers))
	for _, srv := range servers {
		addresses = append(addresses, srv.Address)
	}
	return s.persistAndApplyOverrides(&config.RuntimeOverrides{UpstreamServers: &addresses})
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
	ips, err := lookupHostFn(host)
	if err != nil {
		return "", fmt.Errorf("cannot resolve upstream hostname %q: %w", host, err)
	}

	// Validate ALL resolved IPs — reject if any is private/internal.
	// Defense in depth: a hostname that resolves to even one private IP is
	// suspicious and should be rejected outright.
	//
	// Sort the public IPs before picking the first one so the pinned
	// address is deterministic across calls. net.LookupHost does not
	// guarantee a stable iteration order, so without sorting the same
	// hostname could pin to a different address on each call — which
	// would defeat the whole point of pinning (add and remove of the same
	// hostname would target different pool entries).
	sort.Strings(ips)
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
			pinnedIP = ipStr // Pin to first valid public IP (deterministic via sort)
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

// lookupHostFn is the hostname-to-IP resolver used by validateAndPinUpstream.
// It is a package-level variable so tests can inject a deterministic stub
// resolver; production code uses net.LookupHost (the default).
var lookupHostFn = net.LookupHost

// handleACL returns ACL rules or updates them.
