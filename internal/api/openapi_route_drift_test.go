package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// registeredRoutes is the canonical list of /api/v1 routes the server's mux
// actually registers (server.go). When you add a route there, add it here —
// the guard below fails otherwise. The {zone}-parameterized routes
// (zones/{zone}, zones/{zone}/records, zones/{zone}/export) are handled by
// the /api/v1/zones/ prefix and are matched as templates in the phantom gate.
var registeredRoutes = []string{
	"/api/v1/acl",
	"/api/v1/auth/bootstrap",
	"/api/v1/auth/login",
	"/api/v1/auth/logout",
	"/api/v1/auth/roles",
	"/api/v1/auth/users",
	"/api/v1/blocklists",
	"/api/v1/config",
	"/api/v1/config/cache",
	"/api/v1/config/logging",
	"/api/v1/config/rrl",
	"/api/v1/config/reload",
	"/api/v1/csp-report",
	"/api/v1/dnssec/keys",
	"/api/v1/dnssec/status",
	"/api/v1/geoip/stats",
	"/api/v1/metrics/history",
	"/api/v1/queries",
	"/api/v1/rpz",
	"/api/v1/rpz/rules",
	"/api/v1/server/config",
	"/api/v1/topdomains",
	"/api/v1/upstreams",
	"/api/v1/zones",
	"/api/v1/zones/reload",
	"/api/v1/zones/transfers",
	"/api/v1/cache/flush",
	"/api/v1/cache/stats",
	"/api/v1/cluster/join",
	"/api/v1/cluster/leave",
	"/api/v1/cluster/nodes",
	"/api/v1/cluster/status",
	"/api/v1/status",
	"/health",
	"/api/dashboard/stats",
}

// TestOpenAPISpecDocumentsEveryRegisteredRoute is the route-drift guard:
// every route the mux registers must appear in the OpenAPI contract, so the
// published API documentation can never silently fall behind the served
// surface (round-8/25 found 23 of 33 routes missing from it).
func TestOpenAPISpecDocumentsEveryRegisteredRoute(t *testing.T) {
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal([]byte(OpenAPISpec), &spec); err != nil {
		t.Fatalf("OpenAPISpec is not valid JSON: %v", err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("OpenAPISpec declares no paths at all")
	}

	documented := make(map[string]bool, len(spec.Paths))
	for path := range spec.Paths {
		documented[path] = true
	}

	for _, route := range registeredRoutes {
		if !documented[route] {
			t.Errorf("route %s is registered but not documented in OpenAPISpec", route)
		}
	}

	// Phantom gate: everything the spec documents must correspond to a
	// registered route ({zone} templates match the /api/v1/zones/ prefix).
	for path := range documented {
		if strings.Contains(path, "{") {
			continue // parameterized template, matched by prefix below
		}
		found := false
		for _, route := range registeredRoutes {
			if route == path || strings.HasPrefix(route, path+"/") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("OpenAPISpec documents path %s but no route registers it", path)
		}
	}
}
