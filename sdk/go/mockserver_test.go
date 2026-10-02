package nothingdns

// In-process mock of the NothingDNS management API for the SDK test suite.
// It mirrors sdk/python/tests/conftest.py and sdk/typescript/test/mock-server.mjs.
//
// The mock implements the response shapes of the real management API contract
// (NothingDNS 1.2.17) for the endpoints the suite exercises, and records every
// request so tests can assert on methods, paths, bodies and headers.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testUsername     = "admin"
	testPassword     = "correct"
	testToken        = "tok-123"
	testServiceToken = testToken + "-service"

	testZoneFile = "$ORIGIN example.com.\n@ IN SOA ns1 hostmaster 7 3600 600 86400 300\n"
)

// recordedRequest is one request the mock received: the method, the raw path
// including the query string, the decoded JSON body (nil when absent) and the
// Authorization header value ("" when absent).
type recordedRequest struct {
	Method string
	Path   string
	Body   map[string]any
	Auth   string
}

// mockAPI is an in-process stand-in for the NothingDNS management API.
type mockAPI struct {
	server *httptest.Server

	mu       sync.Mutex
	requests []recordedRequest
}

// newMockAPI starts a fresh mock server; one per test, so recorded requests
// never leak between tests.
func newMockAPI(t *testing.T) *mockAPI {
	t.Helper()
	m := &mockAPI{}
	m.server = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

// baseURL is the address tests should point their client at.
func (m *mockAPI) baseURL() string { return m.server.URL }

// last returns the most recent recorded request.
func (m *mockAPI) last() recordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests[len(m.requests)-1]
}

// count returns how many requests have been recorded so far.
func (m *mockAPI) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}

// handle records the request and serves the canned response for its route.
// The recorded path is the raw request-URI, so percent-encoded path segments
// (see Transport.escape) stay escaped exactly as the SDK sent them.
func (m *mockAPI) handle(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if raw, err := io.ReadAll(r.Body); err == nil && len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &body)
	}
	m.mu.Lock()
	m.requests = append(m.requests, recordedRequest{
		Method: r.Method,
		Path:   r.RequestURI,
		Body:   body,
		Auth:   r.Header.Get("Authorization"),
	})
	m.mu.Unlock()

	route := r.RequestURI
	if i := strings.IndexByte(route, '?'); i >= 0 {
		route = route[:i]
	}

	sendJSON := func(code int, payload any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(payload)
	}
	sendText := func(code int, payload string) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(code)
		_, _ = io.WriteString(w, payload)
	}

	switch route {
	case "/health", "/readyz", "/livez":
		sendJSON(http.StatusOK, map[string]any{"status": "healthy", "timestamp": "2026-10-02T11:00:00Z"})
		return
	case "/api/v1/auth/login":
		if password, _ := body["password"].(string); password != testPassword {
			sendJSON(http.StatusUnauthorized, map[string]any{"error": "invalid credentials"})
			return
		}
		sendJSON(http.StatusOK, map[string]any{
			"token":    testToken,
			"username": testUsername,
			"role":     "admin",
			"expires":  "2026-10-02T12:00:00Z",
		})
		return
	case "/api/v1/auth/logout":
		sendJSON(http.StatusOK, map[string]any{"message": "logged out"})
		return
	case "/api/v1/status":
		sendJSON(http.StatusOK, map[string]any{
			"status":    "running",
			"timestamp": "t",
			"version":   "1.2.17",
			"cache":     map[string]any{"size": 3, "capacity": 100, "hits": 9, "misses": 1, "hit_ratio": 0.9},
			"cluster":   map[string]any{"enabled": false, "node_id": "n1", "node_count": 1, "alive_count": 1, "healthy": true},
		})
		return
	case "/api/v1/zones":
		sendJSON(http.StatusOK, map[string]any{
			"zones":     []any{map[string]any{"name": "example.com", "serial": 7, "records": 3}},
			"total":     1,
			"truncated": false,
		})
		return
	case "/api/v1/zones/example.com/records":
		switch r.Method {
		case http.MethodGet:
			sendJSON(http.StatusOK, map[string]any{
				"records":   []any{map[string]any{"name": "www", "type": "A", "ttl": 300, "class": "IN", "data": "192.0.2.1"}},
				"total":     1,
				"truncated": false,
			})
		case http.MethodPost:
			sendJSON(http.StatusCreated, map[string]any{"message": "record added"})
		case http.MethodPut:
			sendJSON(http.StatusOK, map[string]any{"message": "record replaced"})
		default:
			sendJSON(http.StatusOK, map[string]any{"message": "records deleted"})
		}
		return
	case "/api/v1/zones/example.com/export":
		sendText(http.StatusOK, testZoneFile)
		return
	case "/api/v1/zones/missing.com":
		sendJSON(http.StatusNotFound, map[string]any{"error": "Zone missing.com not found"})
		return
	case "/api/v1/zones/2.0.192.in-addr.arpa/ptr-bulk":
		sendJSON(http.StatusOK, map[string]any{
			"preview":      true,
			"total":        256,
			"willAdd":      256,
			"willAddA":     0,
			"willSkip":     0,
			"willOverride": 0,
			"changes": []any{map[string]any{
				"name":   "1",
				"type":   "PTR",
				"ttl":    300,
				"data":   "host-192-0-2-1.example.com",
				"action": "add",
			}},
		})
		return
	case "/api/v1/zones/8.b.d.0.1.0.0.2.ip6.arpa/ptr6-lookup":
		sendJSON(http.StatusOK, map[string]any{
			"ip":      "2001:db8::1",
			"ptr":     "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa",
			"ptrFQDN": "host.example.com.",
			"target":  "host.example.com",
			"ttl":     300,
			"found":   true,
		})
		return
	case "/api/v1/acl":
		if r.Method == http.MethodGet {
			sendJSON(http.StatusOK, map[string]any{
				"rules": []any{map[string]any{
					"name":     "office",
					"networks": []any{"10.0.0.0/8"},
					"action":   "allow",
					"types":    []any{"A"},
					"redirect": "",
				}},
				"allow_recursion": map[string]any{"allow_all": false, "networks": []any{"10.0.0.0/8"}},
				"persistent":      true,
				"policy_file":     "/var/lib/nothingdns/access_policy.json",
			})
		} else {
			sendJSON(http.StatusOK, map[string]any{"message": "acl updated"})
		}
		return
	case "/api/v1/acl/recursion":
		sendJSON(http.StatusOK, map[string]any{"allow_all": false, "networks": []any{"10.0.0.0/8"}})
		return
	case "/api/v1/config/logging":
		sendJSON(http.StatusOK, map[string]any{"message": "log level updated"})
		return
	}

	if strings.HasPrefix(route, "/api/v1/config/") {
		sendJSON(http.StatusOK, map[string]any{"message": "config updated"})
		return
	}

	switch route {
	case "/api/dashboard/stats":
		sendJSON(http.StatusOK, map[string]any{
			"uptime":          3600,
			"queriesTotal":    42,
			"queriesPerSec":   1.5,
			"cacheHitRate":    0.75,
			"blockedQueries":  3,
			"activeClients":   2,
			"zoneCount":       1,
			"upstreamLatency": 12,
		})
	case "/api/dashboard/queries":
		sendJSON(http.StatusOK, []any{map[string]any{
			"timestamp": "t", "clientIp": "10.0.0.5", "countryCode": "NL", "domain": "example.com",
			"queryType": "A", "responseCode": "NOERROR", "answers": []any{"192.0.2.1"},
			"duration": 1, "cached": true, "blocked": false, "protocol": "udp",
		}})
	case "/api/v1/queries":
		sendJSON(http.StatusOK, map[string]any{
			"queries": []any{map[string]any{
				"timestamp": "t", "client_ip": "10.0.0.5", "domain": "example.com", "query_type": "A",
				"response_code": "NOERROR", "answers": []any{"192.0.2.1"}, "duration_ms": 1,
				"cached": true, "blocked": false, "protocol": "udp",
			}},
			"total": 1, "offset": 0, "limit": 50,
		})
	case "/api/v1/upstreams":
		if r.Method == http.MethodGet {
			sendJSON(http.StatusOK, map[string]any{
				"upstreams": []any{map[string]any{"address": "9.9.9.9:53", "healthy": true, "queries": 5, "failed": 0, "failovers": 0}},
				"servers":   []any{map[string]any{"address": "9.9.9.9:53", "healthy": true, "latency_ms": 12.5}},
			})
			return
		}
		sendJSON(http.StatusOK, map[string]any{"message": "upstream added"})
	case "/api/v1/zones/transfers":
		sendJSON(http.StatusOK, map[string]any{
			"slave_zones": []any{map[string]any{
				"zone": "sub.example.com", "masters": "192.0.2.53", "serial": 3,
				"last_transfer": "2026-10-01T00:00:00Z", "status": "synced", "records": 12,
			}},
		})
	case "/api/v1/dnssec/status":
		sendJSON(http.StatusOK, map[string]any{"enabled": true, "require_dnssec": false})
	case "/api/v1/dnssec/keys":
		sendJSON(http.StatusForbidden, map[string]any{"error": "admin role required"})
	case "/api/v1/cache/flush":
		sendJSON(http.StatusTooManyRequests, map[string]any{"error": "rate limited"})
	default:
		sendJSON(http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

// ---------------------------------------------------------------------------
// Shared test fixtures and assertion helpers (stdlib only, no testify).
// ---------------------------------------------------------------------------

// newTestClient returns an unauthenticated client bound to the mock server.
func newTestClient(t *testing.T, m *mockAPI) *Client {
	t.Helper()
	return NewClient(m.baseURL(), "", 5*time.Second, nil, nil)
}

// bodyJSON renders a recorded request body back to canonical JSON (map keys
// sorted by encoding/json) so tests can compare the exact wire shape,
// including keys that nil-pointer fields omitted.
func bodyJSON(t *testing.T, rec recordedRequest) string {
	t.Helper()
	raw, err := json.Marshal(rec.Body)
	if err != nil {
		t.Fatalf("could not re-encode recorded body: %v", err)
	}
	return string(raw)
}

func wantNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// wantEqual compares with reflect.DeepEqual so maps, slices and structs work.
func wantEqual[T any](t *testing.T, label string, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: got %+v, want %+v", label, got, want)
	}
}

func wantTrue(t *testing.T, cond bool, label string) {
	t.Helper()
	if !cond {
		t.Errorf("%s: condition is false", label)
	}
}

func boolPtr(v bool) *bool    { return &v }
func intPtr(v int) *int       { return &v }
func strPtr(v string) *string { return &v }
