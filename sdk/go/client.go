package nothingdns

import (
	"context"
	"net/http"
	"time"
)

// Client is the entry point to the NothingDNS management API. It mirrors the
// server's API groups as namespaces:
//
//	client.Auth       // login, bootstrap, session, users, roles
//	client.Zones      // zones, records, export, bulk PTR
//	client.Cache      // cache statistics and flush
//	client.Config     // effective config + runtime tunables
//	client.ACL        // ACL rules and recursion allow list
//	client.Blocklists // blocklist sources and filtering
//	client.RPZ        // response policy zones
//	client.DNSSEC     // validation status and signing keys
//	client.Upstreams  // upstream pool health
//	client.GeoIP      // GeoDNS statistics
//	client.Cluster    // gossip + Raft cluster management
//	client.Dashboard  // dashboard counters, query events, zone summary
//	client.Metrics    // query log, top domains, metrics history
//
// Every method returns typed models (see models.go) and returns an
// *ErrAPIError for any non-2xx response. A Client is safe for concurrent use
// by multiple goroutines as long as its token is not changed concurrently; the
// Transport keeps no mutable per-request state. Give each goroutine its own
// Client only if you also want a separate connection pool.
type Client struct {
	transport *Transport

	// Auth handles login, bootstrap, session, users and roles.
	Auth *AuthService
	// Zones handles zones, records, export and bulk PTR.
	Zones *ZonesService
	// Cache handles cache statistics and flush.
	Cache *CacheService
	// Config handles effective configuration and runtime tunables.
	Config *ConfigService
	// ACL handles ACL rules and the recursion allow list.
	ACL *ACLService
	// Blocklists handles blocklist sources and filtering.
	Blocklists *BlocklistsService
	// RPZ handles response policy zones.
	RPZ *RPZService
	// DNSSEC handles validation status and signing keys.
	DNSSEC *DNSSECService
	// Upstreams handles the upstream pool.
	Upstreams *UpstreamsService
	// GeoIP handles GeoDNS statistics.
	GeoIP *GeoIPService
	// Cluster handles gossip + Raft cluster management.
	Cluster *ClusterService
	// Dashboard handles dashboard counters, query events and zone summary.
	Dashboard *DashboardService
	// Metrics handles the query log, top domains and metrics history.
	Metrics *MetricsService
}

// NewClient builds a Client for one NothingDNS server.
//
// baseURL is the address of the server's HTTP listener (the server.http
// section of the config; defaults to DefaultBaseURL). token may be a JWT from
// Auth.Login / Auth.Bootstrap or the static server.http.auth_token value; pass
// "" to start unauthenticated and call Auth.Login later. timeout is the
// per-request timeout (defaults to DefaultTimeout when zero). httpClient may
// be nil, in which case a client with that timeout is used; supply your own to
// control TLS, proxies or connection pooling. headers are extra default
// headers merged into every request.
//
// Example:
//
//	client := nothingdns.NewClient("http://dns.example.com:8080", "", 0, nil, nil)
//	defer client.Close()
//	_, err := client.Auth.Login(ctx, os.Getenv("NDNS_USER"), os.Getenv("NDNS_PASSWORD"), true)
func NewClient(baseURL string, token string, timeout time.Duration, httpClient *http.Client, headers map[string]string) *Client {
	t := NewTransport(baseURL, token, timeout, httpClient, headers)
	c := &Client{transport: t}
	c.Auth = &AuthService{t: t}
	c.Zones = &ZonesService{t: t}
	c.Cache = &CacheService{t: t}
	c.Config = &ConfigService{t: t}
	c.ACL = &ACLService{t: t}
	c.Blocklists = &BlocklistsService{t: t}
	c.RPZ = &RPZService{t: t}
	c.DNSSEC = &DNSSECService{t: t}
	c.Upstreams = &UpstreamsService{t: t}
	c.GeoIP = &GeoIPService{t: t}
	c.Cluster = &ClusterService{t: t}
	c.Dashboard = &DashboardService{t: t}
	c.Metrics = &MetricsService{t: t}
	return c
}

// BaseURL returns the server address, without a trailing slash.
func (c *Client) BaseURL() string { return c.transport.BaseURL() }

// Token returns the bearer token currently in use (or "").
func (c *Client) Token() string { return c.transport.Token() }

// SetToken sets the bearer token used by every namespace. The value may be a
// JWT from Auth.Login / Auth.Bootstrap, the static server.http.auth_token
// value, or "" to continue unauthenticated.
func (c *Client) SetToken(token string) { c.transport.SetToken(token) }

// Transport exposes the underlying Transport for advanced use.
func (c *Client) Transport() *Transport { return c.transport }

// Close releases the Transport's resources. When a custom *http.Client was
// supplied this only closes idle connections on its transport; the caller
// remains responsible for any client-specific cleanup.
func (c *Client) Close() {
	if t := c.transport.HTTPClient().Transport; t != nil {
		if closer, ok := t.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
	}
}

// Health calls GET /health — a health check that requires no authentication.
// It fails with an *ErrAPIError carrying status 429 when the endpoint's own
// rate limit is hit.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	if err := c.transport.doJSON(ctx, "GET", "/health", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Ready calls GET /readyz — a readiness probe that requires no
// authentication. It fails with an *ErrAPIError carrying status 503 when the
// server is not ready to answer queries; treat that as "not ready" rather than
// a hard failure.
func (c *Client) Ready(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	if err := c.transport.doJSON(ctx, "GET", "/readyz", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Live calls GET /livez — a liveness probe that requires no authentication.
func (c *Client) Live(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	if err := c.transport.doJSON(ctx, "GET", "/livez", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status calls GET /api/v1/status — status, version, cache and cluster
// summary. Any authenticated user may call this; the cache block is present
// for operators and admins only.
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	if err := c.transport.doJSON(ctx, "GET", "/api/v1/status", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ServerConfig calls GET /api/v1/server/config — port, log level, DNS64 and
// cookies. It requires the operator role or higher.
func (c *Client) ServerConfig(ctx context.Context) (*ServerConfig, error) {
	var out ServerConfig
	if err := c.transport.doJSON(ctx, "GET", "/api/v1/server/config", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// OpenAPISpec returns the server's OpenAPI document (GET /api/openapi.json).
// It is useful for detecting server capabilities that this SDK version
// predates.
func (c *Client) OpenAPISpec(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.transport.doJSON(ctx, "GET", "/api/openapi.json", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// APIDocs returns the API explorer page (GET /api/docs) as raw HTML.
func (c *Client) APIDocs(ctx context.Context) (string, error) {
	return c.transport.doText(ctx, "GET", "/api/docs", nil)
}

// APIDocsScript returns the API explorer script (GET /api/docs/app.js) as
// raw JavaScript.
func (c *Client) APIDocsScript(ctx context.Context) (string, error) {
	return c.transport.doText(ctx, "GET", "/api/docs/app.js", nil)
}

// ReportCSPViolation posts a Content-Security-Policy violation report to the
// server's report sink (POST /api/v1/csp-report). report is any
// JSON-serialisable object matching the CSP violation shape, for example a
// struct with "csp-report" set to a map. The server answers 204 with no body.
func (c *Client) ReportCSPViolation(ctx context.Context, report any) error {
	return c.transport.doJSON(ctx, "POST", "/api/v1/csp-report", nil, report, nil)
}
