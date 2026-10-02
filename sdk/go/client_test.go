package nothingdns

// Behavioural tests for the NothingDNS Go SDK against the in-process mock API,
// mirroring sdk/python/tests/test_client.py and sdk/typescript/test/client.test.mjs.
//
// They pin the request-level contract: paths, methods, query strings, JSON
// bodies, bearer-auth propagation and typed model decoding.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Health & authentication
// ---------------------------------------------------------------------------

func TestHealthEndpointsNeedNoAuth(t *testing.T) {
	cases := []struct {
		name string
		call func(context.Context, *Client) (*HealthResponse, error)
		path string
	}{
		{"health", func(ctx context.Context, c *Client) (*HealthResponse, error) { return c.Health(ctx) }, "/health"},
		{"readyz", func(ctx context.Context, c *Client) (*HealthResponse, error) { return c.Ready(ctx) }, "/readyz"},
		{"livez", func(ctx context.Context, c *Client) (*HealthResponse, error) { return c.Live(ctx) }, "/livez"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockAPI(t)
			c := newTestClient(t, m)

			health, err := tc.call(context.Background(), c)
			wantNoError(t, err)
			wantEqual(t, "status", health.Status, "healthy")

			rec := m.last()
			wantEqual(t, "method", rec.Method, "GET")
			wantEqual(t, "path", rec.Path, tc.path)
			wantEqual(t, "authorization header", rec.Auth, "")
		})
	}
}

func TestLoginStoresTokenAndNextRequestCarriesIt(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	session, err := c.Auth.Login(ctx, testUsername, testPassword, true)
	wantNoError(t, err)
	wantEqual(t, "session role", session.Role, "admin")
	wantEqual(t, "session expires", session.Expires, "2026-10-02T12:00:00Z")
	wantEqual(t, "client token", c.Token(), testToken)

	// The login request itself must not carry a token; the next one must.
	wantEqual(t, "login authorization header", m.last().Auth, "")

	_, err = c.Status(ctx)
	wantNoError(t, err)
	wantEqual(t, "status authorization header", m.last().Auth, "Bearer "+testToken)
}

func TestLoginCanSkipStoringTheToken(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	session, err := c.Auth.Login(context.Background(), testUsername, testPassword, false)
	wantNoError(t, err)
	wantEqual(t, "session token", session.Token, testToken)
	wantEqual(t, "client token stays empty", c.Token(), "")
}

func TestSetTokenIsUsedForRequests(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	c.SetToken(testServiceToken)
	_, err := c.Status(context.Background())
	wantNoError(t, err)
	wantEqual(t, "authorization header", m.last().Auth, "Bearer "+testServiceToken)
}

func TestLogoutReturnsTheServerMessage(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	c.SetToken(testToken)
	message, err := c.Auth.Logout(context.Background())
	wantNoError(t, err)
	wantEqual(t, "logout message", message, "logged out")
}

// ---------------------------------------------------------------------------
// Status & models
// ---------------------------------------------------------------------------

func TestStatusDecodesNestedModels(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	status, err := c.Status(context.Background())
	wantNoError(t, err)
	wantEqual(t, "version", status.Version, "1.2.17")
	wantEqual(t, "cache hit ratio", status.Cache.HitRatio, 0.9)
	wantEqual(t, "cluster enabled", status.Cluster.Enabled, false)
	wantEqual(t, "cluster node id", status.Cluster.NodeID, "n1")
}

// ---------------------------------------------------------------------------
// Zones & records
// ---------------------------------------------------------------------------

func TestZoneListDecodesZones(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	zones, err := c.Zones.List(context.Background())
	wantNoError(t, err)
	wantEqual(t, "total", zones.Total, 1)
	wantEqual(t, "truncated", zones.Truncated, false)
	if len(zones.Zones) != 1 {
		t.Fatalf("zones: got %d entries, want 1", len(zones.Zones))
	}
	wantEqual(t, "zone name", zones.Zones[0].Name, "example.com")
	wantEqual(t, "zone serial", zones.Zones[0].Serial, 7)
}

func TestRecordCRUDMethodsPathsAndBodies(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	records, err := c.Zones.ListRecords(ctx, "example.com", "")
	wantNoError(t, err)
	if len(records.Records) != 1 {
		t.Fatalf("records: got %d entries, want 1", len(records.Records))
	}
	wantEqual(t, "record data", records.Records[0].Data, "192.0.2.1")
	wantEqual(t, "record class", records.Records[0].Class, "IN")

	message, err := c.Zones.AddRecord(ctx, "example.com", "api", "A", "192.0.2.9", &AddRecordOptions{TTL: intPtr(60)})
	wantNoError(t, err)
	wantEqual(t, "add ack", message, "record added")
	rec := m.last()
	wantEqual(t, "add method", rec.Method, "POST")
	wantEqual(t, "add path", rec.Path, "/api/v1/zones/example.com/records")
	wantEqual(t, "add body", bodyJSON(t, rec), `{"data":"192.0.2.9","name":"api","ttl":60,"type":"A"}`)

	message, err = c.Zones.ReplaceRecord(ctx, "example.com", "api", "A", "192.0.2.9", "192.0.2.10", nil)
	wantNoError(t, err)
	wantEqual(t, "replace ack", message, "record replaced")
	rec = m.last()
	wantEqual(t, "replace method", rec.Method, "PUT")
	wantEqual(t, "replace body", bodyJSON(t, rec), `{"data":"192.0.2.10","name":"api","old_data":"192.0.2.9","type":"A"}`)

	message, err = c.Zones.DeleteRecords(ctx, "example.com", "api", "A")
	wantNoError(t, err)
	wantEqual(t, "delete ack", message, "records deleted")
	rec = m.last()
	wantEqual(t, "delete method", rec.Method, "DELETE")
	wantEqual(t, "delete body", bodyJSON(t, rec), `{"name":"api","type":"A"}`)
}

func TestZoneExportReturnsRawZoneFile(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	c.SetToken(testToken)
	text, err := c.Zones.Export(context.Background(), "example.com")
	wantNoError(t, err)
	wantTrue(t, strings.HasPrefix(text, "$ORIGIN example.com."), "export starts with $ORIGIN")
}

func TestMissingZoneReturns404(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	_, err := c.Zones.Get(context.Background(), "missing.com")
	var apiErr *ErrAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *ErrAPIError, got %T: %v", err, err)
	}
	wantEqual(t, "status code", apiErr.StatusCode, http.StatusNotFound)
	wantTrue(t, strings.Contains(apiErr.Message, "missing.com"), "message names the zone")
	wantTrue(t, errors.Is(err, ErrNotFound), "errors.Is ErrNotFound")
}

func TestPTRBulkPreviewWireKeysAndDecoding(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	preview, err := c.Zones.PTRBulk(ctx, "2.0.192.in-addr.arpa", "192.0.2.0/24", "host-{ip}.example.com",
		&PTRBulkOptions{AddA: boolPtr(false), Preview: boolPtr(true)})
	wantNoError(t, err)
	wantEqual(t, "preview flag", preview.Preview, true)
	wantEqual(t, "willAdd", preview.WillAdd, 256)
	if len(preview.Changes) != 1 {
		t.Fatalf("changes: got %d entries, want 1", len(preview.Changes))
	}
	wantEqual(t, "change data", preview.Changes[0].Data, "host-192-0-2-1.example.com")
	wantEqual(t, "change action", preview.Changes[0].Action, "add")

	// The request keeps the wire's camelCase keys.
	wantEqual(t, "request body", bodyJSON(t, m.last()),
		`{"addA":false,"cidr":"192.0.2.0/24","pattern":"host-{ip}.example.com","preview":true}`)

	// Without options only cidr and pattern travel; nil pointers are omitted.
	_, err = c.Zones.PTRBulk(ctx, "2.0.192.in-addr.arpa", "192.0.2.0/24", "host-{ip}.example.com", nil)
	wantNoError(t, err)
	wantEqual(t, "request body without options", bodyJSON(t, m.last()),
		`{"cidr":"192.0.2.0/24","pattern":"host-{ip}.example.com"}`)
}

func TestPTR6LookupSendsIPQueryParam(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	lookup, err := c.Zones.PTR6Lookup(context.Background(), "8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1")
	wantNoError(t, err)
	wantEqual(t, "found", lookup.Found, true)
	wantEqual(t, "target", lookup.Target, "host.example.com")

	u, err := url.Parse(m.last().Path)
	wantNoError(t, err)
	wantEqual(t, "path", u.Path, "/api/v1/zones/8.b.d.0.1.0.0.2.ip6.arpa/ptr6-lookup")
	wantEqual(t, "ip query param", u.Query().Get("ip"), "2001:db8::1")
}

func TestZoneTransfersDecodeSlaveZones(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	slaves, err := c.Zones.Transfers(context.Background())
	wantNoError(t, err)
	if len(slaves) != 1 {
		t.Fatalf("slave zones: got %d entries, want 1", len(slaves))
	}
	wantEqual(t, "zone", slaves[0].Zone, "sub.example.com")
	wantEqual(t, "status", slaves[0].Status, "synced")
	wantEqual(t, "records", slaves[0].Records, 12)
}

// ---------------------------------------------------------------------------
// ACL
// ---------------------------------------------------------------------------

func TestACLRoundTrip(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	acl, err := c.ACL.Get(ctx)
	wantNoError(t, err)
	if len(acl.Rules) != 1 {
		t.Fatalf("rules: got %d entries, want 1", len(acl.Rules))
	}
	wantEqual(t, "rule action", acl.Rules[0].Action, "allow")
	wantEqual(t, "rule networks", acl.Rules[0].Networks, []string{"10.0.0.0/8"})
	wantEqual(t, "allow_recursion.allow_all", acl.AllowRecursion.AllowAll, false)
	wantEqual(t, "persistent", acl.Persistent, true)

	_, err = c.ACL.Set(ctx, []ACLRule{{Name: "vpn", Networks: []string{"10.1.0.0/16"}, Action: "deny"}})
	wantNoError(t, err)
	wantEqual(t, "set body", bodyJSON(t, m.last()),
		`{"rules":[{"action":"deny","name":"vpn","networks":["10.1.0.0/16"]}]}`)

	recursion, err := c.ACL.SetRecursion(ctx, []string{"10.0.0.0/8"})
	wantNoError(t, err)
	wantEqual(t, "recursion networks", recursion.Networks, []string{"10.0.0.0/8"})
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func TestConfigPartialUpdatesOmitNilFields(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	message, err := c.Config.SetLogging(ctx, "debug")
	wantNoError(t, err)
	wantEqual(t, "logging ack", message, "log level updated")
	rec := m.last()
	wantEqual(t, "logging method", rec.Method, "PUT")
	wantEqual(t, "logging body", bodyJSON(t, rec), `{"level":"debug"}`)

	_, err = c.Config.SetCache(ctx, &CacheConfigOptions{Size: intPtr(5000), ServeStale: boolPtr(true)})
	wantNoError(t, err)
	// nil-pointer fields are omitted from the JSON body, not sent as zeros.
	wantEqual(t, "cache body", bodyJSON(t, m.last()), `{"serve_stale":true,"size":5000}`)

	_, err = c.Config.SetResolution(ctx, &ResolutionOptions{Recursive: boolPtr(true), EDNS0BufferSize: intPtr(1232)})
	wantNoError(t, err)
	wantEqual(t, "resolution body", bodyJSON(t, m.last()), `{"edns0_buffer_size":1232,"recursive":true}`)

	message, err = c.Config.SetDNS64(ctx, true)
	wantNoError(t, err)
	wantEqual(t, "dns64 ack", message, "config updated")
	wantEqual(t, "dns64 body", bodyJSON(t, m.last()), `{"enabled":true}`)
}

// ---------------------------------------------------------------------------
// Dashboard & metrics
// ---------------------------------------------------------------------------

func TestDashboardDecodesCamelCaseKeys(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	stats, err := c.Dashboard.Stats(ctx)
	wantNoError(t, err)
	wantEqual(t, "queriesTotal", stats.QueriesTotal, 42)
	wantEqual(t, "cacheHitRate", stats.CacheHitRate, 0.75)
	wantEqual(t, "zoneCount", stats.ZoneCount, 1)

	events, err := c.Dashboard.Queries(ctx)
	wantNoError(t, err)
	if len(events) != 1 {
		t.Fatalf("events: got %d entries, want 1", len(events))
	}
	wantEqual(t, "clientIp", events[0].ClientIP, "10.0.0.5")
	wantEqual(t, "countryCode", events[0].CountryCode, "NL")
	wantEqual(t, "cached", events[0].Cached, true)
}

func TestQueryLogParamsAndPayload(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	page, err := c.Metrics.QueryLog(ctx, &QueryLogOptions{Limit: 50, Q: "example"})
	wantNoError(t, err)
	wantEqual(t, "path", m.last().Path, "/api/v1/queries?limit=50&q=example")
	if len(page.Queries) != 1 {
		t.Fatalf("queries: got %d entries, want 1", len(page.Queries))
	}
	wantEqual(t, "client_ip", page.Queries[0].ClientIP, "10.0.0.5")
	wantEqual(t, "total", page.Total, 1)

	_, err = c.Metrics.QueryLog(ctx, &QueryLogOptions{Offset: 100, Limit: 50})
	wantNoError(t, err)
	wantEqual(t, "path with offset", m.last().Path, "/api/v1/queries?limit=50&offset=100")

	_, err = c.Metrics.QueryLog(ctx, nil)
	wantNoError(t, err)
	wantEqual(t, "path without options", m.last().Path, "/api/v1/queries")
}

// ---------------------------------------------------------------------------
// Upstreams
// ---------------------------------------------------------------------------

func TestUpstreamsListAndAdd(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	ctx := context.Background()

	pool, err := c.Upstreams.List(ctx)
	wantNoError(t, err)
	if len(pool.Servers) != 1 {
		t.Fatalf("servers: got %d entries, want 1", len(pool.Servers))
	}
	wantEqual(t, "latency", pool.Servers[0].LatencyMS, 12.5)

	message, err := c.Upstreams.Add(ctx, "1.1.1.1:53")
	wantNoError(t, err)
	wantEqual(t, "add ack", message, "upstream added")
	wantEqual(t, "method", m.last().Method, "PUT")
	wantEqual(t, "body", bodyJSON(t, m.last()), `{"action":"add","server":"1.1.1.1:53"}`)
}

// ---------------------------------------------------------------------------
// Local validation
// ---------------------------------------------------------------------------

func TestLocalValidationRejectsBeforeAnyRequest(t *testing.T) {
	cases := []struct {
		name string
		call func(context.Context, *Client) error
	}{
		{"empty ACL rule list", func(ctx context.Context, c *Client) error {
			_, err := c.ACL.Set(ctx, nil)
			return err
		}},
		{"unknown log level", func(ctx context.Context, c *Client) error {
			_, err := c.Config.SetLogging(ctx, "loud")
			return err
		}},
		{"blocklist without a source", func(ctx context.Context, c *Client) error {
			_, err := c.Blocklists.Add(ctx, &AddBlocklistOptions{})
			return err
		}},
		{"blocklist with both sources", func(ctx context.Context, c *Client) error {
			_, err := c.Blocklists.Add(ctx, &AddBlocklistOptions{
				File: strPtr("a.hosts"),
				URL:  strPtr("https://example.invalid/hosts"),
			})
			return err
		}},
		{"unknown role", func(ctx context.Context, c *Client) error {
			_, err := c.Auth.CreateUser(ctx, "ops", "pw-op-1", "root")
			return err
		}},
		{"unknown RPZ action", func(ctx context.Context, c *Client) error {
			_, err := c.RPZ.AddRule(ctx, "ads.example.com", "DENY", nil)
			return err
		}},
		{"zone without nameservers", func(ctx context.Context, c *Client) error {
			_, err := c.Zones.Create(ctx, "example.com", nil, nil)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMockAPI(t)
			c := newTestClient(t, m)
			before := m.count()

			err := tc.call(context.Background(), c)
			if err == nil {
				t.Fatalf("expected a validation error, got nil")
			}
			var validationErr *ErrValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("expected *ErrValidationError, got %T: %v", err, err)
			}
			wantEqual(t, "requests recorded", m.count(), before) // nothing was sent
		})
	}
}

// ---------------------------------------------------------------------------
// Request mechanics
// ---------------------------------------------------------------------------

func TestPathSegmentsAreEscaped(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)

	_, err := c.Zones.Get(context.Background(), "weird zone/name")
	var apiErr *ErrAPIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("expected a 404 *ErrAPIError, got %T: %v", err, err)
	}

	// Space and slash must both stay inside the escaped path segment.
	wantEqual(t, "raw path", m.last().Path, "/api/v1/zones/weird%20zone%2Fname")
	wantTrue(t, strings.Contains(m.last().Path, "%20"), "space escaped as %20")
	wantTrue(t, strings.Contains(m.last().Path, "%2F"), "slash escaped as %2F")
}

func TestTrailingSlashInBaseURLIsNormalised(t *testing.T) {
	m := newMockAPI(t)

	c := NewClient(m.baseURL()+"/", "", 5*time.Second, nil, nil)
	t.Cleanup(c.Close)
	wantEqual(t, "base URL", c.BaseURL(), m.baseURL())

	health, err := c.Health(context.Background())
	wantNoError(t, err)
	wantEqual(t, "status", health.Status, "healthy")
}
