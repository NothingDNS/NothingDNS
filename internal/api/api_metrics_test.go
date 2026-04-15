package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/dashboard"
)

func setupMetricsServer(t *testing.T) (*Server, string) {
	cfg := config.HTTPConfig{Enabled: true, Bind: "127.0.0.1:0"}
	s := NewServer(cfg, nil, nil, nil, nil, nil, nil)
	token := attachTestAuth(s)
	return s, token
}

// ---- QueryLog: exercises with real dashboard data ----

func TestHandleQueryLog_WithDashboardData(t *testing.T) {
	s, token := setupMetricsServer(t)
	ds := dashboard.NewServer()
	s.dashboardServer = ds

	ds.RecordQuery(&dashboard.QueryEvent{
		Timestamp:    time.Now(),
		ClientIP:     "192.168.1.1",
		Domain:       "example.com",
		QueryType:    "A",
		ResponseCode: "NOERROR",
		Duration:     1000000,
		Cached:       true,
		Protocol:     "udp",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/query-log?offset=0&limit=10", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleQueryLog(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp QueryLogResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Total != 1 {
		t.Errorf("expected total=1, got %d", resp.Total)
	}
	if len(resp.Queries) != 1 {
		t.Fatalf("expected 1 query, got %d", len(resp.Queries))
	}
	if resp.Queries[0].Domain != "example.com" {
		t.Errorf("expected domain=example.com, got %s", resp.Queries[0].Domain)
	}
}

func TestHandleQueryLog_Pagination(t *testing.T) {
	s, token := setupMetricsServer(t)
	ds := dashboard.NewServer()
	s.dashboardServer = ds

	for i := 0; i < 20; i++ {
		ds.RecordQuery(&dashboard.QueryEvent{
			Domain:    "test.com",
			Protocol:  "udp",
			Timestamp: time.Now(),
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/query-log?offset=5&limit=10", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleQueryLog(rec, req)

	var resp QueryLogResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Offset != 5 {
		t.Errorf("expected offset=5, got %d", resp.Offset)
	}
	if resp.Limit != 10 {
		t.Errorf("expected limit=10, got %d", resp.Limit)
	}
}

func TestHandleQueryLog_InvalidParams(t *testing.T) {
	s, token := setupMetricsServer(t)
	ds := dashboard.NewServer()
	s.dashboardServer = ds

	req := httptest.NewRequest(http.MethodGet, "/api/v1/query-log?offset=abc&limit=-1", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleQueryLog(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with defaults, got %d", rec.Code)
	}
}

func TestHandleQueryLog_Unauthorized(t *testing.T) {
	s, _ := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/query-log", nil)
	rec := httptest.NewRecorder()
	s.handleQueryLog(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// ---- TopDomains: exercises with real data ----

func TestHandleTopDomains_WithDashboardData(t *testing.T) {
	s, token := setupMetricsServer(t)
	ds := dashboard.NewServer()
	s.dashboardServer = ds

	for i := 0; i < 5; i++ {
		ds.RecordQuery(&dashboard.QueryEvent{Domain: "top1.com", Protocol: "udp", Timestamp: time.Now()})
	}
	for i := 0; i < 3; i++ {
		ds.RecordQuery(&dashboard.QueryEvent{Domain: "top2.com", Protocol: "udp", Timestamp: time.Now()})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/top-domains?limit=5", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleTopDomains(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp TopDomainsResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Limit != 5 {
		t.Errorf("expected limit=5, got %d", resp.Limit)
	}
	if len(resp.Domains) < 1 {
		t.Error("expected at least one domain")
	}
}

func TestHandleTopDomains_InvalidLimit(t *testing.T) {
	s, token := setupMetricsServer(t)
	ds := dashboard.NewServer()
	s.dashboardServer = ds

	req := httptest.NewRequest(http.MethodGet, "/api/v1/top-domains?limit=invalid", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleTopDomains(rec, req)

	var resp TopDomainsResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Limit != 10 {
		t.Errorf("expected default limit=10, got %d", resp.Limit)
	}
}

func TestHandleTopDomains_Unauthorized(t *testing.T) {
	s, _ := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/top-domains", nil)
	rec := httptest.NewRecorder()
	s.handleTopDomains(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// ---- Dashboard Queries/Zones: exercises with real data ----

func TestHandleDashboardQueries_WithData(t *testing.T) {
	s, token := setupMetricsServer(t)
	ds := dashboard.NewServer()
	s.dashboardServer = ds
	ds.RecordQuery(&dashboard.QueryEvent{Domain: "query1.com", Protocol: "tcp", Timestamp: time.Now()})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/queries", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleDashboardQueries(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandleDashboardQueries_Unauthorized(t *testing.T) {
	s, _ := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/queries", nil)
	rec := httptest.NewRecorder()
	s.handleDashboardQueries(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestHandleDashboardZones_Unauthorized(t *testing.T) {
	s, _ := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/zones", nil)
	rec := httptest.NewRecorder()
	s.handleDashboardZones(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// ---- GeoDNS Stats (0% coverage) ----

func TestHandleGeoDNSStats_WrongMethod(t *testing.T) {
	s, token := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geodns/stats", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleGeoDNSStats(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleGeoDNSStats_Unauthorized(t *testing.T) {
	s, _ := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/geodns/stats", nil)
	rec := httptest.NewRecorder()
	s.handleGeoDNSStats(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestHandleGeoDNSStats_NoEngine(t *testing.T) {
	s, token := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/geodns/stats", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleGeoDNSStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp GeoDNSStatsResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Enabled {
		t.Error("expected enabled=false when no geo engine")
	}
}

// ---- Slave Zones (0% coverage) ----

func TestHandleSlaveZones_WrongMethod(t *testing.T) {
	s, token := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/slave-zones", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleSlaveZones(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleSlaveZones_Unauthorized(t *testing.T) {
	s, _ := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/slave-zones", nil)
	rec := httptest.NewRecorder()
	s.handleSlaveZones(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestHandleSlaveZones_NoManager(t *testing.T) {
	s, token := setupMetricsServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/slave-zones", nil)
	req = withTestAdminAuth(req, token)
	rec := httptest.NewRecorder()
	s.handleSlaveZones(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp SlaveZonesResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.SlaveZones) != 0 {
		t.Errorf("expected empty slave zones, got %d", len(resp.SlaveZones))
	}
}
