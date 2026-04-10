package mcp

import (
	"errors"
	"testing"
)

// Mock implementations for testing

type MockZoneManager struct {
	zones     []ZoneInfo
	records   []RecordInfo
	createErr error
	deleteErr error
	getErr    error
	listErr   error
	addRecErr error
	delRecErr error
	importErr error
	exportErr error
}

func (m *MockZoneManager) ListZones() ([]ZoneInfo, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.zones, nil
}

func (m *MockZoneManager) GetZone(name string) (*ZoneInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	for _, z := range m.zones {
		if z.Name == name {
			return &z, nil
		}
	}
	return nil, errors.New("zone not found")
}

func (m *MockZoneManager) CreateZone(name string, opts ZoneOptions) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.zones = append(m.zones, ZoneInfo{Name: name})
	return nil
}

func (m *MockZoneManager) DeleteZone(name string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	return nil
}

func (m *MockZoneManager) AddRecord(zone, name, rtype, value string, ttl int) error {
	if m.addRecErr != nil {
		return m.addRecErr
	}
	m.records = append(m.records, RecordInfo{Name: name, Type: rtype, Value: value, TTL: ttl})
	return nil
}

func (m *MockZoneManager) DeleteRecord(zone, name, rtype string) error {
	if m.delRecErr != nil {
		return m.delRecErr
	}
	return nil
}

func (m *MockZoneManager) GetRecords(zone, name string) ([]RecordInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.records, nil
}

func (m *MockZoneManager) ImportZone(name string, data []byte) error {
	return m.importErr
}

func (m *MockZoneManager) ExportZone(name string) ([]byte, error) {
	return []byte{}, m.exportErr
}

type MockCacheManager struct {
	stats    CacheStats
	flushErr error
}

func (m *MockCacheManager) GetStats() CacheStats {
	return m.stats
}

func (m *MockCacheManager) Flush() error {
	return m.flushErr
}

type MockDNSResolver struct {
	result QueryResult
	err    error
}

func (m *MockDNSResolver) Query(name, qtype string) (*QueryResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &m.result, nil
}

type MockBlocklistManager struct {
	blocked bool
	lists   []string
}

func (m *MockBlocklistManager) IsBlocked(domain string) bool {
	return m.blocked
}

func (m *MockBlocklistManager) Lists() []string {
	return m.lists
}

type MockStatsProvider struct {
	stats ServerStats
}

func (m *MockStatsProvider) GetStats() ServerStats {
	return m.stats
}

// Tests

func TestNewDNSToolsHandler(t *testing.T) {
	zm := &MockZoneManager{}
	cache := &MockCacheManager{}
	resolver := &MockDNSResolver{}
	bl := &MockBlocklistManager{}
	stats := &MockStatsProvider{}

	handler := NewDNSToolsHandler(zm, cache, resolver, bl, stats)
	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
}

func TestDNSToolsHandlerListTools(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	tools, err := handler.ListTools()
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	expectedTools := []string{
		"dns_query", "zone_list", "zone_get", "zone_create", "zone_delete",
		"record_add", "record_delete", "record_list",
		"cache_stats", "cache_flush", "blocklist_check", "server_stats",
	}

	if len(tools) != len(expectedTools) {
		t.Errorf("Expected %d tools, got %d", len(expectedTools), len(tools))
	}

	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}

	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("Missing tool: %s", name)
		}
	}
}

func TestCallToolUnknown(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.CallTool("unknown_tool", nil)
	if err == nil {
		t.Error("Expected error for unknown tool")
	}
}

func TestCallDNSQuery(t *testing.T) {
	resolver := &MockDNSResolver{
		result: QueryResult{
			Name:    "example.com",
			Type:    "A",
			Answers: []string{"93.184.216.34"},
			RCode:   "NOERROR",
			Time:    1000000,
		},
	}
	handler := NewDNSToolsHandler(nil, nil, resolver, nil, nil)

	result, err := handler.CallTool("dns_query", map[string]interface{}{
		"name": "example.com",
		"type": "A",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}

	if len(result.Content) == 0 {
		t.Error("Expected content in result")
	}
}

func TestCallDNSQueryMissingName(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.CallTool("dns_query", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for missing name")
	}
}

func TestCallDNSQueryNoResolver(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("dns_query", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when no resolver configured")
	}
}

func TestCallDNSQueryError(t *testing.T) {
	resolver := &MockDNSResolver{err: errors.New("query failed")}
	handler := NewDNSToolsHandler(nil, nil, resolver, nil, nil)

	result, err := handler.CallTool("dns_query", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when query fails")
	}
}

func TestCallZoneList(t *testing.T) {
	zm := &MockZoneManager{
		zones: []ZoneInfo{
			{Name: "example.com", Serial: 2024010101, RecordCount: 10},
			{Name: "test.com", Serial: 2024010102, RecordCount: 5},
		},
	}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_list", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallZoneListNoManager(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_list", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when no zone manager")
	}
}

func TestCallZoneListError(t *testing.T) {
	zm := &MockZoneManager{listErr: errors.New("list failed")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	_, err := handler.CallTool("zone_list", nil)
	if err == nil {
		t.Error("Expected error from list zones")
	}
}

func TestCallZoneGet(t *testing.T) {
	zm := &MockZoneManager{
		zones: []ZoneInfo{{Name: "example.com", Serial: 2024010101}},
	}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_get", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallZoneGetMissingName(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.CallTool("zone_get", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for missing name")
	}
}

func TestCallZoneGetNotFound(t *testing.T) {
	zm := &MockZoneManager{getErr: errors.New("zone not found")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_get", map[string]interface{}{
		"name": "nonexistent.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result for non-existent zone")
	}
}

func TestCallZoneCreate(t *testing.T) {
	zm := &MockZoneManager{}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_create", map[string]interface{}{
		"name":        "newzone.com",
		"ttl":         3600,
		"admin_email": "admin@newzone.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallZoneCreateMissingName(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.CallTool("zone_create", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for missing name")
	}
}

func TestCallZoneCreateError(t *testing.T) {
	zm := &MockZoneManager{createErr: errors.New("create failed")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_create", map[string]interface{}{
		"name": "newzone.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when create fails")
	}
}

func TestCallZoneDelete(t *testing.T) {
	zm := &MockZoneManager{}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_delete", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallZoneDeleteMissingName(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.CallTool("zone_delete", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for missing name")
	}
}

func TestCallZoneDeleteError(t *testing.T) {
	zm := &MockZoneManager{deleteErr: errors.New("delete failed")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_delete", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when delete fails")
	}
}

func TestCallRecordAdd(t *testing.T) {
	zm := &MockZoneManager{}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("record_add", map[string]interface{}{
		"zone":  "example.com",
		"name":  "www",
		"type":  "A",
		"value": "192.0.2.1",
		"ttl":   3600,
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallRecordAddMissingFields(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	tests := []struct {
		name string
		args map[string]interface{}
	}{
		{"missing zone", map[string]interface{}{"name": "www", "type": "A", "value": "1.2.3.4"}},
		{"missing name", map[string]interface{}{"zone": "example.com", "type": "A", "value": "1.2.3.4"}},
		{"missing type", map[string]interface{}{"zone": "example.com", "name": "www", "value": "1.2.3.4"}},
		{"missing value", map[string]interface{}{"zone": "example.com", "name": "www", "type": "A"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handler.CallTool("record_add", tc.args)
			if err == nil {
				t.Error("Expected error for missing fields")
			}
		})
	}
}

func TestCallRecordAddError(t *testing.T) {
	zm := &MockZoneManager{addRecErr: errors.New("add failed")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("record_add", map[string]interface{}{
		"zone":  "example.com",
		"name":  "www",
		"type":  "A",
		"value": "192.0.2.1",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when add fails")
	}
}

func TestCallRecordDelete(t *testing.T) {
	zm := &MockZoneManager{}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("record_delete", map[string]interface{}{
		"zone": "example.com",
		"name": "www",
		"type": "A",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallRecordDeleteMissingFields(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	tests := []struct {
		name string
		args map[string]interface{}
	}{
		{"missing zone", map[string]interface{}{"name": "www", "type": "A"}},
		{"missing name", map[string]interface{}{"zone": "example.com", "type": "A"}},
		{"missing type", map[string]interface{}{"zone": "example.com", "name": "www"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handler.CallTool("record_delete", tc.args)
			if err == nil {
				t.Error("Expected error for missing fields")
			}
		})
	}
}

func TestCallRecordDeleteError(t *testing.T) {
	zm := &MockZoneManager{delRecErr: errors.New("delete failed")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("record_delete", map[string]interface{}{
		"zone": "example.com",
		"name": "www",
		"type": "A",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when delete fails")
	}
}

func TestCallRecordList(t *testing.T) {
	zm := &MockZoneManager{
		records: []RecordInfo{
			{Name: "www", Type: "A", TTL: 3600, Value: "192.0.2.1"},
			{Name: "mail", Type: "A", TTL: 3600, Value: "192.0.2.2"},
		},
	}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("record_list", map[string]interface{}{
		"zone": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallRecordListMissingZone(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.CallTool("record_list", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for missing zone")
	}
}

func TestCallRecordListError(t *testing.T) {
	zm := &MockZoneManager{getErr: errors.New("list failed")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("record_list", map[string]interface{}{
		"zone": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when list fails")
	}
}

func TestCallCacheStats(t *testing.T) {
	cache := &MockCacheManager{
		stats: CacheStats{Size: 1000, HitRate: 0.85, MissRate: 0.15, Evictions: 50},
	}
	handler := NewDNSToolsHandler(nil, cache, nil, nil, nil)

	result, err := handler.CallTool("cache_stats", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallCacheStatsNoCache(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("cache_stats", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when no cache")
	}
}

func TestCallCacheFlush(t *testing.T) {
	cache := &MockCacheManager{}
	handler := NewDNSToolsHandler(nil, cache, nil, nil, nil)

	result, err := handler.CallTool("cache_flush", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallCacheFlushNoCache(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("cache_flush", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when no cache")
	}
}

func TestCallCacheFlushError(t *testing.T) {
	cache := &MockCacheManager{flushErr: errors.New("flush failed")}
	handler := NewDNSToolsHandler(nil, cache, nil, nil, nil)

	result, err := handler.CallTool("cache_flush", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when flush fails")
	}
}

func TestCallBlocklistCheck(t *testing.T) {
	bl := &MockBlocklistManager{blocked: true}
	handler := NewDNSToolsHandler(nil, nil, nil, bl, nil)

	result, err := handler.CallTool("blocklist_check", map[string]interface{}{
		"domain": "ads.example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallBlocklistCheckMissingDomain(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.CallTool("blocklist_check", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for missing domain")
	}
}

func TestCallBlocklistCheckNoBlocklist(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("blocklist_check", map[string]interface{}{
		"domain": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when no blocklist")
	}
}

func TestCallServerStats(t *testing.T) {
	stats := &MockStatsProvider{
		stats: ServerStats{
			Uptime:         3600,
			QueriesTotal:   10000,
			QueriesPerSec:  100.5,
			CacheHitRate:   0.85,
			BlockedQueries: 500,
			ZonesCount:     10,
		},
	}
	handler := NewDNSToolsHandler(nil, nil, nil, nil, stats)

	result, err := handler.CallTool("server_stats", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

func TestCallServerStatsNoProvider(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("server_stats", nil)
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when no stats provider")
	}
}

// ListResources tests

func TestListResources(t *testing.T) {
	zm := &MockZoneManager{
		zones: []ZoneInfo{{Name: "example.com", RecordCount: 10}},
	}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	resources, err := handler.ListResources()
	if err != nil {
		t.Fatalf("ListResources failed: %v", err)
	}

	// Should have zone resource + server/status + cache/stats
	if len(resources) < 3 {
		t.Errorf("Expected at least 3 resources, got %d", len(resources))
	}
}

func TestListResourcesNoZoneManager(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	resources, err := handler.ListResources()
	if err != nil {
		t.Fatalf("ListResources failed: %v", err)
	}

	// Should have server/status + cache/stats
	if len(resources) < 2 {
		t.Errorf("Expected at least 2 resources, got %d", len(resources))
	}
}

// ReadResource tests

func TestReadResourceInvalidScheme(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.ReadResource("http://example.com")
	if err == nil {
		t.Error("Expected error for invalid URI scheme")
	}
}

func TestReadResourceZone(t *testing.T) {
	zm := &MockZoneManager{
		zones: []ZoneInfo{{Name: "example.com", Serial: 2024010101, RecordCount: 10}},
	}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	contents, err := handler.ReadResource("dns://zone/example.com")
	if err != nil {
		t.Fatalf("ReadResource failed: %v", err)
	}

	if contents.MimeType != "application/json" {
		t.Errorf("Expected JSON mimetype, got %s", contents.MimeType)
	}
}

func TestReadResourceZoneNoManager(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.ReadResource("dns://zone/example.com")
	if err == nil {
		t.Error("Expected error when no zone manager")
	}
}

func TestReadResourceZoneNotFound(t *testing.T) {
	zm := &MockZoneManager{getErr: errors.New("zone not found")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	_, err := handler.ReadResource("dns://zone/nonexistent.com")
	if err == nil {
		t.Error("Expected error for non-existent zone")
	}
}

func TestReadResourceServerStatus(t *testing.T) {
	stats := &MockStatsProvider{stats: ServerStats{Uptime: 3600}}
	handler := NewDNSToolsHandler(nil, nil, nil, nil, stats)

	contents, err := handler.ReadResource("dns://server/status")
	if err != nil {
		t.Fatalf("ReadResource failed: %v", err)
	}

	if contents.MimeType != "application/json" {
		t.Errorf("Expected JSON mimetype, got %s", contents.MimeType)
	}
}

func TestReadResourceServerStatusNoProvider(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.ReadResource("dns://server/status")
	if err == nil {
		t.Error("Expected error when no stats provider")
	}
}

func TestReadResourceCacheStats(t *testing.T) {
	cache := &MockCacheManager{stats: CacheStats{Size: 1000}}
	handler := NewDNSToolsHandler(nil, cache, nil, nil, nil)

	contents, err := handler.ReadResource("dns://cache/stats")
	if err != nil {
		t.Fatalf("ReadResource failed: %v", err)
	}

	if contents.MimeType != "application/json" {
		t.Errorf("Expected JSON mimetype, got %s", contents.MimeType)
	}
}

func TestReadResourceCacheStatsNoCache(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.ReadResource("dns://cache/stats")
	if err == nil {
		t.Error("Expected error when no cache")
	}
}

func TestReadResourceNotFound(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.ReadResource("dns://unknown/resource")
	if err == nil {
		t.Error("Expected error for unknown resource")
	}
}

// ListPrompts tests

func TestListPrompts(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	prompts, err := handler.ListPrompts()
	if err != nil {
		t.Fatalf("ListPrompts failed: %v", err)
	}

	if len(prompts) != 2 {
		t.Errorf("Expected 2 prompts, got %d", len(prompts))
	}

	expectedPrompts := map[string]bool{"troubleshoot_dns": true, "zone_setup": true}
	for _, p := range prompts {
		if !expectedPrompts[p.Name] {
			t.Errorf("Unexpected prompt: %s", p.Name)
		}
	}
}

// GetPrompt tests

func TestGetPromptTroubleshootDNS(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.GetPrompt("troubleshoot_dns", map[string]string{"domain": "example.com"})
	if err != nil {
		t.Fatalf("GetPrompt failed: %v", err)
	}

	if result.Description != "DNS troubleshooting guide" {
		t.Errorf("Unexpected description: %s", result.Description)
	}
}

func TestGetPromptZoneSetup(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.GetPrompt("zone_setup", map[string]string{"zone_name": "example.com"})
	if err != nil {
		t.Fatalf("GetPrompt failed: %v", err)
	}

	if result.Description != "Zone setup guide" {
		t.Errorf("Unexpected description: %s", result.Description)
	}
}

func TestGetPromptUnknown(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	_, err := handler.GetPrompt("unknown_prompt", nil)
	if err == nil {
		t.Error("Expected error for unknown prompt")
	}
}

// Helper function tests

func TestGetString(t *testing.T) {
	args := map[string]interface{}{
		"string": "value",
		"number": 42,
	}

	if getString(args, "string") != "value" {
		t.Error("Expected 'value'")
	}

	if getString(args, "number") != "" {
		t.Error("Expected empty string for non-string value")
	}

	if getString(args, "missing") != "" {
		t.Error("Expected empty string for missing key")
	}
}

func TestGetStringDefault(t *testing.T) {
	args := map[string]interface{}{
		"string": "value",
	}

	if getStringDefault(args, "string", "default") != "value" {
		t.Error("Expected 'value'")
	}

	if getStringDefault(args, "missing", "default") != "default" {
		t.Error("Expected 'default'")
	}
}

func TestGetIntDefault(t *testing.T) {
	args := map[string]interface{}{
		"number": float64(42),
	}

	if getIntDefault(args, "number", 0) != 42 {
		t.Error("Expected 42")
	}

	if getIntDefault(args, "missing", 100) != 100 {
		t.Error("Expected 100")
	}
}

func TestTextResult(t *testing.T) {
	result := textResult("test text")

	if len(result.Content) != 1 {
		t.Fatal("Expected 1 content item")
	}

	if result.Content[0].Text != "test text" {
		t.Errorf("Expected 'test text', got '%s'", result.Content[0].Text)
	}

	if result.IsError {
		t.Error("Expected IsError to be false")
	}
}

func TestErrorResult(t *testing.T) {
	result := errorResult("error text")

	if len(result.Content) != 1 {
		t.Fatal("Expected 1 content item")
	}

	if result.Content[0].Text != "error text" {
		t.Errorf("Expected 'error text', got '%s'", result.Content[0].Text)
	}

	if !result.IsError {
		t.Error("Expected IsError to be true")
	}
}

func TestJsonResult(t *testing.T) {
	data := map[string]string{"key": "value"}
	result := jsonResult(data)

	if len(result.Content) != 1 {
		t.Fatal("Expected 1 content item")
	}

	if result.Content[0].Type != "text" {
		t.Errorf("Expected type 'text', got '%s'", result.Content[0].Type)
	}

	if result.IsError {
		t.Error("Expected IsError to be false")
	}
}
