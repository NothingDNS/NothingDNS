package mcp

import (
	"errors"
	"testing"
)

// Tests to cover nil zone manager paths in tool functions

// TestCallZoneGet_NilManager_ErrorPath covers the "Zone manager not configured" path.
func TestCallZoneGet_NilManager_ErrorPath(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_get", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when zone manager is nil")
	}

	if len(result.Content) == 0 {
		t.Error("Expected content in error result")
	}
}

// TestCallZoneCreate_NilManager_ErrorPath covers the "Zone manager not configured" path.
func TestCallZoneCreate_NilManager_ErrorPath(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_create", map[string]interface{}{
		"name": "newzone.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when zone manager is nil")
	}
}

// TestCallZoneDelete_NilManager_ErrorPath covers the "Zone manager not configured" path.
func TestCallZoneDelete_NilManager_ErrorPath(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_delete", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when zone manager is nil")
	}
}

// TestCallRecordAdd_NilManager_ErrorPath covers the "Zone manager not configured" path.
func TestCallRecordAdd_NilManager_ErrorPath(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

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
		t.Error("Expected error result when zone manager is nil")
	}
}

// TestCallRecordDelete_NilManager_ErrorPath covers the "Zone manager not configured" path.
func TestCallRecordDelete_NilManager_ErrorPath(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("record_delete", map[string]interface{}{
		"zone": "example.com",
		"name": "www",
		"type": "A",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when zone manager is nil")
	}
}

// TestCallRecordList_NilManager_ErrorPath covers the "Zone manager not configured" path.
func TestCallRecordList_NilManager_ErrorPath(t *testing.T) {
	handler := NewDNSToolsHandler(nil, nil, nil, nil, nil)

	result, err := handler.CallTool("record_list", map[string]interface{}{
		"zone": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when zone manager is nil")
	}
}

// TestCallZoneGet_GetZoneError covers the GetZone error path.
func TestCallZoneGet_GetZoneError(t *testing.T) {
	zm := &MockZoneManager{getErr: errors.New("internal error")}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("zone_get", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if !result.IsError {
		t.Error("Expected error result when GetZone fails")
	}
}

// TestCallZoneCreate_WithDefaultTTL covers zone create with default TTL.
func TestCallZoneCreate_WithDefaultTTL(t *testing.T) {
	zm := &MockZoneManager{}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil).WithAuth(&MockAuthProvider{})

	result, err := handler.CallTool("zone_create", map[string]interface{}{
		"name":       "newzone.com",
		"auth_token": "test-token",
		// No ttl provided - should use default 3600
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

// TestCallRecordAdd_WithDefaultTTL covers record add with default TTL.
func TestCallRecordAdd_WithDefaultTTL(t *testing.T) {
	zm := &MockZoneManager{}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil).WithAuth(&MockAuthProvider{})

	result, err := handler.CallTool("record_add", map[string]interface{}{
		"zone":       "example.com",
		"name":       "www",
		"type":       "A",
		"value":      "192.0.2.1",
		"auth_token": "test-token",
		// No ttl provided - should use default 3600
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

// TestCallRecordList_WithNameFilter covers record list with name filter.
func TestCallRecordList_WithNameFilter(t *testing.T) {
	zm := &MockZoneManager{
		records: []RecordInfo{
			{Name: "www", Type: "A", TTL: 3600, Value: "192.0.2.1"},
		},
	}
	handler := NewDNSToolsHandler(zm, nil, nil, nil, nil)

	result, err := handler.CallTool("record_list", map[string]interface{}{
		"zone": "example.com",
		"name": "www",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}

// TestCallDNSQuery_WithDefaultType tests DNS query with default type (A).
func TestCallDNSQuery_WithDefaultType(t *testing.T) {
	resolver := &MockDNSResolver{
		result: QueryResult{
			Name:    "example.com",
			Type:    "A",
			Answers: []string{"93.184.216.34"},
			RCode:   "NOERROR",
		},
	}
	handler := NewDNSToolsHandler(nil, nil, resolver, nil, nil)

	// Call without type - should default to "A"
	result, err := handler.CallTool("dns_query", map[string]interface{}{
		"name": "example.com",
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful result")
	}
}
