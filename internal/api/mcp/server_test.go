package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// MockHandler for testing
type MockHandler struct {
	tools     []Tool
	resources []Resource
	prompts   []Prompt
	// Error injection for testing error paths
	listToolsErr     error
	callToolErr      error
	listResourcesErr error
	readResourceErr  error
	listPromptsErr   error
	getPromptErr     error
}

func (h *MockHandler) ListTools() ([]Tool, error) {
	if h.listToolsErr != nil {
		return nil, h.listToolsErr
	}
	return h.tools, nil
}

func (h *MockHandler) CallTool(name string, args map[string]interface{}) (*ToolResult, error) {
	if h.callToolErr != nil {
		return nil, h.callToolErr
	}
	return &ToolResult{
		Content: []Content{{Type: "text", Text: "tool result for " + name}},
	}, nil
}

func (h *MockHandler) ListResources() ([]Resource, error) {
	if h.listResourcesErr != nil {
		return nil, h.listResourcesErr
	}
	return h.resources, nil
}

func (h *MockHandler) ReadResource(uri string) (*ResourceContents, error) {
	if h.readResourceErr != nil {
		return nil, h.readResourceErr
	}
	return &ResourceContents{
		URI:      uri,
		MimeType: "application/json",
		Text:     `{"test": "data"}`,
	}, nil
}

func (h *MockHandler) ListPrompts() ([]Prompt, error) {
	if h.listPromptsErr != nil {
		return nil, h.listPromptsErr
	}
	return h.prompts, nil
}

func (h *MockHandler) GetPrompt(name string, args map[string]string) (*PromptResult, error) {
	if h.getPromptErr != nil {
		return nil, h.getPromptErr
	}
	return &PromptResult{
		Description: "Test prompt",
		Messages: []PromptMessage{
			{Role: "user", Content: Content{Type: "text", Text: "test message"}},
		},
	}, nil
}

func TestNewServer(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	if server.name != "test-server" {
		t.Errorf("Expected name 'test-server', got '%s'", server.name)
	}

	if server.version != "1.0.0" {
		t.Errorf("Expected version '1.0.0', got '%s'", server.version)
	}

	// Verify capabilities are set
	if server.capabilities.Tools == nil {
		t.Error("Expected Tools capabilities to be set")
	}
	if server.capabilities.Resources == nil {
		t.Error("Expected Resources capabilities to be set")
	}
	if server.capabilities.Prompts == nil {
		t.Error("Expected Prompts capabilities to be set")
	}
}

func TestHandleInitialize(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	params := InitializeParams{
		ProtocolVersion: MCPVersion,
		ClientInfo: Implementation{
			Name:    "test-client",
			Version: "1.0.0",
		},
	}
	paramsJSON, _ := json.Marshal(params)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "initialize",
		Params:  paramsJSON,
		ID:      1,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(*InitializeResult)
	if !ok {
		t.Fatal("Expected InitializeResult")
	}

	if result.ProtocolVersion != MCPVersion {
		t.Errorf("Expected protocol version %s, got %s", MCPVersion, result.ProtocolVersion)
	}

	if result.ServerInfo.Name != "test-server" {
		t.Errorf("Expected server name 'test-server', got '%s'", result.ServerInfo.Name)
	}

	if result.ServerInfo.Version != "1.0.0" {
		t.Errorf("Expected server version '1.0.0', got '%s'", result.ServerInfo.Version)
	}
}

func TestHandleInitializeWithEmptyParams(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "initialize",
		Params:  nil,
		ID:      1,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(*InitializeResult)
	if !ok {
		t.Fatal("Expected InitializeResult")
	}

	if result.ProtocolVersion != MCPVersion {
		t.Errorf("Expected protocol version %s, got %s", MCPVersion, result.ProtocolVersion)
	}
}

func TestHandleInitializeWithInvalidParams(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "initialize",
		Params:  json.RawMessage(`invalid json`),
		ID:      1,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error for invalid params")
	}

	if resp.Error.Code != InvalidParams {
		t.Errorf("Expected InvalidParams error, got %d", resp.Error.Code)
	}
}

func TestHandleNotificationsInitialized(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	if server.initialized {
		t.Error("Expected server to not be initialized initially")
	}

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "notifications/initialized",
		ID:      nil,
	}

	resp := server.HandleRequest(context.Background(), req)

	// Notification should return nil result with no error
	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	if !server.initialized {
		t.Error("Expected server to be initialized after notification")
	}
}

func TestHandleToolsList(t *testing.T) {
	handler := &MockHandler{
		tools: []Tool{
			{Name: "test_tool", Description: "A test tool"},
		},
	}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "tools/list",
		ID:      2,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map result")
	}

	tools, ok := result["tools"].([]Tool)
	if !ok {
		t.Fatal("Expected tools array")
	}

	if len(tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(tools))
	}
}

func TestHandleToolsListError(t *testing.T) {
	handler := &MockHandler{
		listToolsErr: errors.New("list tools error"),
	}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "tools/list",
		ID:      2,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error from handler")
	}

	if resp.Error.Code != InternalError {
		t.Errorf("Expected InternalError, got %d", resp.Error.Code)
	}
}

func TestHandleToolsCall(t *testing.T) {
	handler := &MockHandler{
		tools: []Tool{
			{Name: "test_tool", Description: "A test tool"},
		},
	}
	server := NewServer("test-server", "1.0.0", handler)

	callParams := ToolCallParams{
		Name:      "test_tool",
		Arguments: map[string]interface{}{"arg1": "value1"},
	}
	paramsJSON, _ := json.Marshal(callParams)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "tools/call",
		Params:  paramsJSON,
		ID:      3,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("Expected ToolResult")
	}

	if len(result.Content) == 0 {
		t.Error("Expected content in result")
	}
}

func TestHandleToolsCallWithInvalidParams(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "tools/call",
		Params:  json.RawMessage(`invalid json`),
		ID:      3,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error for invalid params")
	}

	if resp.Error.Code != InvalidParams {
		t.Errorf("Expected InvalidParams error, got %d", resp.Error.Code)
	}
}

func TestHandleToolsCallWithHandlerError(t *testing.T) {
	handler := &MockHandler{
		callToolErr: errors.New("tool execution failed"),
	}
	server := NewServer("test-server", "1.0.0", handler)

	callParams := ToolCallParams{
		Name:      "test_tool",
		Arguments: map[string]interface{}{},
	}
	paramsJSON, _ := json.Marshal(callParams)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "tools/call",
		Params:  paramsJSON,
		ID:      3,
	}

	resp := server.HandleRequest(context.Background(), req)

	// Error is returned in the ToolResult, not as an RPC error
	if resp.Error != nil {
		t.Errorf("Unexpected RPC error: %v", resp.Error)
	}

	result, ok := resp.Result.(*ToolResult)
	if !ok {
		t.Fatal("Expected ToolResult")
	}

	if !result.IsError {
		t.Error("Expected IsError to be true")
	}
}

func TestHandleResourcesList(t *testing.T) {
	handler := &MockHandler{
		resources: []Resource{
			{URI: "test://resource", Name: "Test Resource"},
		},
	}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "resources/list",
		ID:      4,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map result")
	}

	resources, ok := result["resources"].([]Resource)
	if !ok {
		t.Fatal("Expected resources array")
	}

	if len(resources) != 1 {
		t.Errorf("Expected 1 resource, got %d", len(resources))
	}
}

func TestHandleResourcesListError(t *testing.T) {
	handler := &MockHandler{
		listResourcesErr: errors.New("list resources error"),
	}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "resources/list",
		ID:      4,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error from handler")
	}
}

func TestHandleResourcesRead(t *testing.T) {
	handler := &MockHandler{
		resources: []Resource{
			{URI: "test://resource", Name: "Test Resource"},
		},
	}
	server := NewServer("test-server", "1.0.0", handler)

	readParams := ReadResourceParams{
		URI: "test://resource",
	}
	paramsJSON, _ := json.Marshal(readParams)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "resources/read",
		Params:  paramsJSON,
		ID:      5,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map result")
	}

	contents, ok := result["contents"].([]ResourceContents)
	if !ok {
		t.Fatal("Expected contents array")
	}

	if len(contents) != 1 {
		t.Errorf("Expected 1 content item, got %d", len(contents))
	}

	if contents[0].URI != "test://resource" {
		t.Errorf("Expected URI 'test://resource', got '%s'", contents[0].URI)
	}
}

func TestHandleResourcesReadWithInvalidParams(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "resources/read",
		Params:  json.RawMessage(`invalid`),
		ID:      5,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error for invalid params")
	}

	if resp.Error.Code != InvalidParams {
		t.Errorf("Expected InvalidParams error, got %d", resp.Error.Code)
	}
}

func TestHandleResourcesReadError(t *testing.T) {
	handler := &MockHandler{
		readResourceErr: errors.New("resource not found"),
	}
	server := NewServer("test-server", "1.0.0", handler)

	readParams := ReadResourceParams{
		URI: "test://nonexistent",
	}
	paramsJSON, _ := json.Marshal(readParams)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "resources/read",
		Params:  paramsJSON,
		ID:      5,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error from handler")
	}
}

func TestHandlePromptsList(t *testing.T) {
	handler := &MockHandler{
		prompts: []Prompt{
			{Name: "test_prompt", Description: "A test prompt"},
		},
	}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "prompts/list",
		ID:      5,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map result")
	}

	prompts, ok := result["prompts"].([]Prompt)
	if !ok {
		t.Fatal("Expected prompts array")
	}

	if len(prompts) != 1 {
		t.Errorf("Expected 1 prompt, got %d", len(prompts))
	}
}

func TestHandlePromptsListError(t *testing.T) {
	handler := &MockHandler{
		listPromptsErr: errors.New("list prompts error"),
	}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "prompts/list",
		ID:      5,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error from handler")
	}
}

func TestHandlePromptsGet(t *testing.T) {
	handler := &MockHandler{
		prompts: []Prompt{
			{Name: "test_prompt", Description: "A test prompt"},
		},
	}
	server := NewServer("test-server", "1.0.0", handler)

	getParams := GetPromptParams{
		Name:      "test_prompt",
		Arguments: map[string]string{"arg1": "value1"},
	}
	paramsJSON, _ := json.Marshal(getParams)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "prompts/get",
		Params:  paramsJSON,
		ID:      6,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(*PromptResult)
	if !ok {
		t.Fatal("Expected PromptResult")
	}

	if result.Description != "Test prompt" {
		t.Errorf("Expected description 'Test prompt', got '%s'", result.Description)
	}
}

func TestHandlePromptsGetWithInvalidParams(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "prompts/get",
		Params:  json.RawMessage(`invalid`),
		ID:      6,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error for invalid params")
	}

	if resp.Error.Code != InvalidParams {
		t.Errorf("Expected InvalidParams error, got %d", resp.Error.Code)
	}
}

func TestHandlePromptsGetError(t *testing.T) {
	handler := &MockHandler{
		getPromptErr: errors.New("prompt not found"),
	}
	server := NewServer("test-server", "1.0.0", handler)

	getParams := GetPromptParams{
		Name: "nonexistent_prompt",
	}
	paramsJSON, _ := json.Marshal(getParams)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "prompts/get",
		Params:  paramsJSON,
		ID:      6,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error from handler")
	}
}

func TestHandleUnknownMethod(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "unknown/method",
		ID:      6,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error for unknown method")
	}

	if resp.Error.Code != MethodNotFound {
		t.Errorf("Expected MethodNotFound error, got %d", resp.Error.Code)
	}
}

func TestHandlePing(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "ping",
		ID:      7,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatal("Expected map result")
	}

	if len(result) != 0 {
		t.Error("Expected empty result for ping")
	}
}

func TestRPCError(t *testing.T) {
	err := &RPCError{
		Code:    InvalidParams,
		Message: "test error",
	}

	expected := "RPC error -32602: test error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestRPCErrorWithData(t *testing.T) {
	err := &RPCError{
		Code:    InvalidParams,
		Message: "test error",
		Data:    map[string]interface{}{"key": "value"},
	}

	expected := "RPC error -32602: test error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

func TestFormatSSE(t *testing.T) {
	event := SSEEvent{
		Event: "message",
		Data:  `{"test": "data"}`,
		ID:    "123",
	}

	formatted := FormatSSE(event)

	if formatted == "" {
		t.Error("Expected non-empty SSE format")
	}

	// Should contain event type and data
	expected := "id: 123\nevent: message\ndata: {\"test\": \"data\"}\n\n"
	if formatted != expected {
		t.Errorf("Unexpected format: %s", formatted)
	}
}

func TestFormatSSEWithRetry(t *testing.T) {
	event := SSEEvent{
		Event: "message",
		Data:  `{"test": "data"}`,
		ID:    "123",
		Retry: 5000,
	}

	formatted := FormatSSE(event)

	if formatted == "" {
		t.Error("Expected non-empty SSE format")
	}

	// Should contain retry
	if formatted != "id: 123\nevent: message\nretry: 5000\ndata: {\"test\": \"data\"}\n\n" {
		t.Errorf("Unexpected format: %s", formatted)
	}
}

func TestFormatSSEWithOnlyData(t *testing.T) {
	event := SSEEvent{
		Data: `{"test": "data"}`,
	}

	formatted := FormatSSE(event)

	if formatted == "" {
		t.Error("Expected non-empty SSE format")
	}

	// Should contain only data
	if formatted != "data: {\"test\": \"data\"}\n\n" {
		t.Errorf("Unexpected format: %s", formatted)
	}
}

func TestSSETransport(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)
	transport := NewSSETransport(server)

	// Test add/remove client
	ch := transport.AddClient("client1")
	if ch == nil {
		t.Error("Expected non-nil channel")
	}

	// Test broadcast
	transport.Broadcast(SSEEvent{
		Event: "test",
		Data:  "test data",
	})

	// Should receive on channel
	select {
	case event := <-ch:
		if event.Event != "test" {
			t.Errorf("Expected event 'test', got '%s'", event.Event)
		}
	default:
		t.Error("Expected to receive broadcast event")
	}

	// Remove client
	transport.RemoveClient("client1")

	// Channel should be closed
	_, ok := <-ch
	if ok {
		t.Error("Expected channel to be closed")
	}
}

func TestSSETransportMultipleClients(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)
	transport := NewSSETransport(server)

	ch1 := transport.AddClient("client1")
	ch2 := transport.AddClient("client2")

	transport.Broadcast(SSEEvent{
		Event: "test",
		Data:  "test data",
	})

	// Both clients should receive
	select {
	case event := <-ch1:
		if event.Event != "test" {
			t.Errorf("Expected event 'test', got '%s'", event.Event)
		}
	default:
		t.Error("Expected client1 to receive broadcast event")
	}

	select {
	case event := <-ch2:
		if event.Event != "test" {
			t.Errorf("Expected event 'test', got '%s'", event.Event)
		}
	default:
		t.Error("Expected client2 to receive broadcast event")
	}

	transport.RemoveClient("client1")
	transport.RemoveClient("client2")
}

func TestSSETransportRemoveNonExistentClient(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)
	transport := NewSSETransport(server)

	// Should not panic when removing non-existent client
	transport.RemoveClient("nonexistent")
}

func TestSSETransportBroadcastToFullChannel(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)
	transport := NewSSETransport(server)

	ch := transport.AddClient("client1")

	// Fill the channel buffer
	for i := 0; i < 100; i++ {
		select {
		case ch <- SSEEvent{Event: "fill", Data: "fill"}:
		default:
		}
	}

	// Broadcast should not block even with full channel
	transport.Broadcast(SSEEvent{
		Event: "test",
		Data:  "test data",
	})

	transport.RemoveClient("client1")
}

func TestHandleMessage(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)
	transport := NewSSETransport(server)

	req := Request{
		JSONRPC: JsonRPC,
		Method:  "ping",
		ID:      1,
	}
	data, _ := json.Marshal(req)

	resp, err := transport.HandleMessage(context.Background(), data)
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	var response Response
	if err := json.Unmarshal(resp, &response); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if response.Error != nil {
		t.Errorf("Unexpected error: %v", response.Error)
	}
}

func TestHandleMessageWithInvalidJSON(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)
	transport := NewSSETransport(server)

	resp, err := transport.HandleMessage(context.Background(), []byte(`invalid json`))
	if err != nil {
		t.Fatalf("HandleMessage failed: %v", err)
	}

	var response Response
	if err := json.Unmarshal(resp, &response); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if response.Error == nil {
		t.Error("Expected error for invalid JSON")
	}

	if response.Error.Code != ParseError {
		t.Errorf("Expected ParseError, got %d", response.Error.Code)
	}
}

func TestParseTimestamp(t *testing.T) {
	ts, err := ParseTimestamp("2024-01-15T10:30:00Z")
	if err != nil {
		t.Fatalf("ParseTimestamp failed: %v", err)
	}

	if ts.Year() != 2024 {
		t.Errorf("Expected year 2024, got %d", ts.Year())
	}
}

func TestParseTimestampInvalid(t *testing.T) {
	_, err := ParseTimestamp("invalid-timestamp")
	if err == nil {
		t.Error("Expected error for invalid timestamp")
	}
}

func TestFormatTimestamp(t *testing.T) {
	// Create a known time
	ts, err := ParseTimestamp("2024-01-15T10:30:00Z")
	if err != nil {
		t.Fatalf("ParseTimestamp failed: %v", err)
	}
	if ts.Year() != 2024 {
		t.Fatalf("Setup failed")
	}

	formatted := FormatTimestamp(ts)
	if formatted != "2024-01-15T10:30:00Z" {
		t.Errorf("Unexpected format: %s", formatted)
	}
}

func TestNewStdioServer(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)
	stdioServer := NewStdioServer(server)

	if stdioServer.server != server {
		t.Error("Expected server to be set")
	}

	if stdioServer.reader == nil {
		t.Error("Expected reader to be set")
	}

	if stdioServer.writer == nil {
		t.Error("Expected writer to be set")
	}
}

func TestConstants(t *testing.T) {
	// Test version constants
	if MCPVersion != "2024-11-05" {
		t.Errorf("Unexpected MCPVersion: %s", MCPVersion)
	}

	if ProtocolName != "mcp" {
		t.Errorf("Unexpected ProtocolName: %s", ProtocolName)
	}

	if JsonRPC != "2.0" {
		t.Errorf("Unexpected JsonRPC: %s", JsonRPC)
	}

	// Test error codes
	if ParseError != -32700 {
		t.Errorf("Unexpected ParseError: %d", ParseError)
	}

	if InvalidRequest != -32600 {
		t.Errorf("Unexpected InvalidRequest: %d", InvalidRequest)
	}

	if MethodNotFound != -32601 {
		t.Errorf("Unexpected MethodNotFound: %d", MethodNotFound)
	}

	if InvalidParams != -32602 {
		t.Errorf("Unexpected InvalidParams: %d", InvalidParams)
	}

	if InternalError != -32603 {
		t.Errorf("Unexpected InternalError: %d", InternalError)
	}
}

func TestCommonErrors(t *testing.T) {
	if ErrMethodNotFound.Code != MethodNotFound {
		t.Errorf("Unexpected ErrMethodNotFound code: %d", ErrMethodNotFound.Code)
	}

	if ErrInvalidParams.Code != InvalidParams {
		t.Errorf("Unexpected ErrInvalidParams code: %d", ErrInvalidParams.Code)
	}

	if ErrInternalError.Code != InternalError {
		t.Errorf("Unexpected ErrInternalError code: %d", ErrInternalError.Code)
	}
}

func TestRequestResponseIDTypes(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	// Test with string ID
	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "ping",
		ID:      "string-id",
	}

	resp := server.HandleRequest(context.Background(), req)
	if resp.ID != "string-id" {
		t.Errorf("Expected ID 'string-id', got %v", resp.ID)
	}

	// Test with numeric ID
	req.ID = 42
	resp = server.HandleRequest(context.Background(), req)
	if resp.ID != 42 {
		t.Errorf("Expected ID 42, got %v", resp.ID)
	}

	// Test with nil ID (notification)
	req.ID = nil
	resp = server.HandleRequest(context.Background(), req)
	if resp.ID != nil {
		t.Errorf("Expected nil ID, got %v", resp.ID)
	}
}

func TestHandleRequestWithNonRPCError(t *testing.T) {
	handler := &MockHandler{
		listToolsErr: errors.New("non-RPC error"),
	}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "tools/list",
		ID:      1,
	}

	resp := server.HandleRequest(context.Background(), req)

	if resp.Error == nil {
		t.Error("Expected error")
	}

	// Non-RPC errors should be wrapped as InternalError
	if resp.Error.Code != InternalError {
		t.Errorf("Expected InternalError, got %d", resp.Error.Code)
	}

	if resp.Error.Message != "non-RPC error" {
		t.Errorf("Expected message 'non-RPC error', got '%s'", resp.Error.Message)
	}
}
