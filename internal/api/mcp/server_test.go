package mcp

import (
	"context"
	"encoding/json"
	"testing"
)

// MockHandler for testing
type MockHandler struct {
	tools     []Tool
	resources []Resource
	prompts   []Prompt
}

func (h *MockHandler) ListTools() ([]Tool, error) {
	return h.tools, nil
}

func (h *MockHandler) CallTool(name string, args map[string]interface{}) (*ToolResult, error) {
	return &ToolResult{
		Content: []Content{{Type: "text", Text: "tool result for " + name}},
	}, nil
}

func (h *MockHandler) ListResources() ([]Resource, error) {
	return h.resources, nil
}

func (h *MockHandler) ReadResource(uri string) (*ResourceContents, error) {
	return &ResourceContents{
		URI:      uri,
		MimeType: "application/json",
		Text:     `{"test": "data"}`,
	}, nil
}

func (h *MockHandler) ListPrompts() ([]Prompt, error) {
	return h.prompts, nil
}

func (h *MockHandler) GetPrompt(name string, args map[string]string) (*PromptResult, error) {
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
	if formatted != "id: 123\nevent: message\ndata: {\"test\": \"data\"}\n\n" {
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
