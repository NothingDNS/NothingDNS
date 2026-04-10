// Package mcp implements the Model Context Protocol (MCP) server for NothingDNS.
// MCP allows AI assistants like Claude to interact with the DNS server.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// MCP version constants
const (
	MCPVersion   = "2024-11-05"
	ProtocolName = "mcp"
)

// JSON-RPC 2.0 constants
const (
	JsonRPC = "2.0"
)

// Error codes (JSON-RPC 2.0)
const (
	ParseError     = -32700
	InvalidRequest = -32600
	MethodNotFound = -32601
	InvalidParams  = -32602
	InternalError  = -32603
)

// Common errors
var (
	ErrMethodNotFound = &RPCError{Code: MethodNotFound, Message: "Method not found"}
	ErrInvalidParams  = &RPCError{Code: InvalidParams, Message: "Invalid params"}
	ErrInternalError  = &RPCError{Code: InternalError, Message: "Internal error"}
)

// RPCError represents a JSON-RPC error
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// Request represents a JSON-RPC request
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

// Response represents a JSON-RPC response
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

// Notification represents a JSON-RPC notification
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// ServerCapabilities describes server capabilities
type ServerCapabilities struct {
	Tools     *ToolsCapabilities     `json:"tools,omitempty"`
	Resources *ResourcesCapabilities `json:"resources,omitempty"`
	Prompts   *PromptsCapabilities   `json:"prompts,omitempty"`
}

// ToolsCapabilities describes tool capabilities
type ToolsCapabilities struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapabilities describes resource capabilities
type ResourcesCapabilities struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapabilities describes prompt capabilities
type PromptsCapabilities struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ServerInfo describes server information
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Implementation describes the implementation
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeParams represents initialize request params
type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    ClientCaps     `json:"capabilities"`
	ClientInfo      Implementation `json:"clientInfo"`
}

// ClientCaps represents client capabilities
type ClientCaps struct {
	Roots    *RootsCapability `json:"roots,omitempty"`
	Sampling *SamplingCap     `json:"sampling,omitempty"`
}

// RootsCapability represents roots capability
type RootsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// SamplingCap represents sampling capability
type SamplingCap struct{}

// InitializeResult represents initialize response
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// Tool represents an MCP tool
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema represents a JSON schema for tool input
type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

// Property represents a JSON schema property
type Property struct {
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Default     interface{} `json:"default,omitempty"`
}

// ToolCallParams represents tool call parameters
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// ToolResult represents tool execution result
type ToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Content represents content in a result
type Content struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// Resource represents an MCP resource
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ResourceTemplate represents a resource template
type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// ReadResourceParams represents read resource params
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// ResourceContents represents resource contents
type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     []byte `json:"blob,omitempty"`
}

// Prompt represents an MCP prompt
type Prompt struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Arguments   []PromptArg `json:"arguments,omitempty"`
}

// PromptArg represents a prompt argument
type PromptArg struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// GetPromptParams represents get prompt params
type GetPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// PromptResult represents prompt result
type PromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// PromptMessage represents a prompt message
type PromptMessage struct {
	Role    string  `json:"role"`
	Content Content `json:"content"`
}

// Handler handles MCP requests
type Handler interface {
	ListTools() ([]Tool, error)
	CallTool(name string, args map[string]interface{}) (*ToolResult, error)
	ListResources() ([]Resource, error)
	ReadResource(uri string) (*ResourceContents, error)
	ListPrompts() ([]Prompt, error)
	GetPrompt(name string, args map[string]string) (*PromptResult, error)
}

// Server represents an MCP server
type Server struct {
	name         string
	version      string
	handler      Handler
	capabilities ServerCapabilities
	mu           sync.RWMutex
	initialized  bool
}

// NewServer creates a new MCP server
func NewServer(name, version string, handler Handler) *Server {
	return &Server{
		name:    name,
		version: version,
		handler: handler,
		capabilities: ServerCapabilities{
			Tools: &ToolsCapabilities{
				ListChanged: false,
			},
			Resources: &ResourcesCapabilities{
				Subscribe:   false,
				ListChanged: false,
			},
			Prompts: &PromptsCapabilities{
				ListChanged: false,
			},
		},
	}
}

// HandleRequest handles a single JSON-RPC request
func (s *Server) HandleRequest(ctx context.Context, req *Request) *Response {
	resp := &Response{
		JSONRPC: JsonRPC,
		ID:      req.ID,
	}

	result, err := s.dispatch(ctx, req.Method, req.Params)
	if err != nil {
		if rpcErr, ok := err.(*RPCError); ok {
			resp.Error = rpcErr
		} else {
			resp.Error = &RPCError{
				Code:    InternalError,
				Message: err.Error(),
			}
		}
		return resp
	}

	resp.Result = result
	return resp
}

// dispatch dispatches a method call
func (s *Server) dispatch(ctx context.Context, method string, params json.RawMessage) (interface{}, error) {
	switch method {
	case "initialize":
		return s.handleInitialize(params)
	case "notifications/initialized":
		s.mu.Lock()
		s.initialized = true
		s.mu.Unlock()
		return nil, nil
	case "tools/list":
		return s.handleToolsList()
	case "tools/call":
		return s.handleToolsCall(params)
	case "resources/list":
		return s.handleResourcesList()
	case "resources/read":
		return s.handleResourcesRead(params)
	case "prompts/list":
		return s.handlePromptsList()
	case "prompts/get":
		return s.handlePromptsGet(params)
	case "ping":
		return map[string]interface{}{}, nil
	default:
		return nil, ErrMethodNotFound
	}
}

func (s *Server) handleInitialize(params json.RawMessage) (*InitializeResult, error) {
	var initParams InitializeParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &initParams); err != nil {
			return nil, ErrInvalidParams
		}
	}

	return &InitializeResult{
		ProtocolVersion: MCPVersion,
		Capabilities:    s.capabilities,
		ServerInfo: ServerInfo{
			Name:    s.name,
			Version: s.version,
		},
	}, nil
}

func (s *Server) handleToolsList() (interface{}, error) {
	tools, err := s.handler.ListTools()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"tools": tools,
	}, nil
}

func (s *Server) handleToolsCall(params json.RawMessage) (*ToolResult, error) {
	var callParams ToolCallParams
	if err := json.Unmarshal(params, &callParams); err != nil {
		return nil, ErrInvalidParams
	}

	result, err := s.handler.CallTool(callParams.Name, callParams.Arguments)
	if err != nil {
		return &ToolResult{
			Content: []Content{
				{Type: "text", Text: err.Error()},
			},
			IsError: true,
		}, nil
	}
	return result, nil
}

func (s *Server) handleResourcesList() (interface{}, error) {
	resources, err := s.handler.ListResources()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"resources": resources,
	}, nil
}

func (s *Server) handleResourcesRead(params json.RawMessage) (interface{}, error) {
	var readParams ReadResourceParams
	if err := json.Unmarshal(params, &readParams); err != nil {
		return nil, ErrInvalidParams
	}

	contents, err := s.handler.ReadResource(readParams.URI)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"contents": []ResourceContents{*contents},
	}, nil
}

func (s *Server) handlePromptsList() (interface{}, error) {
	prompts, err := s.handler.ListPrompts()
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"prompts": prompts,
	}, nil
}

func (s *Server) handlePromptsGet(params json.RawMessage) (*PromptResult, error) {
	var getParams GetPromptParams
	if err := json.Unmarshal(params, &getParams); err != nil {
		return nil, ErrInvalidParams
	}

	return s.handler.GetPrompt(getParams.Name, getParams.Arguments)
}

// StdioServer wraps an MCP server with stdio transport
type StdioServer struct {
	server *Server
	reader *bufio.Reader
	writer io.Writer
}

// NewStdioServer creates a new stdio-based MCP server
func NewStdioServer(server *Server) *StdioServer {
	return &StdioServer{
		server: server,
		reader: bufio.NewReader(os.Stdin),
		writer: os.Stdout,
	}
}

// Run runs the stdio server
func (s *StdioServer) Run(ctx context.Context) error {
	encoder := json.NewEncoder(s.writer)
	decoder := json.NewDecoder(s.reader)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var req Request
		if err := decoder.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			// Send parse error
			_ = encoder.Encode(&Response{
				JSONRPC: JsonRPC,
				Error:   &RPCError{Code: ParseError, Message: "Parse error"},
				ID:      nil,
			})
			continue
		}

		resp := s.server.HandleRequest(ctx, &req)
		if resp.ID != nil || resp.Error != nil {
			if err := encoder.Encode(resp); err != nil {
				return fmt.Errorf("encode response: %w", err)
			}
		}
	}
}

// SendNotification sends a notification to the client
func (s *StdioServer) SendNotification(method string, params interface{}) error {
	encoder := json.NewEncoder(s.writer)

	notif := map[string]interface{}{
		"jsonrpc": JsonRPC,
		"method":  method,
	}
	if params != nil {
		notif["params"] = params
	}

	return encoder.Encode(notif)
}

// SSEEvent represents a Server-Sent Event
type SSEEvent struct {
	Event string
	Data  string
	ID    string
	Retry int
}

// SSETransport handles SSE-based transport for web clients
type SSETransport struct {
	server  *Server
	clients map[string]chan SSEEvent
	mu      sync.RWMutex
}

// NewSSETransport creates a new SSE transport
func NewSSETransport(server *Server) *SSETransport {
	return &SSETransport{
		server:  server,
		clients: make(map[string]chan SSEEvent),
	}
}

// AddClient adds a new SSE client
func (t *SSETransport) AddClient(id string) chan SSEEvent {
	t.mu.Lock()
	defer t.mu.Unlock()

	ch := make(chan SSEEvent, 100)
	t.clients[id] = ch
	return ch
}

// RemoveClient removes an SSE client
func (t *SSETransport) RemoveClient(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if ch, ok := t.clients[id]; ok {
		close(ch)
		delete(t.clients, id)
	}
}

// Broadcast sends an event to all clients
func (t *SSETransport) Broadcast(event SSEEvent) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, ch := range t.clients {
		select {
		case ch <- event:
		default:
			// Channel full, skip
		}
	}
}

// HandleMessage handles an incoming message from SSE client
func (t *SSETransport) HandleMessage(ctx context.Context, data []byte) ([]byte, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		resp := &Response{
			JSONRPC: JsonRPC,
			Error:   &RPCError{Code: ParseError, Message: "Parse error"},
			ID:      nil,
		}
		return json.Marshal(resp)
	}

	resp := t.server.HandleRequest(ctx, &req)
	return json.Marshal(resp)
}

// FormatSSE formats an event for SSE
func FormatSSE(event SSEEvent) string {
	result := ""
	if event.ID != "" {
		result += fmt.Sprintf("id: %s\n", event.ID)
	}
	if event.Event != "" {
		result += fmt.Sprintf("event: %s\n", event.Event)
	}
	if event.Retry > 0 {
		result += fmt.Sprintf("retry: %d\n", event.Retry)
	}
	result += fmt.Sprintf("data: %s\n\n", event.Data)
	return result
}

// ParseTimestamp parses an RFC 3339 timestamp
func ParseTimestamp(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// FormatTimestamp formats a timestamp as RFC 3339
func FormatTimestamp(t time.Time) string {
	return t.Format(time.RFC3339)
}
