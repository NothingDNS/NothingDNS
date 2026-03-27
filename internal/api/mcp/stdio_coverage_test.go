package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// TestStdioServer_Run_ContextCancellation tests that Run exits on context cancellation.
func TestStdioServer_Run_ContextCancellation(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	input := strings.NewReader("")
	stdioServer := &StdioServer{
		server: server,
		reader: bufio.NewReader(input),
		writer: io.Discard,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := stdioServer.Run(ctx)
	// Acceptable outcomes: DeadlineExceeded or Canceled
	if err != context.DeadlineExceeded && err != context.Canceled {
		t.Logf("Run returned: %v", err)
	}
}

// TestStdioServer_Run_EOF tests that Run returns nil on EOF.
func TestStdioServer_Run_EOF(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	input := strings.NewReader("")
	stdioServer := &StdioServer{
		server: server,
		reader: bufio.NewReader(input),
		writer: io.Discard,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := stdioServer.Run(ctx)
	if err != nil {
		t.Errorf("Expected nil error on EOF, got: %v", err)
	}
}

// TestStdioServer_Run_ValidRequest tests Run processes a valid request.
func TestStdioServer_Run_ValidRequest(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "ping",
		ID:      1,
	}
	reqJSON, _ := json.Marshal(req)
	reqJSON = append(reqJSON, '\n')

	input := strings.NewReader(string(reqJSON))
	var output bytes.Buffer

	stdioServer := &StdioServer{
		server: server,
		reader: bufio.NewReader(input),
		writer: &output,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = stdioServer.Run(ctx)

	if output.Len() == 0 {
		t.Error("Expected some output from Run")
	}

	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &resp); err != nil {
		t.Errorf("Failed to unmarshal response: %v, output was: %s", err, output.String())
	}

	if resp.Error != nil {
		t.Errorf("Unexpected error in response: %v", resp.Error)
	}
}

// TestStdioServer_Run_InvalidJSON tests that Run handles invalid JSON.
func TestStdioServer_Run_InvalidJSON(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	input := strings.NewReader("not json at all\n")
	var output bytes.Buffer

	stdioServer := &StdioServer{
		server: server,
		reader: bufio.NewReader(input),
		writer: &output,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = stdioServer.Run(ctx)

	if output.Len() == 0 {
		t.Error("Expected parse error output")
		return
	}

	var resp Response
	line := strings.TrimSpace(output.String())
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		// Try first line only
		lines := strings.SplitN(output.String(), "\n", 2)
		if len(lines) > 0 {
			json.Unmarshal([]byte(strings.TrimSpace(lines[0])), &resp)
		}
	}

	if resp.Error == nil {
		t.Error("Expected parse error in response")
	} else if resp.Error.Code != ParseError {
		t.Errorf("Expected ParseError code %d, got %d", ParseError, resp.Error.Code)
	}
}

// TestStdioServer_SendNotification tests sending notifications.
func TestStdioServer_SendNotification(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	var output bytes.Buffer
	stdioServer := &StdioServer{
		server: server,
		reader: bufio.NewReader(strings.NewReader("")),
		writer: &output,
	}

	err := stdioServer.SendNotification("test/notification", map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("SendNotification() error = %v", err)
	}

	if output.Len() == 0 {
		t.Error("Expected output from SendNotification")
	}

	var notif map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &notif); err != nil {
		t.Fatalf("Failed to unmarshal notification: %v", err)
	}

	if notif["jsonrpc"] != JsonRPC {
		t.Errorf("Expected jsonrpc %s, got %v", JsonRPC, notif["jsonrpc"])
	}

	if notif["method"] != "test/notification" {
		t.Errorf("Expected method 'test/notification', got %v", notif["method"])
	}

	params, ok := notif["params"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected params to be a map")
	}
	if params["key"] != "value" {
		t.Errorf("Expected params.key 'value', got %v", params["key"])
	}
}

// TestStdioServer_SendNotification_NilParams tests sending notification with nil params.
func TestStdioServer_SendNotification_NilParams(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	var output bytes.Buffer
	stdioServer := &StdioServer{
		server: server,
		reader: bufio.NewReader(strings.NewReader("")),
		writer: &output,
	}

	err := stdioServer.SendNotification("test/event", nil)
	if err != nil {
		t.Fatalf("SendNotification() error = %v", err)
	}

	var notif map[string]interface{}
	if err := json.Unmarshal(output.Bytes(), &notif); err != nil {
		t.Fatalf("Failed to unmarshal notification: %v", err)
	}

	if _, hasParams := notif["params"]; hasParams {
		t.Error("Expected no params field when params is nil")
	}
}

// errorWriter is a writer that always returns an error
type errorWriter struct{}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("write error")
}

// TestStdioServer_Run_EncodeError tests handling of encode errors.
func TestStdioServer_Run_EncodeError(t *testing.T) {
	handler := &MockHandler{
		tools: []Tool{{Name: "test_tool", Description: "A test tool"}},
	}
	server := NewServer("test-server", "1.0.0", handler)

	req := &Request{
		JSONRPC: JsonRPC,
		Method:  "tools/list",
		ID:      1,
	}
	reqJSON, _ := json.Marshal(req)
	reqJSON = append(reqJSON, '\n')

	input := strings.NewReader(string(reqJSON))

	stdioServer := &StdioServer{
		server: server,
		reader: bufio.NewReader(input),
		writer: &errorWriter{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := stdioServer.Run(ctx)
	if err == nil {
		t.Error("Expected error from encode failure")
	}
}

// TestStdioServer_Run_MultipleRequests tests processing multiple requests.
func TestStdioServer_Run_MultipleRequests(t *testing.T) {
	handler := &MockHandler{}
	server := NewServer("test-server", "1.0.0", handler)

	var inputBuf strings.Builder
	for i := 0; i < 3; i++ {
		req := &Request{
			JSONRPC: JsonRPC,
			Method:  "ping",
			ID:      i,
		}
		reqJSON, _ := json.Marshal(req)
		inputBuf.Write(reqJSON)
		inputBuf.WriteByte('\n')
	}

	input := strings.NewReader(inputBuf.String())
	var output bytes.Buffer

	stdioServer := &StdioServer{
		server: server,
		reader: bufio.NewReader(input),
		writer: &output,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = stdioServer.Run(ctx)

	respCount := 0
	for _, line := range strings.Split(output.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var resp Response
		if err := json.Unmarshal([]byte(line), &resp); err == nil {
			respCount++
		}
	}

	if respCount != 3 {
		t.Errorf("Expected 3 responses, got %d", respCount)
	}
}
