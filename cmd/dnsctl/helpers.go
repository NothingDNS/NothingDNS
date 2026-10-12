package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const maxAPIResponseBody = 10 << 20

// ============================================================================
// HTTP client helpers
// ============================================================================

// buildAPIRequest constructs an *http.Request against the configured --server,
// validating the URL scheme and attaching the JSON content type (when a body is
// present) and the bearer auth header. Shared by apiRequest and apiGetRaw.
func buildAPIRequest(method, path, body string) (*http.Request, error) {
	server := strings.TrimRight(globalFlags.Server, "/")
	// Reject scheme-less server URLs with a clear, actionable message.
	// Without this guard, `--server localhost:8080` is interpreted by
	// Go's net/url parser as scheme="localhost" rest="8080/api/...",
	// and the request fails with the cryptic
	//   `unsupported protocol scheme "localhost"`.
	// Most operators reach for `localhost:8080` reflexively.
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		return nil, fmt.Errorf("--server must start with http:// or https://, got %q", globalFlags.Server)
	}
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, server+path, bodyReader)
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if globalFlags.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+globalFlags.APIKey)
	}
	return req, nil
}

// doAPIRequest executes req, reads the (size-limited) body, and turns a non-2xx
// status into an error that prefers the server's JSON {"error": ...} message.
// On success it returns the raw response body bytes.
func doAPIRequest(req *http.Request) ([]byte, error) {
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := readAPIResponseBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errResp map[string]interface{}
		if json.Unmarshal(respBody, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func readAPIResponseBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxAPIResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxAPIResponseBody {
		return nil, fmt.Errorf("response body exceeds %d byte limit", maxAPIResponseBody)
	}
	return body, nil
}

func apiRequest(method, path, body string) (map[string]interface{}, error) {
	req, err := buildAPIRequest(method, path, body)
	if err != nil {
		return nil, err
	}
	respBody, err := doAPIRequest(req)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	return result, nil
}

func apiGet(path string) (map[string]interface{}, error) {
	return apiRequest("GET", path, "")
}

// apiGetRaw issues a GET and returns the raw response body bytes,
// for endpoints that don't return JSON (e.g. /zones/{name}/export
// emits BIND-format zone text with application/x-zone-file). Auth
// and base URL handling match apiRequest.
func apiGetRaw(path string) ([]byte, error) {
	req, err := buildAPIRequest("GET", path, "")
	if err != nil {
		return nil, err
	}
	return doAPIRequest(req)
}

func apiPost(path, body string) (map[string]interface{}, error) {
	return apiRequest("POST", path, body)
}

func apiPut(path, body string) (map[string]interface{}, error) {
	return apiRequest("PUT", path, body)
}

func apiDelete(path, body string) (map[string]interface{}, error) {
	return apiRequest("DELETE", path, body)
}

func printJSON(key string, val interface{}, indent string) {
	switch v := val.(type) {
	case map[string]interface{}:
		fmt.Printf("%s%s:\n", indent, key)
		for k, vv := range v {
			printJSON(k, vv, indent+"  ")
		}
	case []interface{}:
		fmt.Printf("%s%s:\n", indent, key)
		for i, vv := range v {
			printJSON(fmt.Sprintf("[%d]", i), vv, indent+"  ")
		}
	default:
		fmt.Printf("%s%s: %s\n", indent, key, jsonValueString(val))
	}
}

// jsonValueString formats a decoded JSON scalar. Numbers arrive as float64,
// which "%v" prints in exponent form from seven digits up (2.024010101e+09);
// they are written as plain decimals instead (F712).
func jsonValueString(v interface{}) string {
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprintf("%v", v)
}
