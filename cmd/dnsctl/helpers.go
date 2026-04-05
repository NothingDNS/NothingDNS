package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ============================================================================
// HTTP client helpers
// ============================================================================

func apiGet(path string) (map[string]interface{}, error) {
	url := strings.TrimRight(globalFlags.Server, "/") + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if globalFlags.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+globalFlags.APIKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if json.Unmarshal(body, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	return result, nil
}

func apiPost(path string) (map[string]interface{}, error) {
	url := strings.TrimRight(globalFlags.Server, "/") + path
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	if globalFlags.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+globalFlags.APIKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if json.Unmarshal(body, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	return result, nil
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
		fmt.Printf("%s%s: %v\n", indent, key, val)
	}
}
