package main

import (
	"fmt"
	"net/http"
	"strings"
)

func cmdBlocklist(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("blocklist subcommand required (status, sources, reload)")
	}

	switch args[0] {
	case "status":
		result, err := apiGet("/api/v1/blocklists")
		if err != nil {
			return err
		}
		fmt.Println("Blocklist Status:")
		if enabled, ok := result["enabled"].(bool); ok {
			fmt.Printf("  Enabled:    %v\n", enabled)
		}
		if total, ok := result["total_rules"].(float64); ok {
			fmt.Printf("  Total Rules: %d\n", int(total))
		}
		if files, ok := result["files_count"].(float64); ok {
			fmt.Printf("  Files:      %d\n", int(files))
		}
		if urls, ok := result["urls_count"].(float64); ok {
			fmt.Printf("  URLs:       %d\n", int(urls))
		}
		if hitCount, ok := result["hit_count"].(float64); ok {
			fmt.Printf("  Hits:       %d\n", int(hitCount))
		}
		if lastReload, ok := result["last_reload"].(string); ok {
			fmt.Printf("  Last Reload: %s\n", lastReload)
		}

	case "sources":
		result, err := apiGet("/api/v1/blocklists/sources")
		if err != nil {
			return err
		}
		sources, ok := result["sources"].([]interface{})
		if !ok {
			sources, ok = result["blocklists"].([]interface{})
		}
		if !ok {
			fmt.Println("No sources information available")
			return nil
		}
		if len(sources) == 0 {
			fmt.Println("No blocklist sources configured")
			return nil
		}
		for _, s := range sources {
			if sm, ok := s.(map[string]interface{}); ok {
				id, _ := sm["id"].(string)
				if id == "" {
					id, _ = sm["source"].(string)
				}
				enabled, _ := sm["enabled"].(bool)
				fmt.Printf("  %s (enabled=%v)\n", id, enabled)
			}
		}

	case "reload":
		result, err := apiPost("/api/v1/config/reload", "")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown blocklist subcommand: %s (supported: status, sources, reload)", args[0])
	}
	return nil
}

func cmdConfig(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("config subcommand required (get, reload)")
	}

	switch args[0] {
	case "get":
		result, err := apiGet("/api/v1/config")
		if err != nil {
			return err
		}
		if len(args) >= 2 && args[1] != "" {
			key := args[1]
			val, ok := lookupConfigPath(result, key)
			if !ok {
				return fmt.Errorf("no such config key: %s", key)
			}
			printJSON(key, val, "")
			return nil
		}
		fmt.Println("Server Configuration:")
		printJSON("config", result, "  ")

	case "reload":
		result, err := apiPost("/api/v1/config/reload", "")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown config subcommand: %s (supported: get, reload)", args[0])
	}
	return nil
}

// lookupConfigPath walks a dot-separated path through a decoded JSON
// map / slice tree. Path segments are compared case-insensitively
// because the server may marshal struct fields with PascalCase keys
// (e.g. "Server.Port") while users expect dotted lowercase
// ("server.port"). Returns the leaf value and true on a clean walk.
func lookupConfigPath(root interface{}, dotted string) (interface{}, bool) {
	if dotted == "" {
		return root, true
	}
	parts := strings.Split(dotted, ".")
	cur := root
	for _, p := range parts {
		switch v := cur.(type) {
		case map[string]interface{}:
			found := false
			for k, vv := range v {
				if strings.EqualFold(k, p) {
					cur = vv
					found = true
					break
				}
			}
			if !found {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	return cur, true
}

func cmdServer(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("server subcommand required (status, health)")
	}

	switch args[0] {
	case "status":
		result, err := apiGet("/api/v1/status")
		if err != nil {
			return err
		}
		fmt.Println("Server Status:")
		if status, ok := result["status"].(string); ok {
			fmt.Printf("  Status:    %s\n", status)
		}
		if version, ok := result["version"].(string); ok {
			fmt.Printf("  Version:   %s\n", version)
		}
		if ts, ok := result["timestamp"].(string); ok {
			fmt.Printf("  Timestamp: %s\n", ts)
		}
		if cache, ok := result["cache"].(map[string]interface{}); ok {
			fmt.Println("  Cache:")
			fmt.Printf("    Size:     %v\n", cache["size"])
			fmt.Printf("    Capacity: %v\n", cache["capacity"])
			fmt.Printf("    Hits:     %v\n", cache["hits"])
			fmt.Printf("    Misses:   %v\n", cache["misses"])
			if ratio, ok := cache["hit_ratio"].(float64); ok {
				fmt.Printf("    Hit Ratio: %.2f%%\n", ratio*100)
			}
		}
		if cluster, ok := result["cluster"].(map[string]interface{}); ok {
			fmt.Println("  Cluster:")
			if enabled, ok := cluster["enabled"].(bool); ok {
				fmt.Printf("    Enabled: %v\n", enabled)
			}
			if nodeID, ok := cluster["node_id"].(string); ok {
				fmt.Printf("    Node ID: %s\n", nodeID)
			}
			if nodeCount, ok := cluster["node_count"].(float64); ok {
				fmt.Printf("    Nodes:   %d\n", int(nodeCount))
			}
			if healthy, ok := cluster["healthy"].(bool); ok {
				fmt.Printf("    Healthy: %v\n", healthy)
			}
		}

	case "health":
		req, err := buildAPIRequest("GET", "/health", "")
		if err != nil {
			return fmt.Errorf("server unhealthy: %w", err)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("server unhealthy: %w", err)
		}
		defer resp.Body.Close()
		body, err := readAPIResponseBody(resp.Body)
		if err != nil {
			return fmt.Errorf("reading health response: %w", err)
		}
		if resp.StatusCode == http.StatusOK {
			fmt.Printf("Server healthy: %s", string(body))
		} else {
			return fmt.Errorf("server unhealthy (HTTP %d): %s", resp.StatusCode, string(body))
		}

	default:
		return fmt.Errorf("unknown server subcommand: %s (supported: status, health)", args[0])
	}
	return nil
}
