package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func cmdBlocklist(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("blocklist subcommand required (status)")
	}

	switch args[0] {
	case "status":
		result, err := apiGet("/api/v1/status")
		if err != nil {
			return err
		}
		fmt.Println("Server Status:")
		if status, ok := result["status"].(string); ok {
			fmt.Printf("  Status: %s\n", status)
		}
		if version, ok := result["version"].(string); ok {
			fmt.Printf("  Version: %s\n", version)
		}

	default:
		return fmt.Errorf("unknown blocklist subcommand: %s", args[0])
	}
	return nil
}

func cmdConfig(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("config subcommand required (reload)")
	}

	switch args[0] {
	case "reload":
		result, err := apiPost("/api/v1/config/reload")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown config subcommand: %s (supported: reload)", args[0])
	}
	return nil
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
		url := strings.TrimRight(globalFlags.Server, "/") + "/health"
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Printf("Server unhealthy: %v\n", err)
			os.Exit(1)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Printf("Server unhealthy: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			fmt.Printf("Server healthy: %s", string(body))
		} else {
			fmt.Printf("Server unhealthy (HTTP %d): %s\n", resp.StatusCode, string(body))
			os.Exit(1)
		}

	default:
		return fmt.Errorf("unknown server subcommand: %s (supported: status, health)", args[0])
	}
	return nil
}
