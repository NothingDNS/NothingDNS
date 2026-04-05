package main

import (
	"fmt"
	"strings"
)

func cmdCluster(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cluster subcommand required (status, peers)")
	}

	switch args[0] {
	case "status":
		result, err := apiGet("/api/v1/cluster/status")
		if err != nil {
			return err
		}
		fmt.Println("Cluster Status:")
		printJSON("cluster", result, "  ")

	case "peers":
		result, err := apiGet("/api/v1/cluster/nodes")
		if err != nil {
			return err
		}
		nodes, ok := result["nodes"].([]interface{})
		if !ok {
			return fmt.Errorf("unexpected response format")
		}
		if len(nodes) == 0 {
			fmt.Println("No cluster nodes found (clustering may be disabled)")
			return nil
		}
		fmt.Printf("%-36s %-20s %-6s %-10s %-10s\n", "ID", "ADDRESS", "PORT", "STATE", "REGION")
		fmt.Printf("%-36s %-20s %-6s %-10s %-10s\n",
			strings.Repeat("-", 36), strings.Repeat("-", 20),
			strings.Repeat("-", 6), strings.Repeat("-", 10), strings.Repeat("-", 10))
		for _, n := range nodes {
			if nm, ok := n.(map[string]interface{}); ok {
				id, _ := nm["id"].(string)
				addr, _ := nm["addr"].(string)
				port := fmt.Sprintf("%v", nm["port"])
				state, _ := nm["state"].(string)
				region, _ := nm["region"].(string)
				fmt.Printf("%-36s %-20s %-6s %-10s %-10s\n", id, addr, port, state, region)
			}
		}

	default:
		return fmt.Errorf("unknown cluster subcommand: %s (supported: status, peers)", args[0])
	}
	return nil
}
