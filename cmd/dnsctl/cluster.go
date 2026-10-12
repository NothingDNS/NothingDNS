package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func cmdCluster(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cluster subcommand required (status, peers, join, leave)")
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
				port := jsonValueString(nm["port"])
				state, _ := nm["state"].(string)
				region, _ := nm["region"].(string)
				fmt.Printf("%-36s %-20s %-6s %-10s %-10s\n", id, addr, port, state, region)
			}
		}

	case "join":
		if len(args) < 2 {
			return fmt.Errorf("seed node address required: dnsctl cluster join <address>[:port]")
		}
		seedAddr := args[1]
		body := map[string]interface{}{
			"seed_address": seedAddr,
		}
		b, _ := json.Marshal(body)
		result, err := apiPost("/api/v1/cluster/join", string(b))
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "leave":
		// The server-side /api/v1/cluster/leave removes the *local*
		// node from the cluster — it does not accept a target node-id.
		// Previously this CLI demanded one and silently shipped it in
		// the body where it was discarded, which was a confusing
		// contract mismatch ("dnsctl cluster leave abc" looked like it
		// would evict node abc, but evicted whatever node the API was
		// talking to). Accept an optional arg for forward compatibility
		// but neither require it nor send it.
		result, err := apiDelete("/api/v1/cluster/leave", "{}")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown cluster subcommand: %s (supported: status, peers, join, leave)", args[0])
	}
	return nil
}
