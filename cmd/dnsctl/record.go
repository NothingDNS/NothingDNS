package main

import (
	"fmt"
	"strconv"
)

func cmdRecord(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("record subcommand required (add, remove, update, list)")
	}

	switch args[0] {
	case "list":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl record list <zone>")
		}
		zoneName := args[1]
		result, err := apiGet("/api/v1/zones")
		if err != nil {
			return err
		}
		zones, ok := result["zones"].([]interface{})
		if !ok {
			return fmt.Errorf("unexpected response format")
		}
		found := false
		for _, z := range zones {
			if zm, ok := z.(map[string]interface{}); ok {
				if name, _ := zm["name"].(string); name == zoneName {
					records, _ := zm["records"].(float64)
					fmt.Printf("Zone: %s (%d records)\n", zoneName, int(records))
					found = true
					break
				}
			}
		}
		if !found {
			fmt.Printf("Zone %s not found\n", zoneName)
		}

	case "add":
		if len(args) < 5 {
			return fmt.Errorf("usage: dnsctl record add <zone> <name> <type> <rdata> [ttl]")
		}
		zone := args[1]
		name := args[2]
		rtype := args[3]
		rdata := args[4]
		ttl := 300
		if len(args) > 5 {
			if t, err := strconv.Atoi(args[5]); err == nil {
				ttl = t
			}
		}
		fmt.Printf("Adding record to zone %s: %s %s %s (TTL: %d)\n", zone, name, rtype, rdata, ttl)
		fmt.Println("Note: Record management via REST API requires dynamic DNS (RFC 2136)")

	case "remove":
		if len(args) < 4 {
			return fmt.Errorf("usage: dnsctl record remove <zone> <name> <type>")
		}
		zone := args[1]
		name := args[2]
		rtype := args[3]
		fmt.Printf("Removing record from zone %s: %s %s\n", zone, name, rtype)
		fmt.Println("Note: Record management via REST API requires dynamic DNS (RFC 2136)")

	case "update":
		if len(args) < 5 {
			return fmt.Errorf("usage: dnsctl record update <zone> <name> <type> <rdata> [ttl]")
		}
		zone := args[1]
		name := args[2]
		rtype := args[3]
		rdata := args[4]
		fmt.Printf("Updating record in zone %s: %s %s %s\n", zone, name, rtype, rdata)
		fmt.Println("Note: Record management via REST API requires dynamic DNS (RFC 2136)")

	default:
		return fmt.Errorf("unknown record subcommand: %s", args[0])
	}
	return nil
}
