package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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
		result, err := apiGet("/api/v1/zones/" + zoneName + "/records")
		if err != nil {
			return err
		}
		records, ok := result["records"].([]interface{})
		if !ok {
			return fmt.Errorf("unexpected response format")
		}
		if len(records) == 0 {
			fmt.Println("No records found")
			return nil
		}
		fmt.Printf("%-40s %-8s %-8s %s\n", "NAME", "TYPE", "TTL", "DATA")
		fmt.Printf("%-40s %-8s %-8s %s\n", strings.Repeat("-", 40), strings.Repeat("-", 8), strings.Repeat("-", 8), strings.Repeat("-", 20))
		for _, r := range records {
			if rm, ok := r.(map[string]interface{}); ok {
				name, _ := rm["name"].(string)
				rtype, _ := rm["type"].(string)
				ttl := fmt.Sprintf("%v", rm["ttl"])
				data, _ := rm["data"].(string)
				fmt.Printf("%-40s %-8s %-8s %s\n", name, rtype, ttl, data)
			}
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
		body := map[string]interface{}{
			"name": name,
			"type": rtype,
			"data": rdata,
			"ttl":  ttl,
		}
		b, _ := json.Marshal(body)
		result, err := apiPost("/api/v1/zones/"+zone+"/records", string(b))
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "remove":
		if len(args) < 4 {
			return fmt.Errorf("usage: dnsctl record remove <zone> <name> <type>")
		}
		zone := args[1]
		name := args[2]
		rtype := args[3]
		body := map[string]interface{}{
			"name": name,
			"type": rtype,
		}
		b, _ := json.Marshal(body)
		result, err := apiDelete("/api/v1/zones/"+zone+"/records", string(b))
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "update":
		if len(args) < 6 {
			return fmt.Errorf("usage: dnsctl record update <zone> <name> <type> <old_data> <new_data> [ttl]")
		}
		zone := args[1]
		name := args[2]
		rtype := args[3]
		oldData := args[4]
		newData := args[5]
		ttl := 0
		if len(args) > 6 {
			if t, err := strconv.Atoi(args[6]); err == nil {
				ttl = t
			}
		}
		body := map[string]interface{}{
			"name":     name,
			"type":     rtype,
			"old_data": oldData,
			"data":     newData,
			"ttl":      ttl,
		}
		b, _ := json.Marshal(body)
		result, err := apiPut("/api/v1/zones/"+zone+"/records", string(b))
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown record subcommand: %s", args[0])
	}
	return nil
}
