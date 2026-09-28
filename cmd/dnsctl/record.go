package main

import (
	"encoding/json"
	"fmt"
	"net/url"
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
		result, err := apiGet("/api/v1/zones/" + url.PathEscape(zoneName) + "/records")
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
		ttl := uint32(300)
		if len(args) > 5 {
			// Reject invalid TTL strings rather than silently keeping the
			// default. The old behavior accepted `record add z n A 1.2.3.4
			// abc` and inserted with TTL=300 with no warning — most users
			// reading the output would have no clue their TTL was ignored.
			t, err := parseRecordTTL(args[5])
			if err != nil {
				return err
			}
			ttl = t
		}
		body := map[string]interface{}{
			"name": name,
			"type": rtype,
			"data": rdata,
			"ttl":  ttl,
		}
		b, _ := json.Marshal(body)
		result, err := apiPost("/api/v1/zones/"+url.PathEscape(zone)+"/records", string(b))
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
		result, err := apiDelete("/api/v1/zones/"+url.PathEscape(zone)+"/records", string(b))
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
		// TTL is optional on the server: an omitted "ttl" keeps the
		// record's current TTL, while an explicit 0 is honoured as
		// "no caching" (see internal/api/api_zones.go handleUpdateRecord).
		// Defaulting to 0 and always sending it made `update` with no
		// [ttl] argument indistinguishable from asking for TTL 0, so
		// simply changing a record's address silently zeroed its TTL.
		// Only send the field when the operator actually supplied one.
		var ttl *uint32
		if len(args) > 6 {
			t, err := parseRecordTTL(args[6])
			if err != nil {
				return err
			}
			ttl = &t
		}
		body := map[string]interface{}{
			"name":     name,
			"type":     rtype,
			"old_data": oldData,
			"data":     newData,
		}
		if ttl != nil {
			body["ttl"] = *ttl
		}
		b, _ := json.Marshal(body)
		result, err := apiPut("/api/v1/zones/"+url.PathEscape(zone)+"/records", string(b))
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

func parseRecordTTL(value string) (uint32, error) {
	ttl, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid TTL %q: must be an integer between 0 and 4294967295", value)
	}
	return uint32(ttl), nil
}
