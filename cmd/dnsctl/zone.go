package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

func cmdZone(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("zone subcommand required (list, add, remove, reload, export, soa)")
	}

	switch args[0] {
	case "list":
		result, err := apiGet("/api/v1/zones")
		if err != nil {
			return err
		}
		zones, ok := result["zones"].([]interface{})
		if !ok {
			return fmt.Errorf("unexpected response format")
		}
		if len(zones) == 0 {
			fmt.Println("No zones configured")
			return nil
		}
		fmt.Printf("%-40s %s\n", "ZONE", "RECORDS")
		fmt.Printf("%-40s %s\n", strings.Repeat("-", 40), strings.Repeat("-", 10))
		for _, z := range zones {
			if zm, ok := z.(map[string]interface{}); ok {
				name, _ := zm["name"].(string)
				records, _ := zm["records"].(float64)
				fmt.Printf("%-40s %d\n", name, int(records))
			}
		}

	case "add":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone add <zone> [nameserver]")
		}
		zoneName := args[1]
		// Normalize: drop any trailing dot before composing default
		// nameserver / admin-email FQDNs. Pre-fix, calling
		// `dnsctl zone add example.com.` produced a double-dotted
		// ns/admin name like `ns1.example.com..` and the server's
		// SOA validation rejected it; users who reflexively typed
		// the absolute form got an unhelpful 400 instead of a
		// working zone.
		bareZone := strings.TrimSuffix(zoneName, ".")
		ns := "ns1." + bareZone + "."
		if len(args) > 2 {
			ns = args[2]
		}
		body := map[string]interface{}{
			"name":        zoneName,
			"nameservers": []string{ns},
			"admin_email": "admin." + bareZone + ".",
			"ttl":         3600,
		}
		b, _ := json.Marshal(body)
		result, err := apiPost("/api/v1/zones", string(b))
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone remove <zone>")
		}
		zoneName := args[1]
		result, err := apiDelete("/api/v1/zones/"+url.PathEscape(zoneName), "")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "reload":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone reload <zone>")
		}
		zoneName := args[1]
		result, err := apiPost("/api/v1/zones/reload?zone="+url.QueryEscape(zoneName), "")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	case "export":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone export <zone>")
		}
		zoneName := args[1]
		body, err := apiGetRaw("/api/v1/zones/" + url.PathEscape(zoneName) + "/export")
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(body); err != nil {
			return fmt.Errorf("failed to write zone export: %w", err)
		}
		if len(body) > 0 && body[len(body)-1] != '\n' {
			fmt.Println()
		}

	case "soa":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone soa <zone> [field=value ...]")
		}
		return zoneSOA(args[1], args[2:])

	default:
		return fmt.Errorf("unknown zone subcommand: %s (supported: list, add, remove, reload, export, soa)", args[0])
	}
	return nil
}

// soaNumberFields are the SOA fields set as numbers (seconds).
var soaNumberFields = map[string]bool{"ttl": true, "refresh": true, "retry": true, "expire": true, "minimum": true}

// zoneSOA shows the zone's SOA or, given field=value arguments, changes those
// fields (GET/PUT /api/v1/zones/{zone}/soa). The server bumps the serial.
func zoneSOA(zoneName string, sets []string) error {
	path := "/api/v1/zones/" + url.PathEscape(zoneName) + "/soa"
	var (
		result map[string]interface{}
		err    error
	)
	if len(sets) == 0 {
		result, err = apiGet(path)
	} else {
		body := make(map[string]interface{}, len(sets))
		for _, set := range sets {
			field, value, ok := strings.Cut(set, "=")
			field = strings.ToLower(field)
			switch {
			case !ok || value == "":
				return fmt.Errorf("invalid SOA setting %q: want field=value", set)
			case field == "mname" || field == "rname":
				body[field] = value
			case soaNumberFields[field]:
				n, perr := strconv.ParseUint(value, 10, 32)
				if perr != nil {
					return fmt.Errorf("invalid %s %q: want seconds", field, value)
				}
				body[field] = n
			case field == "serial":
				return fmt.Errorf("the SOA serial is managed by the server and bumped on every change")
			default:
				return fmt.Errorf("unknown SOA field %q (mname, rname, ttl, refresh, retry, expire, minimum)", field)
			}
		}
		b, _ := json.Marshal(body)
		result, err = apiPut(path, string(b))
	}
	if err != nil {
		return err
	}
	for _, f := range []string{"mname", "rname", "ttl", "serial", "refresh", "retry", "expire", "minimum"} {
		switch v := result[f].(type) {
		case string:
			fmt.Printf("%-8s %s\n", f, v)
		case float64:
			fmt.Printf("%-8s %d\n", f, uint64(v))
		}
	}
	return nil
}
