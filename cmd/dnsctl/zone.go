package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func cmdZone(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("zone subcommand required (list, add, remove, reload)")
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
		ns := "ns1." + zoneName + "."
		if len(args) > 2 {
			ns = args[2]
		}
		body := map[string]interface{}{
			"name":        zoneName,
			"nameservers": []string{ns},
			"admin_email": "admin." + zoneName + ".",
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
		result, err := apiDelete("/api/v1/zones/"+zoneName, "")
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
		result, err := apiPost("/api/v1/zones/reload?zone="+zoneName, "")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown zone subcommand: %s (supported: list, add, remove, reload)", args[0])
	}
	return nil
}
