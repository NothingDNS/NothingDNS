package main

import (
	"fmt"
	"strings"
)

func cmdZone(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("zone subcommand required (list, reload)")
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

	case "reload":
		if len(args) < 2 {
			return fmt.Errorf("zone name required: dnsctl zone reload <zone>")
		}
		zoneName := args[1]
		result, err := apiPost("/api/v1/zones/reload?zone=" + zoneName)
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown zone subcommand: %s (supported: list, reload)", args[0])
	}
	return nil
}
