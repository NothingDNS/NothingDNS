package main

import "fmt"

func cmdCache(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cache subcommand required (flush, stats)")
	}

	switch args[0] {
	case "stats":
		result, err := apiGet("/api/v1/cache/stats")
		if err != nil {
			return err
		}
		fmt.Println("Cache Statistics:")
		fmt.Printf("  Size:      %v\n", result["size"])
		fmt.Printf("  Capacity:  %v\n", result["capacity"])
		fmt.Printf("  Hits:      %v\n", result["hits"])
		fmt.Printf("  Misses:    %v\n", result["misses"])
		if ratio, ok := result["hit_ratio"].(float64); ok {
			fmt.Printf("  Hit Ratio: %.2f%%\n", ratio*100)
		}

	case "flush":
		result, err := apiPost("/api/v1/cache/flush")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown cache subcommand: %s", args[0])
	}
	return nil
}
