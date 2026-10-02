// Command quickstart demonstrates the NothingDNS Go SDK end to end: it logs
// in, lists the zones, adds a record, reads the cache statistics and prints a
// zone export.
//
// Credentials and the server address are read from the environment so that
// nothing sensitive is hardcoded:
//
//	export NDNS_URL="http://localhost:8080"
//	export NDNS_USER="admin"
//	export NDNS_PASSWORD="…"
//	go run ./examples/quickstart
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	nothingdns "github.com/nothingdns/nothingdns/sdk/go"
)

func main() {
	baseURL := os.Getenv("NDNS_URL")
	if baseURL == "" {
		baseURL = nothingdns.DefaultBaseURL
	}
	username := os.Getenv("NDNS_USER")
	password := os.Getenv("NDNS_PASSWORD")
	if username == "" || password == "" {
		log.Fatal("set NDNS_USER and NDNS_PASSWORD before running this example")
	}

	// A single timeout context bounds the whole example.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := nothingdns.NewClient(baseURL, "", 10*time.Second, nil, nil)
	defer client.Close()

	// 1. Log in and keep the returned bearer token on the client.
	session, err := client.Auth.Login(ctx, username, password, true)
	if err != nil {
		log.Fatalf("login failed: %v", err)
	}
	fmt.Printf("logged in as %s (%s)\n", session.Username, session.Role)

	// 2. List the zones served by this node.
	zones, err := client.Zones.List(ctx)
	if err != nil {
		log.Fatalf("list zones failed: %v", err)
	}
	fmt.Printf("zones (%d total):\n", zones.Total)
	for _, z := range zones.Zones {
		fmt.Printf("  - %s (serial %d, %d records)\n", z.Name, z.Serial, z.Records)
	}
	if len(zones.Zones) == 0 {
		fmt.Println("  (no zones yet — create one with client.Zones.Create)")
		return
	}

	// Work against the first zone.
	zone := zones.Zones[0].Name

	// 3. Add a record to that zone. A trailing dot is optional.
	ttl := 300
	_, err = client.Zones.AddRecord(ctx, zone, "www", "A", "192.0.2.1",
		&nothingdns.AddRecordOptions{TTL: &ttl})
	if err != nil && !nothingdns.IsNotFound(err) {
		// A conflict (the record already exists) is not fatal for this
		// example; anything else is.
		fmt.Printf("add record: %v\n", err)
	} else {
		fmt.Printf("added www.%s A 192.0.2.1\n", zone)
	}

	// 4. Read the cache statistics.
	stats, err := client.Cache.Stats(ctx)
	if err != nil {
		log.Fatalf("cache stats failed: %v", err)
	}
	fmt.Printf("cache: %d/%d entries, %d hits, %d misses, hit ratio %.2f\n",
		stats.Size, stats.Capacity, stats.Hits, stats.Misses, stats.HitRatio)

	// 5. Print the zone export in BIND zone-file format.
	export, err := client.Zones.Export(ctx, zone)
	if err != nil {
		log.Fatalf("zone export failed: %v", err)
	}
	fmt.Printf("export of %s:\n%s\n", zone, export)
}
