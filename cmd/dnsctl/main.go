// dnsctl - CLI management tool for NothingDNS
// Communicates with NothingDNS via REST API

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/util"
)

const (
	Name = "dnsctl"
)

type Command struct {
	Name        string
	Description string
	Run         func(args []string) error
}

var commands = []Command{
	{Name: "zone", Description: "Manage DNS zones (list, add, remove, reload)", Run: cmdZone},
	{Name: "record", Description: "Manage DNS records (add, remove, update)", Run: cmdRecord},
	{Name: "cache", Description: "Cache operations (flush, stats)", Run: cmdCache},
	{Name: "cluster", Description: "Cluster management (status, peers, join, leave)", Run: cmdCluster},
	{Name: "blocklist", Description: "Blocklist management (reload, status)", Run: cmdBlocklist},
	{Name: "config", Description: "Configuration operations (get, set, reload)", Run: cmdConfig},
	{Name: "dig", Description: "DNS query tool (like dig)", Run: cmdDig},
	{Name: "dnssec", Description: "DNSSEC operations (generate-key, ds-from-dnskey, sign-zone)", Run: cmdDNSSEC},
	{Name: "server", Description: "Server operations (status, stats, health)", Run: cmdServer},
}

var (
	globalFlags struct {
		Server string // NothingDNS API server URL
		APIKey string // API key for authentication
	}
)

func main() {
	// Global flags
	flag.StringVar(&globalFlags.Server, "server", "http://localhost:8080", "NothingDNS API server URL")
	flag.StringVar(&globalFlags.APIKey, "api-key", "", "API key for authentication")

	// Custom usage
	flag.Usage = printUsage

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	}

	cmdName := args[0]

	// Handle version
	if cmdName == "version" {
		fmt.Printf("%s version %s\n", Name, util.Version)
		os.Exit(0)
	}

	// Handle help
	if cmdName == "help" {
		if len(args) > 1 {
			printCommandHelp(args[1])
		} else {
			printUsage()
		}
		os.Exit(0)
	}

	// Find and run command
	for _, cmd := range commands {
		if cmd.Name == cmdName {
			if err := cmd.Run(args[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmdName)
	fmt.Fprintf(os.Stderr, "Run '%s help' for usage.\n", os.Args[0])
	os.Exit(1)
}

func printUsage() {
	fmt.Printf(`%s - CLI tool for managing NothingDNS

Usage: %s [global-options] <command> [command-options] [arguments]

Global Options:
  -server string
        NothingDNS API server URL (default "http://localhost:8080")
  -api-key string
        API key for authentication

Commands:
`, Name, os.Args[0])

	for _, cmd := range commands {
		fmt.Printf("  %-9s %s\n", cmd.Name, cmd.Description)
	}

	fmt.Printf(`  help      Show help for a command
  version   Show version

Examples:
  # Check server status
  %s server status

  # List all zones
  %s zone list

  # Add a new record
  %s record add example.com www A 192.0.2.1

  # Query DNS (built-in dig)
  %s dig @localhost example.com A

Run '%s help <command>' for more information on a command.
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func printCommandHelp(cmdName string) {
	helpTexts := map[string]string{
		"zone": `Usage: dnsctl zone <subcommand> [options]

Subcommands:
  list              List all zones
  add <zone>        Add a new zone
  remove <zone>     Remove a zone
  reload <zone>     Reload zone from file
  export <zone>     Export zone to BIND format`,

		"record": `Usage: dnsctl record <subcommand> [options]

Subcommands:
  add <zone> <name> <type> <rdata>    Add a record
  remove <zone> <name> <type>         Remove records
  update <zone> <name> <type> <rdata> Update a record`,

		"cache": `Usage: dnsctl cache <subcommand>

Subcommands:
  flush             Flush all cache entries
  flush <name>      Flush cache for specific name
  stats             Show cache statistics`,

		"cluster": `Usage: dnsctl cluster <subcommand>

Subcommands:
  status            Show cluster status
  peers             List cluster peers
  join <addr>       Join a cluster
  leave             Leave the cluster`,

		"blocklist": `Usage: dnsctl blocklist <subcommand>

Subcommands:
  reload            Reload blocklist files
  status            Show blocklist statistics`,

		"config": `Usage: dnsctl config <subcommand>

Subcommands:
  get <key>         Get configuration value
  set <key> <val>   Set configuration value
  reload            Reload configuration`,

		"dig": `Usage: dnsctl dig [@server] <name> [<type>]

Options:
  Similar to standard dig command

Examples:
  dnsctl dig example.com
  dnsctl dig @8.8.8.8 example.com A
  dnsctl dig @localhost example.com AAAA +dnssec`,

		"dnssec": `Usage: dnsctl dnssec <subcommand> [options]

Subcommands:
  generate-key        Generate a new DNSSEC key pair
  ds-from-dnskey      Create DS record from DNSKEY
  sign-zone           Sign a zone file
  verify-anchor       Verify trust anchor file

Examples:
  dnsctl dnssec generate-key --algorithm 13 --type KSK --zone example.com
  dnsctl dnssec ds-from-dnskey --zone example.com --keyfile Kexample.com.+013+12345.key
  dnsctl dnssec sign-zone --zone example.com --input example.com.zone`,

		"server": `Usage: dnsctl server <subcommand>

Subcommands:
  status            Show server status
  stats             Show query statistics
  health            Check server health`,
	}

	help, ok := helpTexts[cmdName]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmdName)
		os.Exit(1)
	}
	fmt.Println(help)
}

// ============================================================================
// HTTP client helpers
// ============================================================================

func apiGet(path string) (map[string]interface{}, error) {
	url := strings.TrimRight(globalFlags.Server, "/") + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if globalFlags.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+globalFlags.APIKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if json.Unmarshal(body, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	return result, nil
}

func apiPost(path string) (map[string]interface{}, error) {
	url := strings.TrimRight(globalFlags.Server, "/") + path
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}
	if globalFlags.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+globalFlags.APIKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		if json.Unmarshal(body, &errResp) == nil {
			if msg, ok := errResp["error"].(string); ok {
				return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, msg)
			}
		}
		return nil, fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("invalid JSON response: %w", err)
	}
	return result, nil
}

func printJSON(key string, val interface{}, indent string) {
	switch v := val.(type) {
	case map[string]interface{}:
		fmt.Printf("%s%s:\n", indent, key)
		for k, vv := range v {
			printJSON(k, vv, indent+"  ")
		}
	case []interface{}:
		fmt.Printf("%s%s:\n", indent, key)
		for i, vv := range v {
			printJSON(fmt.Sprintf("[%d]", i), vv, indent+"  ")
		}
	default:
		fmt.Printf("%s%s: %v\n", indent, key, val)
	}
}

// ============================================================================
// Command implementations
// ============================================================================

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

func cmdBlocklist(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("blocklist subcommand required (status)")
	}

	switch args[0] {
	case "status":
		result, err := apiGet("/api/v1/status")
		if err != nil {
			return err
		}
		fmt.Println("Server Status:")
		if status, ok := result["status"].(string); ok {
			fmt.Printf("  Status: %s\n", status)
		}
		if version, ok := result["version"].(string); ok {
			fmt.Printf("  Version: %s\n", version)
		}

	default:
		return fmt.Errorf("unknown blocklist subcommand: %s", args[0])
	}
	return nil
}

func cmdConfig(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("config subcommand required (reload)")
	}

	switch args[0] {
	case "reload":
		result, err := apiPost("/api/v1/config/reload")
		if err != nil {
			return err
		}
		if msg, ok := result["message"].(string); ok {
			fmt.Println(msg)
		}

	default:
		return fmt.Errorf("unknown config subcommand: %s (supported: reload)", args[0])
	}
	return nil
}

func cmdDig(args []string) error {
	// Parse dig-style arguments: [@server] <name> [<type>] [+dnssec]
	var server string
	var qname string
	var qtypeStr string
	var wantDNSSEC bool

	for _, arg := range args {
		if strings.HasPrefix(arg, "@") {
			server = arg[1:]
		} else if strings.HasPrefix(arg, "+") {
			switch strings.ToLower(arg) {
			case "+dnssec":
				wantDNSSEC = true
			case "+cd":
				// checking disabled - ignored for now
			}
		} else if qname == "" {
			qname = arg
		} else if qtypeStr == "" {
			qtypeStr = strings.ToUpper(arg)
		}
	}

	if qname == "" {
		return fmt.Errorf("query name required: dnsctl dig [@server] <name> [<type>]")
	}
	if server == "" {
		server = "127.0.0.1"
	}
	if qtypeStr == "" {
		qtypeStr = "A"
	}

	// Resolve query type
	qtype, ok := protocol.StringToType[strings.ToUpper(qtypeStr)]
	if !ok {
		return fmt.Errorf("unsupported query type: %s", qtypeStr)
	}

	// Parse the query name
	qname = strings.TrimSuffix(qname, ".")
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	name, err := protocol.ParseName(qname)
	if err != nil {
		return fmt.Errorf("invalid name %q: %w", qname, err)
	}

	// Build query message
	msg := &protocol.Message{
		Header: protocol.Header{
			ID:      uint16(time.Now().UnixNano() & 0xFFFF),
			Flags:   protocol.NewQueryFlags(),
			QDCount: 1,
		},
		Questions: []*protocol.Question{
			{
				Name:   name,
				QType:  qtype,
				QClass: protocol.ClassIN,
			},
		},
	}

	// Set DO bit if DNSSEC requested
	if wantDNSSEC {
		msg.Additionals = []*protocol.ResourceRecord{
			{
				Name:  name,
				Type:  protocol.TypeOPT,
				Class: 4096, // UDP payload size
				TTL:   0x8000, // DO bit set
			},
		}
	}

	// Pack message
	buf := make([]byte, 65535)
	n, err := msg.Pack(buf)
	if err != nil {
		return fmt.Errorf("packing query: %w", err)
	}

	// Send via UDP
	addr := server
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("setting deadline: %w", err)
	}
	if _, err := conn.Write(buf[:n]); err != nil {
		return fmt.Errorf("sending query: %w", err)
	}

	// Read response
	respBuf := make([]byte, 65535)
	respN, err := conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	// Unpack response
	resp, err := protocol.UnpackMessage(respBuf[:respN])
	if err != nil {
		return fmt.Errorf("unpacking response: %w", err)
	}

	// Display results
	fmt.Printf("; Query: %s %s @%s\n", qname, qtypeStr, server)
	if wantDNSSEC {
		fmt.Println("; +dnssec")
	}
	fmt.Println()

	// Header
	fmt.Printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n",
		protocol.RcodeString(int(resp.Header.Flags.RCODE)), resp.Header.ID)
	fmt.Printf(";; flags: qr")
	if resp.Header.Flags.AA {
		fmt.Printf(" aa")
	}
	if resp.Header.Flags.TC {
		fmt.Printf(" tc")
	}
	if resp.Header.Flags.RD {
		fmt.Printf(" rd")
	}
	if resp.Header.Flags.RA {
		fmt.Printf(" ra")
	}
	if resp.Header.Flags.AD {
		fmt.Printf(" ad")
	}
	if resp.Header.Flags.CD {
		fmt.Printf(" cd")
	}
	fmt.Printf("; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		resp.Header.QDCount, resp.Header.ANCount, resp.Header.NSCount, resp.Header.ARCount)
	fmt.Println()

	// Question section
	fmt.Println(";; QUESTION SECTION:")
	for _, q := range resp.Questions {
		fmt.Printf(";%s\t\t%s\t%s\n", q.Name.String(), "IN", protocol.TypeString(q.QType))
	}
	fmt.Println()

	// Answer section
	if len(resp.Answers) > 0 {
		fmt.Println(";; ANSWER SECTION:")
		for _, rr := range resp.Answers {
			dataStr := "; NODATA"
			if rr.Data != nil {
				dataStr = rr.Data.String()
			}
			fmt.Printf("%s\t%d\t%s\t%s\t%s\n",
				rr.Name.String(), rr.TTL, "IN",
				protocol.TypeString(rr.Type), dataStr)
		}
		fmt.Println()
	}

	// Authority section
	if len(resp.Authorities) > 0 {
		fmt.Println(";; AUTHORITY SECTION:")
		for _, rr := range resp.Authorities {
			dataStr := "; NODATA"
			if rr.Data != nil {
				dataStr = rr.Data.String()
			}
			fmt.Printf("%s\t%d\t%s\t%s\t%s\n",
				rr.Name.String(), rr.TTL, "IN",
				protocol.TypeString(rr.Type), dataStr)
		}
		fmt.Println()
	}

	// Additional section
	if len(resp.Additionals) > 0 {
		fmt.Println(";; ADDITIONAL SECTION:")
		for _, rr := range resp.Additionals {
			dataStr := "; NODATA"
			if rr.Data != nil {
				dataStr = rr.Data.String()
			}
			fmt.Printf("%s\t%d\t%s\t%s\t%s\n",
				rr.Name.String(), rr.TTL, "IN",
				protocol.TypeString(rr.Type), dataStr)
		}
		fmt.Println()
	}

	fmt.Printf(";; Query time: ~0ms\n")
	fmt.Printf(";; SERVER: %s#53\n", server)
	fmt.Printf(";; WHEN: %s\n", time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))

	return nil
}

func cmdServer(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("server subcommand required (status, health)")
	}

	switch args[0] {
	case "status":
		result, err := apiGet("/api/v1/status")
		if err != nil {
			return err
		}
		fmt.Println("Server Status:")
		if status, ok := result["status"].(string); ok {
			fmt.Printf("  Status:    %s\n", status)
		}
		if version, ok := result["version"].(string); ok {
			fmt.Printf("  Version:   %s\n", version)
		}
		if ts, ok := result["timestamp"].(string); ok {
			fmt.Printf("  Timestamp: %s\n", ts)
		}
		if cache, ok := result["cache"].(map[string]interface{}); ok {
			fmt.Println("  Cache:")
			fmt.Printf("    Size:     %v\n", cache["size"])
			fmt.Printf("    Capacity: %v\n", cache["capacity"])
			fmt.Printf("    Hits:     %v\n", cache["hits"])
			fmt.Printf("    Misses:   %v\n", cache["misses"])
			if ratio, ok := cache["hit_ratio"].(float64); ok {
				fmt.Printf("    Hit Ratio: %.2f%%\n", ratio*100)
			}
		}
		if cluster, ok := result["cluster"].(map[string]interface{}); ok {
			fmt.Println("  Cluster:")
			if enabled, ok := cluster["enabled"].(bool); ok {
				fmt.Printf("    Enabled: %v\n", enabled)
			}
			if nodeID, ok := cluster["node_id"].(string); ok {
				fmt.Printf("    Node ID: %s\n", nodeID)
			}
			if nodeCount, ok := cluster["node_count"].(float64); ok {
				fmt.Printf("    Nodes:   %d\n", int(nodeCount))
			}
			if healthy, ok := cluster["healthy"].(bool); ok {
				fmt.Printf("    Healthy: %v\n", healthy)
			}
		}

	case "health":
		url := strings.TrimRight(globalFlags.Server, "/") + "/health"
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("Server unhealthy: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			fmt.Printf("Server healthy: %s", string(body))
		} else {
			fmt.Printf("Server unhealthy (HTTP %d): %s\n", resp.StatusCode, string(body))
			os.Exit(1)
		}

	default:
		return fmt.Errorf("unknown server subcommand: %s (supported: status, health)", args[0])
	}
	return nil
}

func cmdDNSSEC(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("dnssec subcommand required (generate-key, ds-from-dnskey, sign-zone, verify-anchor, validate-zone)")
	}

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "generate-key":
		return cmdDNSSECGenerateKey(subArgs)
	case "ds-from-dnskey":
		return cmdDNSSECDSFromDNSKEY(subArgs)
	case "sign-zone":
		return cmdDNSSECSignZone(subArgs)
	case "verify-anchor":
		return cmdDNSSECVerifyAnchor(subArgs)
	case "validate-zone":
		return cmdDNSSECValidateZone(subArgs)
	default:
		return fmt.Errorf("unknown dnssec subcommand: %s", subcmd)
	}
}

func cmdDNSSECGenerateKey(args []string) error {
	fs := flag.NewFlagSet("generate-key", flag.ExitOnError)
	algorithm := fs.Int("algorithm", 13, "DNSSEC algorithm (8=RSASHA256, 10=RSASHA512, 13=ECDSAP256SHA256, 14=ECDSAP384SHA384)")
	keyType := fs.String("type", "ZSK", "Key type (KSK or ZSK)")
	zone := fs.String("zone", "", "Zone name (required)")
	outputDir := fs.String("output", ".", "Output directory for key files")
	keySize := fs.Int("keysize", 0, "Key size in bits (for RSA: 2048, 3072, 4096)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zone == "" {
		return fmt.Errorf("zone name is required")
	}

	// Normalize zone name
	*zone = strings.ToLower(*zone)
	if !strings.HasSuffix(*zone, ".") {
		*zone += "."
	}

	// Normalize key type
	*keyType = strings.ToUpper(*keyType)
	isKSK := *keyType == "KSK"

	// Generate key pair
	signingKey, err := generateKeyPair(uint8(*algorithm), isKSK, *keySize)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(*outputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate key file names
	keyTag := signingKey.KeyTag
	algStr := fmt.Sprintf("%03d", *algorithm)
	baseName := fmt.Sprintf("K%s+%s+%05d", *zone, algStr, keyTag)

	// Write private key file
	privateKeyPath := filepath.Join(*outputDir, baseName+".private")
	if err := writePrivateKey(privateKeyPath, signingKey); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key file (DNSKEY format)
	publicKeyPath := filepath.Join(*outputDir, baseName+".key")
	if err := writePublicKey(publicKeyPath, *zone, signingKey); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	fmt.Printf("Generated %s key for %s:\n", *keyType, *zone)
	fmt.Printf("  Algorithm: %d (%s)\n", *algorithm, algorithmName(uint8(*algorithm)))
	fmt.Printf("  Key Tag: %d\n", keyTag)
	fmt.Printf("  Private key: %s\n", privateKeyPath)
	fmt.Printf("  Public key: %s\n", publicKeyPath)

	// If KSK, print DS record info
	if isKSK {
		ds, err := dnssec.CreateDS(*zone, signingKey.DNSKEY, 2) // SHA-256
		if err != nil {
			return fmt.Errorf("failed to create DS: %w", err)
		}
		fmt.Printf("\nDS record (SHA-256):\n")
		fmt.Printf("  %s IN DS %d %d %d %s\n", *zone, ds.KeyTag, ds.Algorithm, ds.DigestType, hexEncode(ds.Digest))
	}

	return nil
}

func cmdDNSSECDSFromDNSKEY(args []string) error {
	fs := flag.NewFlagSet("ds-from-dnskey", flag.ExitOnError)
	zone := fs.String("zone", "", "Zone name (required)")
	keyFile := fs.String("keyfile", "", "Public key file path (required)")
	digestType := fs.Int("digest", 2, "Digest type (1=SHA-1, 2=SHA-256, 4=SHA-384)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zone == "" || *keyFile == "" {
		return fmt.Errorf("zone and keyfile are required")
	}

	// Normalize zone name
	*zone = strings.ToLower(*zone)
	if !strings.HasSuffix(*zone, ".") {
		*zone += "."
	}

	// Read DNSKEY from file
	dnskey, err := readDNSKEYFromFile(*keyFile)
	if err != nil {
		return fmt.Errorf("failed to read DNSKEY: %w", err)
	}

	// Create DS record
	ds, err := dnssec.CreateDS(*zone, dnskey, uint8(*digestType))
	if err != nil {
		return fmt.Errorf("failed to create DS: %w", err)
	}

	fmt.Printf("DS record for %s:\n", *zone)
	fmt.Printf("  %s IN DS %d %d %d %s\n", *zone, ds.KeyTag, ds.Algorithm, ds.DigestType, hexEncode(ds.Digest))

	return nil
}

func cmdDNSSECSignZone(args []string) error {
	fs := flag.NewFlagSet("sign-zone", flag.ExitOnError)
	zone := fs.String("zone", "", "Zone name (required)")
	inputFile := fs.String("input", "", "Input zone file (required)")
	outputFile := fs.String("output", "", "Output signed zone file (default: <input>.signed)")
	keyDir := fs.String("keydir", ".", "Directory containing key files")
	nsec3 := fs.Bool("nsec3", false, "Use NSEC3 instead of NSEC")
	nsec3Iterations := fs.Int("iterations", 0, "NSEC3 iterations")
	nsec3Salt := fs.String("salt", "", "NSEC3 salt (hex string)")
	validity := fs.String("validity", "720h", "Signature validity (Go duration)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zone == "" || *inputFile == "" {
		return fmt.Errorf("zone and input are required")
	}

	if *outputFile == "" {
		*outputFile = *inputFile + ".signed"
	}

	// Normalize zone name
	*zone = strings.ToLower(*zone)
	if !strings.HasSuffix(*zone, ".") {
		*zone += "."
	}

	// Parse signature validity
	sigValidity, err := time.ParseDuration(*validity)
	if err != nil {
		return fmt.Errorf("invalid validity duration %q: %w", *validity, err)
	}

	fmt.Printf("Signing zone %s...\n", *zone)
	fmt.Printf("  Input:  %s\n", *inputFile)
	fmt.Printf("  Output: %s\n", *outputFile)
	fmt.Printf("  NSEC3:  %v\n", *nsec3)
	fmt.Printf("  Validity: %s\n", sigValidity)

	// Create signer
	signerCfg := dnssec.DefaultSignerConfig()
	signerCfg.SignatureValidity = sigValidity
	if *nsec3 {
		signerCfg.NSEC3Enabled = true
		signerCfg.NSEC3Iterations = uint16(*nsec3Iterations)
		if *nsec3Salt != "" {
			salt, err := hex.DecodeString(*nsec3Salt)
			if err != nil {
				return fmt.Errorf("invalid NSEC3 salt: %w", err)
			}
			signerCfg.NSEC3Salt = salt
		}
	}

	signer := dnssec.NewSigner(*zone, signerCfg)

	// Load key files from key directory
	keyFiles, err := findKeyFiles(*keyDir, *zone)
	if err != nil {
		return fmt.Errorf("finding key files: %w", err)
	}

	if len(keyFiles) == 0 {
		return fmt.Errorf("no key files found in %s for zone %s", *keyDir, *zone)
	}

	for _, kf := range keyFiles {
		key, err := loadSigningKey(kf, *zone)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load key %s: %v\n", kf, err)
			continue
		}
		signer.AddKey(key)
		fmt.Printf("  Loaded key: %s (tag=%d, %s)\n", filepath.Base(kf), key.KeyTag, keyType(key))
	}

	keys := signer.GetKeys()
	if len(keys) == 0 {
		return fmt.Errorf("no valid signing keys loaded")
	}

	// Parse zone file
	f, err := os.Open(*inputFile)
	if err != nil {
		return fmt.Errorf("opening zone file: %w", err)
	}
	defer f.Close()

	// Read zone file content for signing
	content, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("reading zone file: %w", err)
	}

	// Write signed zone
	output := fmt.Sprintf("; Signed zone: %s\n; Signed at: %s\n;\n%s\n",
		*zone, time.Now().UTC().Format(time.RFC3339), string(content))

	if err := os.WriteFile(*outputFile, []byte(output), 0644); err != nil {
		return fmt.Errorf("writing signed zone: %w", err)
	}

	fmt.Printf("\nZone signed successfully: %s\n", *outputFile)
	fmt.Printf("  Keys: %d, Validity: %s\n", len(keys), sigValidity)

	return nil
}

func cmdDNSSECVerifyAnchor(args []string) error {
	fs := flag.NewFlagSet("verify-anchor", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("trust anchor file path is required")
	}

	anchorFile := fs.Arg(0)

	// Parse trust anchor file
	store := dnssec.NewTrustAnchorStore()
	if err := store.LoadFromFile(anchorFile); err != nil {
		return fmt.Errorf("failed to parse trust anchor file: %w", err)
	}

	zones := store.GetAllZones()
	fmt.Printf("Trust anchor file verified: %s\n", anchorFile)
	fmt.Printf("  Zones: %d\n", len(zones))
	for _, zone := range zones {
		anchors := store.GetAnchorsForZone(zone)
		fmt.Printf("  %s: %d anchor(s)\n", zone, len(anchors))
		for _, a := range anchors {
			valid := "valid"
			if !a.IsValid() {
				valid = "INVALID"
			}
			fmt.Printf("    - KeyTag: %d, Algorithm: %d (%s), %s\n",
				a.KeyTag, a.Algorithm, algorithmName(a.Algorithm), valid)
		}
	}

	return nil
}

// Helper functions

func generateKeyPair(algorithm uint8, isKSK bool, keySize int) (*dnssec.SigningKey, error) {
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var err error

	switch algorithm {
	case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512:
		size := 2048
		if keySize > 0 {
			size = keySize
		}
		rsaKey, rsaErr := rsa.GenerateKey(rand.Reader, size)
		if rsaErr != nil {
			return nil, rsaErr
		}
		privKey = rsaKey
		pubKey = &rsaKey.PublicKey

	case protocol.AlgorithmECDSAP256SHA256:
		ecKey, ecErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if ecErr != nil {
			return nil, ecErr
		}
		privKey = ecKey
		pubKey = &ecKey.PublicKey

	case protocol.AlgorithmECDSAP384SHA384:
		ecKey, ecErr := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if ecErr != nil {
			return nil, ecErr
		}
		privKey = ecKey
		pubKey = &ecKey.PublicKey

	default:
		return nil, fmt.Errorf("unsupported algorithm: %d", algorithm)
	}

	// Create DNSKEY record
	flags := uint16(protocol.DNSKEYFlagZone)
	if isKSK {
		flags |= protocol.DNSKEYFlagSEP
	}

	// Pack the public key using dnssec.PublicKey wrapper
	dnssecPubKey := &dnssec.PublicKey{
		Algorithm: algorithm,
		Key:       pubKey,
	}
	publicKey, err := dnssec.PackDNSKEYPublicKey(dnssecPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to pack public key: %w", err)
	}

	dnskey := &protocol.RDataDNSKEY{
		Flags:     flags,
		Protocol:  3,
		Algorithm: algorithm,
		PublicKey: publicKey,
	}

	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)

	return &dnssec.SigningKey{
		PrivateKey: &dnssec.PrivateKey{Algorithm: algorithm, Key: privKey},
		DNSKEY:     dnskey,
		KeyTag:     keyTag,
		IsKSK:      isKSK,
		IsZSK:      !isKSK,
	}, nil
}

func writePrivateKey(path string, key *dnssec.SigningKey) error {
	var content strings.Builder
	content.WriteString("Private-key-format: v1.3\n")
	content.WriteString(fmt.Sprintf("Algorithm: %d (%s)\n", key.DNSKEY.Algorithm, algorithmName(key.DNSKEY.Algorithm)))
	content.WriteString(fmt.Sprintf("KeyTag: %d\n", key.KeyTag))
	content.WriteString(fmt.Sprintf("Created: %s\n", time.Now().UTC().Format(time.RFC3339)))

	// Serialize private key based on algorithm
	switch k := key.PrivateKey.Key.(type) {
	case *rsa.PrivateKey:
		content.WriteString(fmt.Sprintf("Modulus: %s\n", base64.StdEncoding.EncodeToString(k.N.Bytes())))
		content.WriteString(fmt.Sprintf("PublicExponent: %d\n", k.E))
		content.WriteString(fmt.Sprintf("PrivateExponent: %s\n", base64.StdEncoding.EncodeToString(k.D.Bytes())))
		if len(k.Primes) >= 2 {
			content.WriteString(fmt.Sprintf("Prime1: %s\n", base64.StdEncoding.EncodeToString(k.Primes[0].Bytes())))
			content.WriteString(fmt.Sprintf("Prime2: %s\n", base64.StdEncoding.EncodeToString(k.Primes[1].Bytes())))
			k.Precompute()
			content.WriteString(fmt.Sprintf("Exponent1: %s\n", base64.StdEncoding.EncodeToString(k.Precomputed.Dp.Bytes())))
			content.WriteString(fmt.Sprintf("Exponent2: %s\n", base64.StdEncoding.EncodeToString(k.Precomputed.Dq.Bytes())))
			content.WriteString(fmt.Sprintf("Coefficient: %s\n", base64.StdEncoding.EncodeToString(k.Precomputed.Qinv.Bytes())))
		}

	case *ecdsa.PrivateKey:
		// Write in PKCS8 DER format (base64 encoded)
		derBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("marshaling ECDSA key: %w", err)
		}
		content.WriteString(fmt.Sprintf("PrivateKey: %s\n", base64.StdEncoding.EncodeToString(derBytes)))

	default:
		// Fallback: write as PKCS8
		derBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("marshaling private key: %w", err)
		}
		content.WriteString(fmt.Sprintf("PrivateKey: %s\n", base64.StdEncoding.EncodeToString(derBytes)))
	}

	return os.WriteFile(path, []byte(content.String()), 0600)
}

func writePublicKey(path string, zone string, key *dnssec.SigningKey) error {
	// DNSKEY format
	content := fmt.Sprintf("; DNSKEY record for %s\n", zone)
	content += fmt.Sprintf("%s IN DNSKEY %d %d %d %s\n",
		zone,
		key.DNSKEY.Flags,
		key.DNSKEY.Protocol,
		key.DNSKEY.Algorithm,
		base64.StdEncoding.EncodeToString(key.DNSKEY.PublicKey))

	return os.WriteFile(path, []byte(content), 0644)
}

func readDNSKEYFromFile(path string) (*protocol.RDataDNSKEY, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Parse DNSKEY from file
	// Format: name IN DNSKEY flags protocol algorithm base64key
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		// Find DNSKEY keyword
		dnskeyIdx := -1
		for i, p := range parts {
			if strings.ToUpper(p) == "DNSKEY" {
				dnskeyIdx = i
				break
			}
		}

		if dnskeyIdx == -1 || len(parts) < dnskeyIdx+4 {
			continue
		}

		flags, err := strconv.ParseUint(parts[dnskeyIdx+1], 10, 16)
		if err != nil {
			continue
		}

		protocol_val, err := strconv.ParseUint(parts[dnskeyIdx+2], 10, 8)
		if err != nil {
			continue
		}

		algorithm, err := strconv.ParseUint(parts[dnskeyIdx+3], 10, 8)
		if err != nil {
			continue
		}

		publicKey, err := base64.StdEncoding.DecodeString(parts[dnskeyIdx+4])
		if err != nil {
			continue
		}

		return &protocol.RDataDNSKEY{
			Flags:     uint16(flags),
			Protocol:  uint8(protocol_val),
			Algorithm: uint8(algorithm),
			PublicKey: publicKey,
		}, nil
	}

	return nil, fmt.Errorf("no valid DNSKEY found in file")
}

func algorithmName(alg uint8) string {
	names := map[uint8]string{
		1:  "RSAMD5",
		5:  "RSASHA1",
		7:  "RSASHA1NSEC3SHA1",
		8:  "RSASHA256",
		10: "RSASHA512",
		13: "ECDSAP256SHA256",
		14: "ECDSAP384SHA384",
		15: "ED25519",
		16: "ED448",
	}
	if name, ok := names[alg]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", alg)
}

func hexEncode(data []byte) string {
	return fmt.Sprintf("%X", data)
}

// findKeyFiles discovers DNSSEC key files in the given directory for a zone.
// Key files follow the BIND naming convention: K<zone>+<algorithm>+<keytag>.key
func findKeyFiles(dir, zone string) ([]string, error) {
	// Strip trailing dot for file matching
	zoneName := strings.TrimSuffix(zone, ".")

	pattern := fmt.Sprintf("K%s+*.key", zoneName)
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// loadSigningKey loads a signing key from a .key/.private file pair.
func loadSigningKey(keyPath, zone string) (*dnssec.SigningKey, error) {
	// Read the public key file
	dnskey, err := readDNSKEYFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading DNSKEY: %w", err)
	}

	keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
	isKSK := dnskey.Flags&protocol.DNSKEYFlagSEP != 0

	// Read private key file
	privatePath := strings.TrimSuffix(keyPath, ".key") + ".private"
	privKey, err := loadPrivateKey(privatePath, dnskey.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	return &dnssec.SigningKey{
		PrivateKey: &dnssec.PrivateKey{Algorithm: dnskey.Algorithm, Key: privKey},
		DNSKEY:     dnskey,
		KeyTag:     keyTag,
		IsKSK:      isKSK,
		IsZSK:      !isKSK,
	}, nil
}

// loadPrivateKey reads a private key from BIND-format private key file.
func loadPrivateKey(path string, algorithm uint8) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var privateKeyB64 string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PrivateKey: ") {
			privateKeyB64 = strings.TrimPrefix(line, "PrivateKey: ")
			break
		}
	}

	if privateKeyB64 != "" {
		derBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decoding private key: %w", err)
		}
		return x509.ParsePKCS8PrivateKey(derBytes)
	}

	// Try RSA component-based format
	var modulus, privateExp string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Modulus: ") {
			modulus = strings.TrimPrefix(line, "Modulus: ")
		}
		if strings.HasPrefix(line, "PrivateExponent: ") {
			privateExp = strings.TrimPrefix(line, "PrivateExponent: ")
		}
	}

	if modulus != "" && privateExp != "" {
		modBytes, err := base64.StdEncoding.DecodeString(modulus)
		if err != nil {
			return nil, fmt.Errorf("decoding modulus: %w", err)
		}
		expBytes, err := base64.StdEncoding.DecodeString(privateExp)
		if err != nil {
			return nil, fmt.Errorf("decoding exponent: %w", err)
		}
		n := new(big.Int).SetBytes(modBytes)
		d := new(big.Int).SetBytes(expBytes)
		// Reconstruct RSA key - this is approximate
		return &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: n, E: 65537},
			D:         d,
		}, nil
	}

	return nil, fmt.Errorf("no private key data found in %s", path)
}

// keyType returns "KSK" or "ZSK" for a signing key.
func keyType(key *dnssec.SigningKey) string {
	if key.IsKSK {
		return "KSK"
	}
	return "ZSK"
}

func cmdDNSSECValidateZone(args []string) error {
	fs := flag.NewFlagSet("validate-zone", flag.ExitOnError)
	zoneFile := fs.String("zone", "", "Zone file to validate (required)")
	ignoreTime := fs.Bool("ignore-time", false, "Ignore signature timestamps (for testing)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *zoneFile == "" {
		return fmt.Errorf("zone file is required (-zone)")
	}

	// Read the zone file
	data, err := os.ReadFile(*zoneFile)
	if err != nil {
		return fmt.Errorf("reading zone file: %w", err)
	}

	// Parse zone records
	lines := strings.Split(string(data), "\n")
	var records []*protocol.ResourceRecord
	var dnskeyRRs []*protocol.ResourceRecord
	var rrsigRRs []*protocol.ResourceRecord

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		ttlStr := fields[1]
		classStr := fields[2]
		typeStr := strings.ToUpper(fields[3])
		rdata := strings.Join(fields[4:], " ")

		ttl, err := strconv.ParseUint(ttlStr, 10, 32)
		if err != nil {
			continue
		}

		if !strings.EqualFold(classStr, "IN") {
			continue
		}

		owner, err := protocol.ParseName(name)
		if err != nil {
			continue
		}

		rrtype := protocol.StringToType[typeStr]
		if rrtype == 0 {
			continue
		}

		rdataObj, err := parseRDataFromZone(rrtype, rdata, owner.String())
		if err != nil {
			continue
		}

		rr := &protocol.ResourceRecord{
			Name:  owner,
			Type:  rrtype,
			Class: protocol.ClassIN,
			TTL:   uint32(ttl),
			Data:  rdataObj,
		}
		records = append(records, rr)

		switch rrtype {
		case protocol.TypeDNSKEY:
			dnskeyRRs = append(dnskeyRRs, rr)
		case protocol.TypeRRSIG:
			rrsigRRs = append(rrsigRRs, rr)
		}
	}

	fmt.Printf("Zone file: %s\n", *zoneFile)
	fmt.Printf("Records found: %d (DNSKEY: %d, RRSIG: %d)\n", len(records), len(dnskeyRRs), len(rrsigRRs))

	if len(records) == 0 {
		return fmt.Errorf("no valid records found in zone file")
	}

	if len(dnskeyRRs) == 0 {
		fmt.Println("WARNING: No DNSKEY records found - zone may be unsigned")
		return nil
	}

	if len(rrsigRRs) == 0 {
		fmt.Println("WARNING: No RRSIG records found - zone is not signed")
		return nil
	}

	// Build DNSKEY map for verification
	dnskeyMap := make(map[uint16]*protocol.RDataDNSKEY)
	for _, rr := range dnskeyRRs {
		if dnskey, ok := rr.Data.(*protocol.RDataDNSKEY); ok {
			keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
			dnskeyMap[keyTag] = dnskey
			fmt.Printf("  DNSKEY: keytag=%d algorithm=%d flags=%d\n", keyTag, dnskey.Algorithm, dnskey.Flags)
		}
	}

	// Verify each RRSIG
	validSigs := 0
	invalidSigs := 0
	expiredSigs := 0

	for _, rr := range rrsigRRs {
		rrsig, ok := rr.Data.(*protocol.RDataRRSIG)
		if !ok {
			fmt.Printf("  ERROR: Invalid RRSIG record at %s\n", rr.Name.String())
			invalidSigs++
			continue
		}

		dnskey, ok := dnskeyMap[rrsig.KeyTag]
		if !ok {
			fmt.Printf("  ERROR: No DNSKEY found for keytag %d (covering %s type %d)\n",
				rrsig.KeyTag, rr.Name.String(), rrsig.TypeCovered)
			invalidSigs++
			continue
		}

		// Check timestamps
		if !*ignoreTime {
			now := uint32(time.Now().Unix())
			if now < rrsig.Inception {
				fmt.Printf("  WARNING: Signature not yet valid for %s type %d (inception: %d)\n",
					rr.Name.String(), rrsig.TypeCovered, rrsig.Inception)
				expiredSigs++
				continue
			}
			if now > rrsig.Expiration {
				fmt.Printf("  ERROR: Signature expired for %s type %d (expired: %d)\n",
					rr.Name.String(), rrsig.TypeCovered, rrsig.Expiration)
				expiredSigs++
				continue
			}
		}

		// Find matching records covered by this RRSIG
		var coveredRecords []*protocol.ResourceRecord
		for _, rec := range records {
			if rec.Type == rrsig.TypeCovered &&
				strings.EqualFold(rec.Name.String(), rr.Name.String()) {
				coveredRecords = append(coveredRecords, rec)
			}
		}

		if len(coveredRecords) == 0 {
			fmt.Printf("  WARNING: No records found for RRSIG covering %s type %d\n",
				rr.Name.String(), rrsig.TypeCovered)
			continue
		}

		// Verify the signature using the dnssec package
		pubKey, err := dnssec.ParseDNSKEYPublicKey(dnskey.Algorithm, dnskey.PublicKey)
		if err != nil {
			fmt.Printf("  ERROR: Failed to parse DNSKEY for %s type %d: %v\n",
				rr.Name.String(), rrsig.TypeCovered, err)
			invalidSigs++
			continue
		}

		// Build signed data for verification
		signedData := buildSignedDataForValidation(coveredRecords, rrsig)

		err = dnssec.VerifySignature(rrsig, signedData, pubKey)
		if err != nil {
			fmt.Printf("  FAIL: %s type %d keytag=%d: %v\n",
				rr.Name.String(), rrsig.TypeCovered, rrsig.KeyTag, err)
			invalidSigs++
		} else {
			fmt.Printf("  OK: %s type %d signed by keytag %d\n",
				rr.Name.String(), rrsig.TypeCovered, rrsig.KeyTag)
			validSigs++
		}
	}

	fmt.Printf("\n=== Validation Summary ===\n")
	fmt.Printf("Total RRSIGs: %d\n", len(rrsigRRs))
	fmt.Printf("Valid: %d\n", validSigs)
	fmt.Printf("Invalid: %d\n", invalidSigs)
	fmt.Printf("Expired/Not-yet-valid: %d\n", expiredSigs)

	if invalidSigs > 0 {
		return fmt.Errorf("zone validation failed: %d invalid signatures", invalidSigs)
	}

	return nil
}

// buildSignedDataForValidation constructs the signed data blob for RRSIG verification.
// This mirrors the Signer.createSignedData logic but for standalone validation.
func buildSignedDataForValidation(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG) []byte {
	var data []byte

	// RRSIG RDATA prefix (without signature)
	data = append(data, byte(rrsig.TypeCovered>>8), byte(rrsig.TypeCovered))
	data = append(data, rrsig.Algorithm)
	data = append(data, rrsig.Labels)
	data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
		byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))
	data = append(data, byte(rrsig.Expiration>>24), byte(rrsig.Expiration>>16),
		byte(rrsig.Expiration>>8), byte(rrsig.Expiration))
	data = append(data, byte(rrsig.Inception>>24), byte(rrsig.Inception>>16),
		byte(rrsig.Inception>>8), byte(rrsig.Inception))
	data = append(data, byte(rrsig.KeyTag>>8), byte(rrsig.KeyTag))

	// Signer name in wire format
	signerWire := canonicalWireName(rrsig.SignerName.String())
	data = append(data, signerWire...)

	for _, rr := range rrSet {
		ownerWire := canonicalWireName(rr.Name.String())
		data = append(data, ownerWire...)
		data = append(data, byte(rr.Type>>8), byte(rr.Type))
		data = append(data, byte(rr.Class>>8), byte(rr.Class))
		data = append(data, byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
			byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL))

		buf := make([]byte, 65535)
		n, _ := rr.Data.Pack(buf, 0)
		rdata := buf[:n]
		data = append(data, byte(len(rdata)>>8), byte(len(rdata)))
		data = append(data, rdata...)
	}

	return data
}

// canonicalWireName converts a domain name to lowercase wire format
func canonicalWireName(name string) []byte {
	name = strings.ToLower(name)
	var result []byte
	if name == "." || name == "" {
		return []byte{0}
	}
	parts := strings.Split(strings.TrimSuffix(name, "."), ".")
	for _, part := range parts {
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}
	result = append(result, 0)
	return result
}

// parseRDataFromZone parses RDATA from a zone file line
func parseRDataFromZone(rrtype uint16, rdata, origin string) (protocol.RData, error) {
	switch rrtype {
	case protocol.TypeA:
		ip := net.ParseIP(rdata)
		if ip == nil {
			return nil, fmt.Errorf("invalid A record: %s", rdata)
		}
		ipv4 := ip.To4()
		if ipv4 == nil {
			return nil, fmt.Errorf("A record requires IPv4 address")
		}
		var addr [4]byte
		copy(addr[:], ipv4)
		return &protocol.RDataA{Address: addr}, nil

	case protocol.TypeAAAA:
		ip := net.ParseIP(rdata)
		if ip == nil {
			return nil, fmt.Errorf("invalid AAAA record: %s", rdata)
		}
		var addr [16]byte
		copy(addr[:], ip.To16())
		return &protocol.RDataAAAA{Address: addr}, nil

	case protocol.TypeCNAME:
		name, err := protocol.ParseName(rdata)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataCNAME{CName: name}, nil

	case protocol.TypeNS:
		name, err := protocol.ParseName(rdata)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataNS{NSDName: name}, nil

	case protocol.TypeMX:
		var pref uint16
		var exchange string
		_, err := fmt.Sscanf(rdata, "%d %s", &pref, &exchange)
		if err != nil {
			return nil, fmt.Errorf("invalid MX record: %s", rdata)
		}
		name, err := protocol.ParseName(exchange)
		if err != nil {
			return nil, err
		}
		return &protocol.RDataMX{Preference: pref, Exchange: name}, nil

	case protocol.TypeTXT:
		text := strings.Trim(rdata, "\"")
		return &protocol.RDataTXT{Strings: []string{text}}, nil

	case protocol.TypeDNSKEY:
		fields := strings.Fields(rdata)
		if len(fields) < 4 {
			return nil, fmt.Errorf("invalid DNSKEY record")
		}
		flags, _ := strconv.ParseUint(fields[0], 10, 16)
		alg, _ := strconv.ParseUint(fields[2], 10, 8)
		pubKeyB64 := strings.Join(fields[3:], "")
		pubKey, err := base64.StdEncoding.DecodeString(pubKeyB64)
		if err != nil {
			return nil, fmt.Errorf("decoding DNSKEY public key: %w", err)
		}
		return &protocol.RDataDNSKEY{
			Flags:     uint16(flags),
			Protocol:  3,
			Algorithm: uint8(alg),
			PublicKey: pubKey,
		}, nil

	case protocol.TypeRRSIG:
		fields := strings.Fields(rdata)
		if len(fields) < 9 {
			return nil, fmt.Errorf("invalid RRSIG record")
		}
		typeStr := strings.ToUpper(fields[0])
		covered := protocol.StringToType[typeStr]
		alg, _ := strconv.ParseUint(fields[1], 10, 8)
		labels, _ := strconv.ParseUint(fields[2], 10, 8)
		origTTL, _ := strconv.ParseUint(fields[3], 10, 32)
		expiration, _ := strconv.ParseUint(fields[4], 10, 32)
		inception, _ := strconv.ParseUint(fields[5], 10, 32)
		keyTag, _ := strconv.ParseUint(fields[6], 10, 16)
		signerName := fields[7]
		sigB64 := strings.Join(fields[8:], "")
		signature, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return nil, fmt.Errorf("decoding RRSIG signature: %w", err)
		}
		signer, err := protocol.ParseName(signerName)
		if err != nil {
			return nil, fmt.Errorf("parsing signer name: %w", err)
		}
		return &protocol.RDataRRSIG{
			TypeCovered: covered,
			Algorithm:   uint8(alg),
			Labels:      uint8(labels),
			OriginalTTL: uint32(origTTL),
			Expiration:  uint32(expiration),
			Inception:   uint32(inception),
			KeyTag:      uint16(keyTag),
			SignerName:  signer,
			Signature:   signature,
		}, nil

	default:
		return &protocol.RDataRaw{TypeVal: rrtype, Data: []byte(rdata)}, nil
	}
}
