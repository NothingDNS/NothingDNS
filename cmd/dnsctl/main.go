// dnsctl - CLI management tool for NothingDNS
// Communicates with NothingDNS via REST API

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

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

	httpClient = &http.Client{
		Timeout: 30 * time.Second,
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
