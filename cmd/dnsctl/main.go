// dnsctl - CLI management tool for NothingDNS
// Communicates with NothingDNS via REST API

package main

import (
	"flag"
	"fmt"
	"io"
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
	{Name: "zone", Description: "Manage DNS zones (list, add, remove, reload, export)", Run: cmdZone},
	{Name: "record", Description: "Manage DNS records (list, add, remove, update)", Run: cmdRecord},
	{Name: "cache", Description: "Cache operations (flush, stats)", Run: cmdCache},
	{Name: "cluster", Description: "Cluster management (status, peers, join, leave)", Run: cmdCluster},
	{Name: "blocklist", Description: "Blocklist management (status, sources, reload)", Run: cmdBlocklist},
	{Name: "config", Description: "Configuration operations (get, reload)", Run: cmdConfig},
	{Name: "dig", Description: "DNS query tool (like dig)", Run: cmdDig},
	{Name: "dnssec", Description: "DNSSEC operations (status, keys, generate-key, ds-from-dnskey, sign-zone, verify-anchor, validate-zone)", Run: cmdDNSSEC},
	{Name: "server", Description: "Server operations (status, health)", Run: cmdServer},
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
	os.Exit(runMain(os.Args[1:]))
}

func runMain(args []string) int {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	// Env-variable defaults — flags override when set explicitly.
	// Operators commonly script dnsctl from CI pipelines and shell
	// rc files; pinning the API key to every invocation via --api-key
	// puts it in process listings and shell history. NOTHINGDNS_API_KEY
	// keeps it out of argv. NOTHINGDNS_SERVER mirrors the same
	// convention for the server URL.
	defaultServer := os.Getenv("NOTHINGDNS_SERVER")
	if defaultServer == "" {
		defaultServer = "http://localhost:8080"
	}
	defaultAPIKey := os.Getenv("NOTHINGDNS_API_KEY")

	// Global flags
	fs.StringVar(&globalFlags.Server, "server", defaultServer, "NothingDNS API server URL (env: NOTHINGDNS_SERVER)")
	fs.StringVar(&globalFlags.APIKey, "api-key", defaultAPIKey, "API key for authentication (env: NOTHINGDNS_API_KEY)")
	// --version / -version: match the daemon binary so both tools
	// answer the standard CLI question the same way.
	showVersion := fs.Bool("version", false, "Show version and exit")
	// --help / -help: print the usage block instead of bailing out
	// with "flag: help requested" from flag.ContinueOnError.
	showHelp := fs.Bool("help", false, "Show usage and exit")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if *showVersion {
		fmt.Printf("%s version %s\n", Name, util.Version)
		return 0
	}
	if *showHelp {
		printUsage()
		return 0
	}

	parsedArgs := fs.Args()
	if len(parsedArgs) < 1 {
		printUsage()
		return 1
	}

	cmdName := parsedArgs[0]

	// Handle version (positional form — kept for back-compat).
	if cmdName == "version" {
		fmt.Printf("%s version %s\n", Name, util.Version)
		return 0
	}

	// Handle help (positional form).
	if cmdName == "help" {
		if len(parsedArgs) > 1 {
			return printCommandHelp(parsedArgs[1])
		}
		printUsage()
		return 0
	}

	// Find and run command
	for _, cmd := range commands {
		if cmd.Name == cmdName {
			if err := cmd.Run(parsedArgs[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}
			return 0
		}
	}

	fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmdName)
	fmt.Fprintf(os.Stderr, "Run '%s help' for usage.\n", os.Args[0])
	return 1
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

func printCommandHelp(cmdName string) int {
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
  peers             List cluster peers`,

		"blocklist": `Usage: dnsctl blocklist <subcommand>

Subcommands:
  status            Show blocklist statistics
  sources           List blocklist sources`,

		"config": `Usage: dnsctl config <subcommand>

Subcommands:
  get               Get current configuration
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
  health            Check server health
  bootstrap         Create the first dashboard admin (run on the server host)

Bootstrap options:
  --username NAME   Admin username (default: admin)
  --old-password    Also read the current password, to reset an existing admin

The password is read from NOTHINGDNS_ADMIN_PASSWORD or stdin, never argv.

Examples:
  dnsctl server bootstrap --username admin
  docker exec -i nothingdns dnsctl server bootstrap < password.txt`,
	}

	help, ok := helpTexts[cmdName]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmdName)
		return 1
	}
	fmt.Println(help)
	return 0
}
