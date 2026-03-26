// dnsctl - CLI management tool for NothingDNS
// Communicates with NothingDNS via REST API

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/dnssec"
	"github.com/nothingdns/nothingdns/internal/protocol"
)

const (
	Version = "0.1.0"
	Name    = "dnsctl"
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
		fmt.Printf("%s version %s\n", Name, Version)
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

// Command implementations (placeholders)

func cmdZone(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("zone subcommand required (list, add, remove, reload, export)")
	}
	// TODO: Implement zone management via REST API
	fmt.Printf("Zone command: %s (not yet implemented)\n", strings.Join(args, " "))
	return nil
}

func cmdRecord(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("record subcommand required (add, remove, update)")
	}
	// TODO: Implement record management via REST API
	fmt.Printf("Record command: %s (not yet implemented)\n", strings.Join(args, " "))
	return nil
}

func cmdCache(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cache subcommand required (flush, stats)")
	}
	// TODO: Implement cache operations via REST API
	fmt.Printf("Cache command: %s (not yet implemented)\n", strings.Join(args, " "))
	return nil
}

func cmdCluster(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("cluster subcommand required (status, peers, join, leave)")
	}
	// TODO: Implement cluster management via REST API
	fmt.Printf("Cluster command: %s (not yet implemented)\n", strings.Join(args, " "))
	return nil
}

func cmdBlocklist(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("blocklist subcommand required (reload, status)")
	}
	// TODO: Implement blocklist management via REST API
	fmt.Printf("Blocklist command: %s (not yet implemented)\n", strings.Join(args, " "))
	return nil
}

func cmdConfig(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("config subcommand required (get, set, reload)")
	}
	// TODO: Implement config operations via REST API
	fmt.Printf("Config command: %s (not yet implemented)\n", strings.Join(args, " "))
	return nil
}

func cmdDig(args []string) error {
	// TODO: Implement built-in dig using internal/protocol directly
	// This is the only command that doesn't use REST API
	fmt.Printf("Dig command: %s (not yet implemented)\n", strings.Join(args, " "))
	return nil
}

func cmdServer(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("server subcommand required (status, stats, health)")
	}
	// TODO: Implement server operations via REST API
	fmt.Printf("Server command: %s (not yet implemented)\n", strings.Join(args, " "))
	return nil
}

func cmdDNSSEC(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("dnssec subcommand required (generate-key, ds-from-dnskey, sign-zone, verify-anchor)")
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

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Mark flags as used (TODO: implement in full zone signing)
	_ = nsec3Iterations
	_ = nsec3Salt

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

	fmt.Printf("Signing zone %s...\n", *zone)
	fmt.Printf("  Input: %s\n", *inputFile)
	fmt.Printf("  Output: %s\n", *outputFile)
	fmt.Printf("  NSEC3: %v\n", *nsec3)

	// TODO: Implement full zone signing
	// For now, this is a placeholder that shows the command structure
	fmt.Println("Zone signing not yet fully implemented")
	fmt.Println("This command will:")
	fmt.Println("  1. Load all private keys from", *keyDir)
	fmt.Println("  2. Parse the zone file")
	fmt.Println("  3. Sign all RRsets")
	fmt.Println("  4. Generate NSEC/NSEC3 chain")
	fmt.Println("  5. Write signed zone to output file")

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
		privKey, err = rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return nil, err
		}
		pubKey = &privKey.(*rsa.PrivateKey).PublicKey

	case protocol.AlgorithmECDSAP256SHA256:
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pubKey = &privKey.(*ecdsa.PrivateKey).PublicKey

	case protocol.AlgorithmECDSAP384SHA384:
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pubKey = &privKey.(*ecdsa.PrivateKey).PublicKey

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
	// TODO: Implement proper private key serialization
	// For now, write a placeholder
	content := fmt.Sprintf("Private-key-format: v1.3\n")
	content += fmt.Sprintf("Algorithm: %d (%s)\n", key.DNSKEY.Algorithm, algorithmName(key.DNSKEY.Algorithm))
	content += fmt.Sprintf("KeyTag: %d\n", key.KeyTag)
	content += fmt.Sprintf("Created: %s\n", time.Now().UTC().Format(time.RFC3339))
	content += fmt.Sprintf("# TODO: Implement full private key serialization\n")

	return os.WriteFile(path, []byte(content), 0600)
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
