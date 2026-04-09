package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/nothingdns/nothingdns/internal/zone"
)

// RecordRequest represents a record to be added via API
type RecordRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

// ZoneImport handles importing BIND zone files into NothingDNS
type ZoneImport struct {
	zoneName   string
	adminEmail string
	nameservers []string
	records    []RecordRequest
	ttl        uint32
	origin     string
}

// ImportCommand handles the import subcommand for zone files
func cmdImport(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("import subcommand required (bind, validate)")
	}

	switch args[0] {
	case "bind":
		return cmdImportBind(args[1:])
	case "validate":
		return cmdValidateZone(args[1:])
	default:
		return fmt.Errorf("unknown import subcommand: %s (supported: bind, validate)", args[0])
	}
}

// cmdImportBind imports a BIND zone file
func cmdImportBind(args []string) error {
	var zoneFile string
	var dryRun bool
	var serverURL string

	// Parse flags
	i := 0
	for i < len(args) {
		switch args[i] {
		case "-f", "--file":
			if i+1 >= len(args) {
				return fmt.Errorf("flag %s requires argument", args[i])
			}
			zoneFile = args[i+1]
			i += 2
		case "-n", "--dry-run":
			dryRun = true
			i++
		case "-s", "--server":
			if i+1 >= len(args) {
				return fmt.Errorf("flag %s requires argument", args[i])
			}
			serverURL = args[i+1]
			i += 2
		case "-h", "--help":
			return printImportHelp()
		default:
			if strings.HasPrefix(args[i], "-") {
				return fmt.Errorf("unknown flag: %s", args[i])
			}
			if zoneFile == "" {
				zoneFile = args[i]
			}
			i++
		}
	}

	if zoneFile == "" {
		return fmt.Errorf("zone file required (use -f flag)")
	}

	// Parse the BIND zone file
	z, err := parseBINDZoneFile(zoneFile)
	if err != nil {
		return fmt.Errorf("failed to parse zone file: %w", err)
	}

	fmt.Printf("Parsed zone: %s (%d records)\n", z.zoneName, len(z.records))

	if dryRun {
		fmt.Println("\n=== DRY RUN - Records to be imported ===")
		for _, r := range z.records {
			fmt.Printf("%s %d %s %s\n", r.Name, r.TTL, r.Type, r.Data)
		}
		return nil
	}

	if serverURL == "" {
		serverURL = getServerURL()
	}

	// Import via API
	return importZoneViaAPI(serverURL, z)
}

// parseBINDZoneFile parses a BIND zone file and returns a ZoneImport
func parseBINDZoneFile(filename string) (*ZoneImport, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	// Use the built-in zone parser for BIND format
	z, err := zone.ParseFile(filename, file)
	if err != nil {
		return nil, fmt.Errorf("parsing zone file: %w", err)
	}

	// Validate the zone
	if err := z.Validate(); err != nil {
		return nil, fmt.Errorf("validating zone: %w", err)
	}

	zi := &ZoneImport{
		zoneName: z.Origin,
		ttl:      3600,
		records:  make([]RecordRequest, 0, countRecords(z)),
	}

	// Extract SOA info
	if z.SOA != nil {
		zi.adminEmail = z.SOA.RName
		zi.ttl = z.SOA.TTL
	}

	// Extract NS records for nameservers
	if nsRecords, ok := z.Records["NS"]; ok {
		for _, ns := range nsRecords {
			zi.nameservers = append(zi.nameservers, ns.RData)
		}
	}

	// Convert all records
	for rtype, recs := range z.Records {
		for _, rec := range recs {
			// Skip meta-records
			if rtype == "SOA" || rtype == "NS" {
				continue
			}

			recReq := RecordRequest{
				Name: rec.Name,
				Type: rtype,
				TTL:  rec.TTL,
				Data: rec.RData,
			}
			zi.records = append(zi.records, recReq)
		}
	}

	return zi, nil
}

// countRecords counts total records in a zone
func countRecords(z *zone.Zone) int {
	total := 0
	for _, recs := range z.Records {
		total += len(recs)
	}
	return total
}

// importZoneViaAPI imports the zone via the NothingDNS API
func importZoneViaAPI(serverURL string, zi *ZoneImport) error {
	// First create the zone
	createReq := map[string]interface{}{
		"name":        zi.zoneName,
		"ttl":         zi.ttl,
		"admin_email": zi.adminEmail,
		"nameservers": zi.nameservers,
	}

	body, err := json.Marshal(createReq)
	if err != nil {
		return fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := http.Post(serverURL+"/api/v1/zones", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("creating zone: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		fmt.Println("Zone already exists, adding records...")
	} else if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("zone creation failed (%d): %s", resp.StatusCode, string(respBody))
	}

	// Add records
	added := 0
	for _, rec := range zi.records {
		recReq := map[string]interface{}{
			"name": rec.Name,
			"type": rec.Type,
			"ttl":  rec.TTL,
			"data": rec.Data,
		}

		body, err := json.Marshal(recReq)
		if err != nil {
			continue
		}

		url := fmt.Sprintf("%s/api/v1/zones/%s/records", serverURL, zi.zoneName)
		resp, err := http.Post(url, "application/json", strings.NewReader(string(body)))
		if err != nil {
			fmt.Printf("Warning: failed to add record %s %s: %v\n", rec.Name, rec.Type, err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusCreated {
			added++
		}
	}

	fmt.Printf("Successfully imported zone %s (%d/%d records added)\n", zi.zoneName, added, len(zi.records))
	return nil
}

// cmdValidateZone validates a zone file without importing
func cmdValidateZone(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("zone file required")
	}

	filename := args[0]

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	// Use built-in parser
	z, err := zone.ParseFile(filename, file)
	if err != nil {
		return fmt.Errorf("parsing failed: %w", err)
	}

	// Validate
	if err := z.Validate(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Count records by type
	typeCounts := make(map[string]int)
	total := 0
	for rtype, records := range z.Records {
		typeCounts[rtype] = len(records)
		total += len(records)
	}

	fmt.Printf("Zone %s is valid\n", z.Origin)
	fmt.Printf("Total records: %d\n", total)
	if soa := z.SOA; soa != nil {
		fmt.Printf("SOA: %s %s (Serial: %d)\n", soa.MName, soa.RName, soa.Serial)
	}
	fmt.Println("\nRecords by type:")
	for rtype, count := range typeCounts {
		fmt.Printf("  %s: %d\n", rtype, count)
	}

	return nil
}

// printImportHelp prints help for the import command
func printImportHelp() error {
	help := `
Usage: dnsctl import bind [flags] [zone-file]

Import a BIND zone file into NothingDNS.

Flags:
  -f, --file FILE     Zone file to import (required)
  -s, --server URL    NothingDNS API server URL (default: localhost:5380)
  -n, --dry-run       Parse and show records without importing
  -h, --help          Show this help

Examples:
  dnsctl import bind -f example.com.zone
  dnsctl import bind -f example.com.zone --dry-run
  dnsctl import bind -f example.com.zone -s http://localhost:5380

Usage: dnsctl import validate [zone-file]

Validate a BIND zone file without importing.

Examples:
  dnsctl import validate example.com.zone
`
	fmt.Println(help)
	return nil
}

func getServerURL() string {
	// Could read from config file, environment variable, etc.
	return "http://localhost:5380"
}

// ImportFile imports a zone file directly (for programmatic use)
func ImportFile(filename string) (*ZoneImport, error) {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".zone" || ext == "" || ext == ".txt" {
		return parseBINDZoneFile(filename)
	}
	return nil, fmt.Errorf("unsupported file type: %s", ext)
}

// Export exports a ZoneImport to BIND format
func (zi *ZoneImport) Export() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("$ORIGIN %s\n", zi.zoneName))
	sb.WriteString(fmt.Sprintf("$TTL %d\n\n", zi.ttl))

	for _, rec := range zi.records {
		sb.WriteString(fmt.Sprintf("%s %d IN %s %s\n", rec.Name, rec.TTL, rec.Type, rec.Data))
	}

	return sb.String()
}

// GenerateRecords generates DNS records from a $GENERATE directive
func GenerateRecords(rangeStr, ownerTemplate, recordType, rhsTemplate string, ttl uint32) ([]RecordRequest, error) {
	// Parse range: 1-10 or 0-10/2
	re := regexp.MustCompile(`^(\d+)-(\d+)(?:/(\d+))?$`)
	matches := re.FindStringSubmatch(rangeStr)
	if matches == nil {
		return nil, fmt.Errorf("invalid range: %s", rangeStr)
	}

	start, _ := strconv.Atoi(matches[1])
	stop, _ := strconv.Atoi(matches[2])
	step := 1
	if matches[3] != "" {
		step, _ = strconv.Atoi(matches[3])
		if step == 0 {
			step = 1
		}
	}

	records := make([]RecordRequest, 0, (stop-start)/step+1)
	for i := start; i <= stop; i += step {
		iStr := strconv.Itoa(i)

		// Replace $ with the current number in owner
		owner := strings.ReplaceAll(ownerTemplate, "$", iStr)
		owner = strings.ReplaceAll(owner, "${0}", iStr)

		// Replace $N in rhs
		rhs := rhsTemplate
		for j := 0; j <= 9; j++ {
			rhs = strings.ReplaceAll(rhs, fmt.Sprintf("$%d", j), iStr)
			rhs = strings.ReplaceAll(rhs, fmt.Sprintf("${%d}", j), iStr)
		}

		rec := RecordRequest{
			Name: owner,
			Type: recordType,
			TTL:  ttl,
			Data: rhs,
		}
		records = append(records, rec)
	}

	return records, nil
}
