// NothingDNS - Utility functions

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/config"
	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/util"
)

// decodeHex32 decodes a hex string into a 32-byte slice. Used by the
// L-6 at-rest encryption wiring (storage.encryption_key,
// cluster.snapshot_encryption_key). config.Validate has already
// enforced the same shape, so this is a defensive belt-and-braces
// decode at the consumption site.
func decodeHex32(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return raw, nil
}

// resolveDashboardBearer picks the static bearer the dashboard server
// will accept (when authenticateRequest's legacy-token branch fires).
// It returns the explicitly-configured AuthToken and NOTHING ELSE —
// in particular it must never return AuthSecret, which is the
// HMAC-SHA512 session-signing key. Leaking the dashboard bearer would
// otherwise leak the key needed to forge arbitrary session tokens.
// See SECURITY-REPORT.md H-1.
func resolveDashboardBearer(httpCfg config.HTTPConfig) string {
	return httpCfg.AuthToken
}

// validateAuthPersistenceConfig enforces SECURITY-REPORT.md L-4: an
// on-disk session-token file requires a stable AuthSecret. Without
// one the per-run random secret invalidates every persisted session
// at restart and the daemon silently boots with an empty token map
// — operators see only a "Failed to load persisted tokens" warning
// in the log. Fail-fast at startup so the misconfiguration is
// impossible to deploy.
func validateAuthPersistenceConfig(httpCfg config.HTTPConfig) error {
	if httpCfg.TokenPersistencePath != "" && httpCfg.AuthSecret == "" {
		return fmt.Errorf("token_persistence_path requires auth_secret to be set — without it, the per-run random secret invalidates every persisted session at restart (set auth_secret in config or remove token_persistence_path)")
	}
	return nil
}

// isSubdomain checks if child is a subdomain of parent.
func isSubdomain(child, parent string) bool {
	child = canonicalize(child)
	parent = canonicalize(parent)
	if parent == "." {
		return true
	}
	if child == parent {
		return true
	}
	return strings.HasSuffix(child, "."+parent)
}

// canonicalize ensures a domain name ends with a dot and is lowercase.
func canonicalize(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// typeToString converts a DNS type number to string.
func typeToString(qtype uint16) string {
	return protocol.TypeString(qtype)
}

// rcodeToString converts a DNS response code to a human-readable string.
func rcodeToString(rcode uint8) string {
	switch rcode {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	case 6:
		return "YXDOMAIN"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

// stringToType converts a type string to DNS type number.
func stringToType(s string) uint16 {
	return protocol.RecordTypeFromText(s)
}

// parseRData parses RData string based on record type.
func parseRData(rtype, rdata string) protocol.RData {
	return protocol.ParseRDataText(rtype, rdata)
}

// parseSOARData parses SOA RData: "mname rname serial refresh retry expire minimum"
func parseSOARData(rdata string) protocol.RData {
	return protocol.ParseRDataText("SOA", rdata)
}

// parseSRVRData parses SRV RData: "priority weight port target"
func parseSRVRData(rdata string) protocol.RData {
	return protocol.ParseRDataText("SRV", rdata)
}

// parseCAARData parses CAA RData: "flags tag value"
func parseCAARData(rdata string) protocol.RData {
	return protocol.ParseRDataText("CAA", rdata)
}

// rdataPacks reports whether rd serializes successfully to wire format.
func rdataPacks(rd protocol.RData) bool {
	return protocol.RDataPacksText(rd)
}

// extractTTL extracts a reasonable TTL from a response.
func extractTTL(resp *protocol.Message) uint32 {
	if resp == nil {
		return 300
	}
	for _, answer := range resp.Answers {
		if answer != nil && answer.TTL > 0 {
			return answer.TTL
		}
	}
	return 300
}

// hasDOBit checks if the client wants DNSSEC (DO bit in OPT record).
// The DO bit indicates the client supports DNSSEC and wants signatures.
func hasDOBit(msg *protocol.Message) bool {
	if msg == nil {
		return false
	}
	for _, rr := range msg.Additionals {
		if rr != nil && rr.Type == protocol.TypeOPT {
			// The DO bit is bit 15 of the TTL field in OPT records
			// Format: Extended RCODE (8 bits) | Version (8 bits) | DO (1 bit) | Z (15 bits)
			return (rr.TTL & 0x8000) != 0
		}
	}
	return false
}

// parseDurationOrDefault parses a duration string, returning defaultValue if parsing fails.
func parseDurationOrDefault(s string, defaultValue time.Duration) time.Duration {
	if s == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultValue
	}
	return d
}

// logLevelFromString converts a level string to LogLevel.
func logLevelFromString(s string) util.LogLevel {
	switch strings.ToLower(s) {
	case "debug":
		return util.DEBUG
	case "info":
		return util.INFO
	case "warn", "warning":
		return util.WARN
	case "error":
		return util.ERROR
	case "fatal":
		return util.FATAL
	default:
		return util.INFO
	}
}

// logFormatFromString converts a format string to LogFormat.
func logFormatFromString(s string) util.LogFormat {
	switch strings.ToLower(s) {
	case "json":
		return util.JSONFormat
	case "text":
		return util.TextFormat
	default:
		return util.TextFormat
	}
}

// loadRootHintsFile parses a named.root format file into resolver.RootHint entries.
// Lines are whitespace-delimited: NAME TTL CLASS TYPE RDATA
// NS records define root server names; A/AAAA records provide their addresses.
func loadRootHintsFile(path string) ([]resolver.RootHint, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Map server name -> hint (accumulates IPv4/IPv6)
	hintMap := make(map[string]*resolver.RootHint)
	var order []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == ';' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Fields: NAME [TTL] [CLASS] TYPE RDATA
		name := strings.ToLower(fields[0])
		rtype := ""
		rdata := ""

		// Find the type field — skip optional TTL and CLASS
		idx := 1
		for idx < len(fields)-1 {
			upper := strings.ToUpper(fields[idx])
			if upper == "A" || upper == "AAAA" || upper == "NS" {
				rtype = upper
				rdata = fields[idx+1]
				break
			}
			idx++
		}
		if rtype == "" {
			continue
		}

		switch rtype {
		case "NS":
			nsName := strings.ToLower(rdata)
			if !strings.HasSuffix(nsName, ".") {
				nsName += "."
			}
			if _, exists := hintMap[nsName]; !exists {
				hintMap[nsName] = &resolver.RootHint{Name: nsName}
				order = append(order, nsName)
			}
		case "A":
			if h, ok := hintMap[name]; ok {
				h.IPv4 = append(h.IPv4, rdata)
			}
		case "AAAA":
			if h, ok := hintMap[name]; ok {
				h.IPv6 = append(h.IPv6, rdata)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading root hints: %w", err)
	}

	if len(order) == 0 {
		return nil, fmt.Errorf("no root hints found in %s", path)
	}

	hints := make([]resolver.RootHint, 0, len(order))
	for _, name := range order {
		hints = append(hints, *hintMap[name])
	}
	return hints, nil
}
