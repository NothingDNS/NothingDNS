// NothingDNS - Utility functions

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/resolver"
	"github.com/nothingdns/nothingdns/internal/util"
)

// isSubdomain checks if child is a subdomain of parent.
func isSubdomain(child, parent string) bool {
	child = canonicalize(child)
	parent = canonicalize(parent)
	return len(child) >= len(parent) && child[len(child)-len(parent):] == parent
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

// stringToType converts a type string to DNS type number.
func stringToType(s string) uint16 {
	if t, ok := protocol.StringToType[strings.ToUpper(s)]; ok {
		return t
	}
	return 0
}

// parseRData parses RData string based on record type.
func parseRData(rtype, rdata string) protocol.RData {
	switch strings.ToUpper(rtype) {
	case "A":
		ip := net.ParseIP(rdata)
		if ip != nil {
			ipv4 := ip.To4()
			if ipv4 == nil {
				return nil
			}
			var addr [4]byte
			copy(addr[:], ipv4)
			return &protocol.RDataA{Address: addr}
		}
	case "AAAA":
		ip := net.ParseIP(rdata)
		if ip != nil {
			var addr [16]byte
			copy(addr[:], ip.To16())
			return &protocol.RDataAAAA{Address: addr}
		}
	case "CNAME":
		name, err := protocol.ParseName(rdata)
		if err == nil {
			return &protocol.RDataCNAME{CName: name}
		}
	case "NS":
		name, err := protocol.ParseName(rdata)
		if err == nil {
			return &protocol.RDataNS{NSDName: name}
		}
	case "PTR":
		name, err := protocol.ParseName(rdata)
		if err == nil {
			return &protocol.RDataPTR{PtrDName: name}
		}
	case "MX":
		parts := strings.Fields(rdata)
		if len(parts) >= 2 {
			pref, _ := strconv.Atoi(parts[0])
			exchange, err := protocol.ParseName(parts[1])
			if err == nil {
				return &protocol.RDataMX{
					Preference: uint16(pref),
					Exchange:   exchange,
				}
			}
		}
	case "TXT":
		return &protocol.RDataTXT{Strings: []string{rdata}}
	case "SOA":
		return parseSOARData(rdata)
	case "SRV":
		return parseSRVRData(rdata)
	case "CAA":
		return parseCAARData(rdata)
	}
	return nil
}

// parseSOARData parses SOA RData: "mname rname serial refresh retry expire minimum"
func parseSOARData(rdata string) protocol.RData {
	fields := strings.Fields(rdata)
	if len(fields) < 7 {
		return nil
	}
	mname, err := protocol.ParseName(fields[0])
	if err != nil {
		return nil
	}
	rname, err := protocol.ParseName(fields[1])
	if err != nil {
		return nil
	}
	serial, _ := strconv.ParseUint(fields[2], 10, 32)
	refresh, _ := strconv.ParseUint(fields[3], 10, 32)
	retry, _ := strconv.ParseUint(fields[4], 10, 32)
	expire, _ := strconv.ParseUint(fields[5], 10, 32)
	minimum, _ := strconv.ParseUint(fields[6], 10, 32)
	return &protocol.RDataSOA{
		MName:   mname,
		RName:   rname,
		Serial:  uint32(serial),
		Refresh: uint32(refresh),
		Retry:   uint32(retry),
		Expire:  uint32(expire),
		Minimum: uint32(minimum),
	}
}

// parseSRVRData parses SRV RData: "priority weight port target"
func parseSRVRData(rdata string) protocol.RData {
	fields := strings.Fields(rdata)
	if len(fields) < 4 {
		return nil
	}
	priority, _ := strconv.ParseUint(fields[0], 10, 16)
	weight, _ := strconv.ParseUint(fields[1], 10, 16)
	port, _ := strconv.ParseUint(fields[2], 10, 16)
	target, err := protocol.ParseName(fields[3])
	if err != nil {
		return nil
	}
	return &protocol.RDataSRV{
		Priority: uint16(priority),
		Weight:   uint16(weight),
		Port:     uint16(port),
		Target:   target,
	}
}

// parseCAARData parses CAA RData: "flags tag value"
func parseCAARData(rdata string) protocol.RData {
	fields := strings.Fields(rdata)
	if len(fields) < 3 {
		return nil
	}
	flags, _ := strconv.ParseUint(fields[0], 10, 8)
	return &protocol.RDataCAA{
		Flags: uint8(flags),
		Tag:   fields[1],
		Value: strings.Join(fields[2:], " "),
	}
}

// extractTTL extracts a reasonable TTL from a response.
func extractTTL(resp *protocol.Message) uint32 {
	if len(resp.Answers) > 0 && resp.Answers[0].TTL > 0 {
		return resp.Answers[0].TTL
	}
	return 300
}

// hasDOBit checks if the client wants DNSSEC (DO bit in OPT record).
// The DO bit indicates the client supports DNSSEC and wants signatures.
func hasDOBit(msg *protocol.Message) bool {
	for _, rr := range msg.Additionals {
		if rr.Type == protocol.TypeOPT {
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
