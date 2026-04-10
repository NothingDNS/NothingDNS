package geodns

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
)

// MMDB (MaxMind DB) format constants.
const (
	mmdbMetadataMarker = "\xAB\xCD\xEFMaxMind.com"
	mmdbNodeSize       = 24 // 6 bytes per node (left/right children, 3 bytes each)
	mmdbVersion        = 2
)

// GeoRecord holds geo-targeted DNS record data.
type GeoRecord struct {
	// Records maps region codes to record data.
	// Key: region code (e.g., "US", "NA", "AS1234")
	// Value: RData string
	Records map[string]string
	// Default is used when no geo rule matches.
	Default string
	// Type is the DNS record type (e.g., "A", "AAAA").
	Type string
	// TTL for the response.
	TTL uint32
}

// GeoRule defines a geographic matching rule.
type GeoRule struct {
	// Domain pattern this rule applies to.
	Domain string
	// Record type this rule applies to.
	Type string
	// GeoRecords for this rule.
	GeoRecords *GeoRecord
}

// Engine provides GeoDNS resolution.
type Engine struct {
	mu sync.RWMutex

	// Geo rules keyed by domain:type
	rules map[string]*GeoRecord

	// MMDB data.
	mmdbData      []byte
	mmdbIPv4Count uint32
	mmdbIPv6Count uint32
	mmdbTreeSize  uint32
	mmdbLoaded    bool

	// Metadata.
	enabled bool

	// Metrics.
	lookups uint64
	hits    uint64
	misses  uint64
}

// Config holds GeoDNS engine configuration.
type Config struct {
	Enabled bool
	// MMDBFile is the path to the MaxMind GeoIP database file.
	MMDBFile string
	// GeoRules maps domain:type to a GeoRecord.
	// Loaded from config or API.
	GeoRules map[string]*GeoRecord
}

// NewEngine creates a new GeoDNS engine.
func NewEngine(cfg Config) *Engine {
	e := &Engine{
		enabled: cfg.Enabled,
		rules:   make(map[string]*GeoRecord),
	}
	if cfg.GeoRules != nil {
		for k, v := range cfg.GeoRules {
			e.rules[k] = v
		}
	}
	return e
}

// LoadMMDB loads a MaxMind DB file for geo lookups.
func (e *Engine) LoadMMDB(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("geodns: read mmdb: %w", err)
	}

	// Find metadata section (search from end of file)
	idx := len(data) - len(mmdbMetadataMarker)
	if idx < 0 {
		return fmt.Errorf("geodns: invalid mmdb: metadata marker not found")
	}

	found := -1
	for i := idx; i >= 0; i-- {
		if string(data[i:i+len(mmdbMetadataMarker)]) == mmdbMetadataMarker {
			found = i
			break
		}
	}
	if found == -1 {
		return fmt.Errorf("geodns: metadata marker not found")
	}

	// Parse metadata (simple key-value pairs after marker)
	metaStart := found + len(mmdbMetadataMarker)
	if metaStart >= len(data) {
		return fmt.Errorf("geodns: truncated metadata")
	}

	// Extract key fields from metadata
	ipv4Count, treeSize, err := parseMMDBMetadata(data[metaStart:])
	if err != nil {
		return fmt.Errorf("geodns: parse metadata: %w", err)
	}

	e.mu.Lock()
	e.mmdbData = data
	e.mmdbIPv4Count = ipv4Count
	e.mmdbTreeSize = treeSize
	e.mmdbLoaded = true
	e.mu.Unlock()

	return nil
}

// parseMMDBMetadata extracts tree size and node count from MMDB metadata.
// MMDB metadata is encoded as a simple data section with key-value pairs.
func parseMMDBMetadata(data []byte) (ipv4Count, treeSize uint32, err error) {
	// MMDB metadata uses a TLV-like format.
	// We look for "node_count" and "tree_size" fields.
	// For a minimal parser, we extract the data section start offset.

	// The metadata structure is a map with known fields.
	// In binary MMDB format, the metadata section before the data section
	// contains: node_count (uint32), tree_size in bytes.
	// We do a simplified parse looking for the data section offset.

	// The tree is made of 24-byte nodes. node_count * 24 = tree bytes.
	// For IPv4, only the first node_count nodes are relevant.
	// For IPv6, all nodes are searched.

	// Try to find "node_count" field in the metadata map
	offset := 0
	for offset < len(data)-6 {
		// Look for field markers (simplified)
		// MMDB metadata is actually in a custom binary format
		// For our parser, we read the last 16 bytes of metadata
		// which typically contain node_count and record_size
		if offset+4 <= len(data) {
			val := binary.BigEndian.Uint32(data[offset : offset+4])
			if val > 0 && val < 100000000 {
				// Likely a node count
				if ipv4Count == 0 {
					ipv4Count = val
				}
			}
		}
		offset++
	}

	// Calculate tree size from node count
	// Each node is 24 bytes (2 * 3-byte pointers for record_size=24)
	if ipv4Count > 0 {
		treeSize = ipv4Count * 24
	}

	if ipv4Count == 0 {
		return 0, 0, fmt.Errorf("could not determine node count")
	}

	return ipv4Count, treeSize, nil
}

// LookupCountry looks up the country code for an IP address using the MMDB.
func (e *Engine) LookupCountry(ip net.IP) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.mmdbLoaded || len(e.mmdbData) == 0 {
		return ""
	}

	result := e.mmdbLookup(ip)
	if result == nil {
		return ""
	}

	// Extract country ISO code from the record
	return extractCountryCode(result)
}

// LookupASN looks up the ASN for an IP address.
func (e *Engine) LookupASN(ip net.IP) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.mmdbLoaded || len(e.mmdbData) == 0 {
		return ""
	}

	result := e.mmdbLookup(ip)
	if result == nil {
		return ""
	}

	return extractASN(result)
}

// LookupContinent looks up the continent code for an IP address.
func (e *Engine) LookupContinent(ip net.IP) string {
	country := e.LookupCountry(ip)
	return countryToContinent(country)
}

// mmdbLookup traverses the MMDB tree for the given IP.
func (e *Engine) mmdbLookup(ip net.IP) []byte {
	ip = ip.To4()
	isIPv4 := ip != nil
	if !isIPv4 {
		ip = ip.To16()
	}

	if ip == nil {
		return nil
	}

	nodeCount := e.mmdbIPv4Count
	if !isIPv4 {
		nodeCount = e.mmdbIPv6Count
		if nodeCount == 0 {
			nodeCount = e.mmdbIPv4Count // fallback
		}
	}

	// Traverse the tree bit by bit
	nodeIdx := uint32(0)
	bits := len(ip) * 8

	for i := 0; i < bits; i++ {
		if nodeIdx >= nodeCount {
			// Data section
			dataOffset := nodeIdx - nodeCount
			dataStart := e.mmdbTreeSize
			if int(dataStart+dataOffset) < len(e.mmdbData) {
				return e.parseDataRecord(int(dataStart + dataOffset))
			}
			return nil
		}

		// Read node (6 bytes: left 3 bytes + right 3 bytes)
		// Using 24-bit record size (6 bytes per node)
		byteOffset := nodeIdx * 6
		if int(byteOffset)+6 > int(e.mmdbTreeSize) {
			return nil
		}

		nodeData := e.mmdbData[byteOffset : byteOffset+6]

		var nextNode uint32
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1

		if bit == 0 {
			// Left child (first 3 bytes)
			nextNode = uint32(nodeData[0])<<16 | uint32(nodeData[1])<<8 | uint32(nodeData[2])
		} else {
			// Right child (last 3 bytes)
			nextNode = uint32(nodeData[3])<<16 | uint32(nodeData[4])<<8 | uint32(nodeData[5])
		}

		nodeIdx = nextNode
	}

	return nil
}

// parseDataRecord parses a data record from the MMDB data section.
func (e *Engine) parseDataRecord(offset int) []byte {
	if offset >= len(e.mmdbData) {
		return nil
	}
	// Data records start with a type byte followed by length and content.
	// Simplified: return raw bytes for further parsing.
	return e.mmdbData[offset:]
}

// Resolve performs GeoDNS resolution for a query.
// Returns the RData string matching the client's geo location, or empty string.
func (e *Engine) Resolve(domain, rtype string, clientIP net.IP) string {
	if !e.enabled {
		return ""
	}

	atomic.AddUint64(&e.lookups, 1)

	key := domain + ":" + rtype

	e.mu.RLock()
	geoRec, ok := e.rules[key]
	e.mu.RUnlock()

	if !ok {
		atomic.AddUint64(&e.misses, 1)
		return ""
	}

	// Try geo lookups in order of specificity:
	// 1. ASN match (e.g., "AS1234")
	// 2. Country match (e.g., "US")
	// 3. Continent match (e.g., "NA")
	// 4. Default

	// Check ASN
	asn := e.LookupASN(clientIP)
	if asn != "" {
		if data, ok := geoRec.Records[asn]; ok {
			atomic.AddUint64(&e.hits, 1)
			return data
		}
	}

	// Check country
	country := e.LookupCountry(clientIP)
	if country != "" {
		if data, ok := geoRec.Records[country]; ok {
			atomic.AddUint64(&e.hits, 1)
			return data
		}
	}

	// Check continent
	continent := countryToContinent(country)
	if continent != "" {
		if data, ok := geoRec.Records[continent]; ok {
			atomic.AddUint64(&e.hits, 1)
			return data
		}
	}

	// Default
	if geoRec.Default != "" {
		atomic.AddUint64(&e.hits, 1)
		return geoRec.Default
	}

	atomic.AddUint64(&e.misses, 1)
	return ""
}

// SetRule adds or updates a geo rule.
func (e *Engine) SetRule(domain, rtype string, rec *GeoRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := domain + ":" + rtype
	e.rules[key] = rec
}

// RemoveRule removes a geo rule.
func (e *Engine) RemoveRule(domain, rtype string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := domain + ":" + rtype
	delete(e.rules, key)
}

// Stats returns GeoDNS engine statistics.
func (e *Engine) Stats() Stats {
	e.mu.RLock()
	ruleCount := len(e.rules)
	e.mu.RUnlock()

	return Stats{
		Enabled:    e.enabled,
		Rules:      ruleCount,
		MMDBLoaded: e.mmdbLoaded,
		Lookups:    atomic.LoadUint64(&e.lookups),
		Hits:       atomic.LoadUint64(&e.hits),
		Misses:     atomic.LoadUint64(&e.misses),
	}
}

// IsEnabled returns whether the engine is enabled.
func (e *Engine) IsEnabled() bool {
	return e.enabled
}

// Stats holds GeoDNS statistics.
type Stats struct {
	Enabled    bool
	Rules      int
	MMDBLoaded bool
	Lookups    uint64
	Hits       uint64
	Misses     uint64
}

// extractCountryCode extracts an ISO country code from raw MMDB data.
func extractCountryCode(data []byte) string {
	// In MMDB format, the country ISO code is stored as a 2-byte string
	// preceded by a field indicator. Search for "country" → "iso_code" pattern.
	// The structure is typically: map{ "country" => map{ "iso_code" => string(2 chars) } }

	// Simple approach: scan for 2-letter ASCII sequences that look like country codes
	for i := 0; i < len(data)-2; i++ {
		// Look for pointer + string type marker followed by 2 uppercase ASCII letters
		if data[i] == 0x02 && i+2 < len(data) {
			code := string(data[i+1 : i+3])
			if isUpperAlpha(code[0]) && isUpperAlpha(code[1]) {
				return code
			}
		}
	}
	return ""
}

// extractASN extracts an ASN from raw MMDB data.
func extractASN(data []byte) string {
	// ASN is stored as a uint32 in the MMDB.
	// Look for the ASN field and format as "AS<number>"
	for i := 0; i < len(data)-4; i++ {
		// ASN values are typically stored as uint32 or uint16
		if data[i] >= 0xc0 && data[i] <= 0xc7 {
			// Could be an unsigned integer type
			asn := uint32(data[i+1])<<16 | uint32(data[i+2])<<8 | uint32(data[i+3])
			if asn > 0 && asn < 10000000 {
				return fmt.Sprintf("AS%d", asn)
			}
		}
	}
	return ""
}

// countryToContinent maps ISO country codes to continent codes.
func countryToContinent(country string) string {
	if len(country) != 2 {
		return ""
	}
	continentMap := map[string]string{
		"AF": "AS", "AL": "EU", "DZ": "AF", "AD": "EU", "AO": "AF",
		"AG": "NA", "AR": "SA", "AM": "AS", "AU": "OC", "AT": "EU",
		"AZ": "AS", "BS": "NA", "BH": "AS", "BD": "AS", "BB": "NA",
		"BY": "EU", "BE": "EU", "BZ": "NA", "BJ": "AF", "BT": "AS",
		"BO": "SA", "BA": "EU", "BW": "AF", "BR": "SA", "BN": "AS",
		"BG": "EU", "BF": "AF", "BI": "AF", "KH": "AS", "CM": "AF",
		"CA": "NA", "CF": "AF", "TD": "AF", "CL": "SA", "CN": "AS",
		"CO": "SA", "CD": "AF", "CG": "AF", "CR": "NA", "HR": "EU",
		"CU": "NA", "CY": "AS", "CZ": "EU", "DK": "EU", "DJ": "AF",
		"DM": "NA", "DO": "NA", "EC": "SA", "EG": "AF", "SV": "NA",
		"GQ": "AF", "ER": "AF", "EE": "EU", "ET": "AF", "FJ": "OC",
		"FI": "EU", "FR": "EU", "GA": "AF", "GM": "AF", "GE": "AS",
		"DE": "EU", "GH": "AF", "GR": "EU", "GD": "NA", "GT": "NA",
		"GN": "AF", "GW": "AF", "GY": "SA", "HT": "NA", "HN": "NA",
		"HU": "EU", "IS": "EU", "IN": "AS", "ID": "AS", "IR": "AS",
		"IQ": "AS", "IE": "EU", "IL": "AS", "IT": "EU", "CI": "AF",
		"JM": "NA", "JP": "AS", "JO": "AS", "KZ": "AS", "KE": "AF",
		"KI": "OC", "KP": "AS", "KR": "AS", "KW": "AS", "KG": "AS",
		"LA": "AS", "LV": "EU", "LB": "AS", "LS": "AF", "LR": "AF",
		"LY": "AF", "LI": "EU", "LT": "EU", "LU": "EU", "MK": "EU",
		"MG": "AF", "MW": "AF", "MY": "AS", "MV": "AS", "ML": "AF",
		"MT": "EU", "MH": "OC", "MR": "AF", "MU": "AF", "MX": "NA",
		"FM": "OC", "MD": "EU", "MC": "EU", "MN": "AS", "ME": "EU",
		"MA": "AF", "MZ": "AF", "MM": "AS", "NA": "AF", "NR": "OC",
		"NP": "AS", "NL": "EU", "NZ": "OC", "NI": "NA", "NE": "AF",
		"NG": "AF", "NO": "EU", "OM": "AS", "PK": "AS", "PW": "OC",
		"PA": "NA", "PG": "OC", "PY": "SA", "PE": "SA", "PH": "AS",
		"PL": "EU", "PT": "EU", "QA": "AS", "RO": "EU", "RU": "EU",
		"RW": "AF", "KN": "NA", "LC": "NA", "VC": "NA", "WS": "OC",
		"SM": "EU", "ST": "AF", "SA": "AS", "SN": "AF", "RS": "EU",
		"SC": "AF", "SL": "AF", "SG": "AS", "SK": "EU", "SI": "EU",
		"SB": "OC", "SO": "AF", "ZA": "AF", "ES": "EU", "LK": "AS",
		"SD": "AF", "SR": "SA", "SZ": "AF", "SE": "EU", "CH": "EU",
		"SY": "AS", "TW": "AS", "TJ": "AS", "TZ": "AF", "TH": "AS",
		"TL": "AS", "TG": "AF", "TO": "OC", "TT": "NA", "TN": "AF",
		"TR": "AS", "TM": "AS", "TV": "OC", "UG": "AF", "UA": "EU",
		"AE": "AS", "GB": "EU", "US": "NA", "UY": "SA", "UZ": "AS",
		"VU": "OC", "VE": "SA", "VN": "AS", "YE": "AS", "ZM": "AF",
		"ZW": "AF",
	}
	if c, ok := continentMap[country]; ok {
		return c
	}
	return ""
}

func isUpperAlpha(b byte) bool {
	return b >= 'A' && b <= 'Z'
}
