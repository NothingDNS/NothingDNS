package geodns

import (
	"encoding/binary"
	"fmt"
	"io"
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
	maxMMDBFileSize    = 256 << 20
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

	// MMDB data + parsed metadata cache.
	mmdbData       []byte
	mmdbIPv4Count  uint32
	mmdbIPv6Count  uint32
	mmdbTreeSize   uint32
	mmdbRecordSize uint32 // 24, 28, or 32 bits per tree-node record
	mmdbIPVersion  uint32 // 4 or 6 (DB-level, distinct from query IP version)
	mmdbNodeCount  uint32 // total BST node count (== mmdbIPv4Count for v4 DBs)
	mmdbLoaded     bool

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

// LoadMMDB loads a MaxMind DB file using the real binary-format parser in
// mmdb.go (RFC: https://maxmind.github.io/MaxMind-DB/).
func (e *Engine) LoadMMDB(path string) error {
	data, err := readMMDBFile(path, maxMMDBFileSize)
	if err != nil {
		return fmt.Errorf("geodns: read mmdb: %w", err)
	}

	nodeCount, recordSize, ipVersion, metadataStart, _, err := mmdbParseMetadata(data)
	if err != nil {
		return fmt.Errorf("geodns: parse metadata: %w", err)
	}

	// Tree size = nodeCount * (2*recordSize) bits = nodeCount * recordSize / 4 bytes.
	treeBytes64 := uint64(nodeCount) * uint64(recordSize*2) / 8
	if treeBytes64 > uint64(^uint32(0)) {
		return fmt.Errorf("geodns: mmdb tree too large: %d bytes", treeBytes64)
	}
	if treeBytes64 > uint64(metadataStart) || metadataStart < int(treeBytes64)+16 {
		return fmt.Errorf("geodns: invalid mmdb tree size %d before metadata offset %d", treeBytes64, metadataStart)
	}
	treeBytes := uint32(treeBytes64)

	e.mu.Lock()
	e.mmdbData = data
	if ipVersion == 4 {
		e.mmdbIPv4Count = nodeCount
		e.mmdbIPv6Count = 0
	} else {
		e.mmdbIPv4Count = nodeCount
		e.mmdbIPv6Count = nodeCount
	}
	e.mmdbTreeSize = treeBytes
	e.mmdbRecordSize = recordSize
	e.mmdbIPVersion = ipVersion
	e.mmdbNodeCount = nodeCount
	e.mmdbLoaded = true
	e.mu.Unlock()
	return nil
}

func readMMDBFile(path string, maxSize int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("mmdb file exceeds %d bytes", maxSize)
	}
	return data, nil
}

// parseMMDBMetadata extracts tree size and node count from MMDB metadata.
// SEE F138: this is a brute-force heuristic, not an MMDB parser. Retained
// solely so unit tests compile. Do not call from production paths.
func parseMMDBMetadata(data []byte) (ipv4Count, treeSize uint32, err error) {
	offset := 0
	for offset < len(data)-6 {
		if offset+4 <= len(data) {
			val := binary.BigEndian.Uint32(data[offset : offset+4])
			if val > 0 && val < 100000000 {
				if ipv4Count == 0 {
					ipv4Count = val
				}
			}
		}
		offset++
	}
	if ipv4Count > 0 {
		treeSize = ipv4Count * 24
	}
	if ipv4Count == 0 {
		return 0, 0, fmt.Errorf("could not determine node count")
	}
	return ipv4Count, treeSize, nil
}

// LookupCountry looks up the ISO 3166-1 alpha-2 country code for ip
// (e.g. "US", "DE"). Returns "" when the IP is not in the database or
// the record lacks a country.iso_code field.
//
// GeoLite2-Country / GeoIP2-Country / GeoIP2-City all use the structure
//
//	{ "country": { "iso_code": "<code>", ... }, ... }
//
// so the same code path works across products.
func (e *Engine) LookupCountry(ip net.IP) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.mmdbLoaded || len(e.mmdbData) == 0 {
		return ""
	}
	rec := e.mmdbLookup(ip)
	if rec == nil {
		return ""
	}
	country, ok := rec["country"].(map[string]interface{})
	if !ok {
		return ""
	}
	iso, _ := country["iso_code"].(string)
	return iso
}

// LookupASN looks up the autonomous system number for ip, returned as
// "AS<number>" (e.g. "AS15169"). Returns "" when the IP is not in the
// database or the record lacks an autonomous_system_number field.
//
// GeoLite2-ASN encodes the field as a uint32 at the top level:
//
//	{ "autonomous_system_number": <uint32>, "autonomous_system_organization": "...", ... }
func (e *Engine) LookupASN(ip net.IP) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.mmdbLoaded || len(e.mmdbData) == 0 {
		return ""
	}
	rec := e.mmdbLookup(ip)
	if rec == nil {
		return ""
	}
	asn, ok := rec["autonomous_system_number"].(uint64)
	if !ok {
		return ""
	}
	return fmt.Sprintf("AS%d", asn)
}

// LookupContinent looks up the continent code for an IP address.
func (e *Engine) LookupContinent(ip net.IP) string {
	country := e.LookupCountry(ip)
	return countryToContinent(country)
}

// mmdbLookup traverses the MMDB tree for ip and, if found, returns the
// decoded data-section record (always a typed map for GeoLite2/GeoIP2
// databases). Returns nil on "not found" or any decode error.
//
// IPv4 lookups against an IPv6 database expand to the ::ffff:0:0/96
// IPv4-mapped range per MaxMind convention (MMDB §1.4 "IPv4 in IPv6").
func (e *Engine) mmdbLookup(ip net.IP) map[string]interface{} {
	if ip == nil {
		return nil
	}

	// Normalise: IPv4 in v6 DB → expand to 16-byte IPv4-mapped form.
	var lookupIP net.IP
	var bits int
	if ip4 := ip.To4(); ip4 != nil {
		if e.mmdbIPVersion == 6 {
			lookupIP = ip.To16() // ::ffff:a.b.c.d
			bits = 128
		} else {
			lookupIP = ip4
			bits = 32
		}
	} else {
		lookupIP = ip.To16()
		if lookupIP == nil {
			return nil
		}
		bits = 128
		// An IPv6 query against a v4-only DB has no useful answer.
		if e.mmdbIPVersion == 4 {
			return nil
		}
	}

	// Tree walk to get the data-section offset (absolute file offset).
	treeBytes := e.mmdbTreeSize
	if uint64(treeBytes) > uint64(len(e.mmdbData)) {
		return nil
	}
	tree := e.mmdbData[:treeBytes]
	dataOff, ok, err := mmdbLookup(tree, e.mmdbNodeCount, e.mmdbRecordSize, lookupIP, bits)
	if err != nil || !ok {
		return nil
	}

	// Decode the data-section record at the absolute file offset returned
	// by mmdbLookup. dataStart is the start of the data section, used by
	// the decoder to resolve internal pointers relative to it.
	//
	// mmdbLookup already returns an absolute file offset computed per the
	// MaxMind spec ($offset_in_file = (record_value - node_count) +
	// search_tree_size), so a single decode attempt is correct — a retry
	// with identical arguments would only duplicate the same failure.
	dec := &mmdbDecoder{
		buf:       e.mmdbData,
		dataStart: int(treeBytes) + 16,
	}
	v, _, err := dec.decodeValue(int(dataOff), 32)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]interface{})
	return m
}

// parseDataRecord is a legacy helper kept for unit tests of the bounds-
// check branch. The real lookup path uses mmdbDecoder.decodeValue.
//
//nolint:unused // retained for legacy test compatibility.
func (e *Engine) parseDataRecord(offset int) []byte {
	if offset >= len(e.mmdbData) {
		return nil
	}
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
//
// mmdbLoaded is written under e.mu.Lock() by LoadMMDB; reading it
// outside the lock raced with a concurrent reload and produced a
// data race (and could observe mmdbLoaded=true while mmdbData was
// still mid-swap). Snapshot mmdbLoaded together with the rule
// count under the same RLock.
func (e *Engine) Stats() Stats {
	e.mu.RLock()
	ruleCount := len(e.rules)
	mmdbLoaded := e.mmdbLoaded
	e.mu.RUnlock()

	return Stats{
		Enabled:    e.enabled,
		Rules:      ruleCount,
		MMDBLoaded: mmdbLoaded,
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
