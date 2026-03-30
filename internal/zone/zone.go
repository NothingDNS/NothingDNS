package zone

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// RecordChange represents a single record addition or deletion
// Used for IXFR (Incremental Zone Transfer) journaling
type RecordChange struct {
	Name   string
	Type   uint16 // protocol.TypeA, protocol.TypeAAAA, etc.
	TTL    uint32
	RData  string
}

// ZoneChange represents a set of changes made to a zone in one update
type ZoneChange struct {
	OldSerial uint32
	NewSerial uint32
	Added     []RecordChange
	Deleted   []RecordChange
}
type Zone struct {
	// Origin is the root domain name of the zone (e.g., "example.com.")
	Origin string

	// DefaultTTL is the default TTL for records without explicit TTL.
	DefaultTTL uint32

	// SOA is the Start of Authority record.
	SOA *SOARecord

	// Records stores all resource records by domain name.
	// Key is the fully qualified domain name.
	Records map[string][]Record

	// NS records for the zone apex.
	NS []NSRecord
}

// Record represents a single DNS resource record in a zone.
type Record struct {
	Name   string // Domain name (relative or absolute)
	TTL    uint32 // Time to live in seconds
	Class  string // Usually "IN" for Internet
	Type   string // Record type (A, AAAA, CNAME, etc.)
	RData  string // Record data (type-specific)
	Line   int    // Line number in source file (for error reporting)
}

// SOARecord represents a Start of Authority record.
type SOARecord struct {
	Name     string // Zone name
	TTL      uint32
	MName    string // Primary name server
	RName    string // Responsible person's email
	Serial   uint32 // Zone serial number
	Refresh  uint32 // Refresh interval
	Retry    uint32 // Retry interval
	Expire   uint32 // Expire interval
	Minimum  uint32 // Minimum TTL (negative caching)
}

// NSRecord represents an NS record.
type NSRecord struct {
	Name string // Domain name
	TTL  uint32
	NSDName string // Name server hostname
}

// ARecord represents an A record.
type ARecord struct {
	Name    string
	TTL     uint32
	Address net.IP
}

// AAAARecord represents an AAAA record.
type AAAARecord struct {
	Name    string
	TTL     uint32
	Address net.IP
}

// CNAMERecord represents a CNAME record.
type CNAMERecord struct {
	Name    string
	TTL     uint32
	CName   string // Canonical name
}

// MXRecord represents an MX record.
type MXRecord struct {
	Name     string
	TTL      uint32
	Preference uint16
	Exchange   string // Mail server hostname
}

// TXTRecord represents a TXT record.
type TXTRecord struct {
	Name string
	TTL  uint32
	Text string // TXT data (can contain multiple strings)
}

// PTRRecord represents a PTR record.
type PTRRecord struct {
	Name   string
	TTL    uint32
	PtrDName string // Domain name
}

// SRVRecord represents an SRV record.
type SRVRecord struct {
	Name     string
	TTL      uint32
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

// NewZone creates a new empty zone.
func NewZone(origin string) *Zone {
	return &Zone{
		Origin:  canonicalize(origin),
		Records: make(map[string][]Record),
	}
}

// canonicalize ensures a domain name ends with a dot.
func canonicalize(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// makeAbsolute converts a potentially relative name to absolute using the origin.
func makeAbsolute(name, origin string) string {
	name = strings.TrimSpace(name)
	if name == "" || name == "@" {
		return origin
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "." + origin
}

// ParseFile parses a zone file and returns a Zone.
func ParseFile(filename string, r io.Reader) (*Zone, error) {
	p := &parser{
		filename: filename,
		scanner:  bufio.NewScanner(r),
		lineNum:  0,
		zone: &Zone{
			Origin:  ".",
			Records: make(map[string][]Record),
		},
	}
	return p.parse()
}

// parser handles the parsing of zone files.
type parser struct {
	filename   string
	scanner    *bufio.Scanner
	lineNum    int
	zone       *Zone
	lastOwner  string // Last seen owner name (for continuation lines)
	parenDepth int    // Parenthesis nesting depth for multi-line records
	lineBuf    string // Accumulated line content across parenthesized spans
	lineStart  int    // Line number where the current multi-line record started
}

// parse performs the actual parsing.
func (p *parser) parse() (*Zone, error) {
	for p.scanner.Scan() {
		p.lineNum++
		rawLine := p.scanner.Text()
		line := strings.TrimSpace(rawLine)

		// If we're inside a parenthesized multi-line record, accumulate lines
		if p.parenDepth > 0 {
			// Strip comments from continuation line
			if idx := strings.Index(line, ";"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			if line == "" {
				continue
			}
			p.lineBuf += " " + line
			for _, ch := range line {
				if ch == '(' {
					p.parenDepth++
				} else if ch == ')' {
					p.parenDepth--
				}
			}
			if p.parenDepth <= 0 {
				// Multi-line record complete — parse the joined line
				p.parenDepth = 0
				combined := p.lineBuf
				p.lineBuf = ""
				combined = strings.ReplaceAll(combined, "(", " ")
				combined = strings.ReplaceAll(combined, ")", " ")
				combined = strings.Join(strings.Fields(combined), " ")
				if err := p.parseRecord(combined); err != nil {
					return nil, fmt.Errorf("%s:%d: %w", p.filename, p.lineStart, err)
				}
			}
			continue
		}

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Handle control entries ($ORIGIN, $TTL, $INCLUDE)
		if strings.HasPrefix(line, "$") {
			if err := p.handleControl(line); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", p.filename, p.lineNum, err)
			}
			continue
		}

		// Check if this line opens a multi-line record
		hasOpen := strings.Contains(line, "(")
		hasClose := strings.Contains(line, ")")
		if hasOpen && !hasClose {
			// Start accumulating a multi-line record
			p.parenDepth = 1
			p.lineStart = p.lineNum
			// Strip comments from first line
			if idx := strings.Index(line, ";"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			p.lineBuf = line
			continue
		}

		// Parse resource record
		if err := p.parseRecord(line); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", p.filename, p.lineNum, err)
		}
	}

	if err := p.scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: read error: %w", p.filename, err)
	}

	// Handle unclosed parenthesis
	if p.parenDepth > 0 {
		return nil, fmt.Errorf("%s:%d: unclosed parenthesis", p.filename, p.lineStart)
	}

	return p.zone, nil
}

// handleControl handles control entries like $ORIGIN, $TTL, $INCLUDE.
func (p *parser) handleControl(line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}

	directive := strings.ToUpper(fields[0])

	switch directive {
	case "$ORIGIN":
		if len(fields) < 2 {
			return fmt.Errorf("$ORIGIN requires a domain name")
		}
		p.zone.Origin = canonicalize(fields[1])

	case "$TTL":
		if len(fields) < 2 {
			return fmt.Errorf("$TTL requires a value")
		}
		ttl, err := parseTTL(fields[1])
		if err != nil {
			return fmt.Errorf("invalid $TTL: %w", err)
		}
		p.zone.DefaultTTL = ttl

	case "$INCLUDE":
		// $INCLUDE not supported in basic version
		return fmt.Errorf("$INCLUDE not supported")

	default:
		return fmt.Errorf("unknown control directive: %s", directive)
	}

	return nil
}

// parseRecord parses a single resource record line.
func (p *parser) parseRecord(line string) error {
	// Remove comments
	if idx := strings.Index(line, ";"); idx >= 0 {
		line = line[:idx]
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	// Split into fields
	fields := parseFields(line)
	if len(fields) < 2 {
		return fmt.Errorf("invalid record format")
	}

	// Parse owner name, TTL, class, type, and rdata
	record := Record{
		Line:  p.lineNum,
		Class: "IN", // Default class
	}

	fieldIdx := 0

	// First field: owner name (optional if it starts with whitespace)
	if !strings.HasPrefix(p.scanner.Text(), " \t") {
		// Line starts with owner name
		record.Name = fields[fieldIdx]
		fieldIdx++
		p.lastOwner = record.Name
	} else {
		// Continuation line - use last owner
		record.Name = p.lastOwner
	}

	// Look for TTL, Class, and Type in the next fields
	for fieldIdx < len(fields) && !isType(fields[fieldIdx]) {
		field := fields[fieldIdx]

		// Check if it's a TTL
		if ttl, err := parseTTL(field); err == nil {
			record.TTL = ttl
			fieldIdx++
			continue
		}

		// Check if it's a class
		if isClass(field) {
			record.Class = strings.ToUpper(field)
			fieldIdx++
			continue
		}

		// Unknown field
		fieldIdx++
	}

	// Next field should be the type
	if fieldIdx >= len(fields) {
		return fmt.Errorf("missing record type")
	}
	record.Type = strings.ToUpper(fields[fieldIdx])
	fieldIdx++

	// Remaining fields are RData
	if fieldIdx < len(fields) {
		record.RData = strings.Join(fields[fieldIdx:], " ")
	}

	// Use default TTL if not specified
	if record.TTL == 0 {
		record.TTL = p.zone.DefaultTTL
	}

	// Make name absolute and lowercase
	absName := strings.ToLower(makeAbsolute(record.Name, p.zone.Origin))

	// Store the record
	p.zone.Records[absName] = append(p.zone.Records[absName], record)

	// Handle special records
	if err := p.handleSpecialRecord(absName, record); err != nil {
		return err
	}

	return nil
}

// handleSpecialRecord handles SOA and NS records specially.
func (p *parser) handleSpecialRecord(name string, record Record) error {
	switch record.Type {
	case "SOA":
		if err := p.parseSOA(name, record); err != nil {
			return fmt.Errorf("parsing SOA: %w", err)
		}
	case "NS":
		ns := NSRecord{
			Name:    name,
			TTL:     record.TTL,
			NSDName: makeAbsolute(record.RData, p.zone.Origin),
		}
		p.zone.NS = append(p.zone.NS, ns)
	}
	return nil
}

// parseSOA parses an SOA record's RData.
func (p *parser) parseSOA(name string, record Record) error {
	// SOA format: mname rname serial refresh retry expire minimum
	// Example: ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 86400

	fields := parseFields(record.RData)
	if len(fields) < 7 {
		return fmt.Errorf("SOA record requires 7 fields, got %d", len(fields))
	}

	serial, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid serial: %w", err)
	}

	refresh, err := parseTTL(fields[3])
	if err != nil {
		return fmt.Errorf("invalid refresh: %w", err)
	}

	retry, err := parseTTL(fields[4])
	if err != nil {
		return fmt.Errorf("invalid retry: %w", err)
	}

	expire, err := parseTTL(fields[5])
	if err != nil {
		return fmt.Errorf("invalid expire: %w", err)
	}

	minimum, err := parseTTL(fields[6])
	if err != nil {
		return fmt.Errorf("invalid minimum: %w", err)
	}

	p.zone.SOA = &SOARecord{
		Name:    name,
		TTL:     record.TTL,
		MName:   makeAbsolute(fields[0], p.zone.Origin),
		RName:   makeAbsolute(fields[1], p.zone.Origin),
		Serial:  uint32(serial),
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minimum: minimum,
	}

	return nil
}

// parseFields splits a line into fields, handling quoted strings.
func parseFields(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch r {
		case '"':
			if inQuotes {
				// End of quoted string
				fields = append(fields, current.String())
				current.Reset()
				inQuotes = false
			} else {
				// Start of quoted string
				if current.Len() > 0 {
					fields = append(fields, current.String())
					current.Reset()
				}
				inQuotes = true
			}
		case ' ', '\t':
			if inQuotes {
				current.WriteRune(r)
			} else {
				if current.Len() > 0 {
					fields = append(fields, current.String())
					current.Reset()
				}
			}
		case '(':
			// Ignore parentheses (line continuation markers in zone files)
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		case ')':
			// End of multi-line record
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		fields = append(fields, current.String())
	}

	return fields
}

// isType checks if a field is a valid record type.
func isType(field string) bool {
	types := map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true, "NS": true,
		"PTR": true, "SOA": true, "SRV": true, "TXT": true, "CAA": true,
		"DNSKEY": true, "DS": true, "NSEC": true, "RRSIG": true,
		"TLSA": true, "SSHFP": true, "SPF": true, "DKIM": true,
		"AFSDB": true, "APL": true, "CERT": true, "DHCID": true,
		"DNAME": true, "HINFO": true, "HIP": true, "IPSECKEY": true,
		"KEY": true, "KX": true, "LOC": true, "NAPTR": true,
		"NSEC3": true, "NSEC3PARAM": true, "OPENPGPKEY": true,
		"RP": true, "SIG": true, "TA": true, "TKEY": true,
		"TSIG": true, "URI": true, "ZONEMD": true,
	}
	return types[strings.ToUpper(field)]
}

// isClass checks if a field is a valid class.
func isClass(field string) bool {
	classes := map[string]bool{
		"IN": true, "CS": true, "CH": true, "HS": true,
	}
	return classes[strings.ToUpper(field)]
}

// parseTTL parses a TTL value (integer or with suffix like 1h, 1d, 1w).
func parseTTL(s string) (uint32, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, fmt.Errorf("empty TTL")
	}

	// Check for suffix
	multiplier := uint32(1)
	if len(s) > 0 {
		switch s[len(s)-1] {
		case 'S':
			s = s[:len(s)-1]
		case 'M':
			multiplier = 60
			s = s[:len(s)-1]
		case 'H':
			multiplier = 3600
			s = s[:len(s)-1]
		case 'D':
			multiplier = 86400
			s = s[:len(s)-1]
		case 'W':
			multiplier = 604800
			s = s[:len(s)-1]
		}
	}

	val, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}

	return uint32(val) * multiplier, nil
}

// Lookup finds records for a given name and type.
func (z *Zone) Lookup(name, rrtype string) []Record {
	name = strings.ToLower(canonicalize(name))
	rrtype = strings.ToUpper(rrtype)

	var results []Record
	for _, record := range z.Records[name] {
		if strings.ToUpper(record.Type) == rrtype {
			results = append(results, record)
		}
	}
	return results
}

// LookupAll finds all records for a given name.
func (z *Zone) LookupAll(name string) []Record {
	name = strings.ToLower(canonicalize(name))
	return z.Records[name]
}

// Validate checks the zone for required records and consistency.
func (z *Zone) Validate() error {
	if z.Origin == "" || z.Origin == "." {
		return fmt.Errorf("zone has no origin")
	}

	if z.SOA == nil {
		return fmt.Errorf("zone missing SOA record")
	}

	if len(z.NS) == 0 {
		return fmt.Errorf("zone missing NS records")
	}

	return nil
}
