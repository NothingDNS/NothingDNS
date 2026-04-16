package zone

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// maxIncludeDepth is the maximum nesting depth for $INCLUDE directives
// to prevent infinite recursion from circular includes.
const maxIncludeDepth = 10

// maxGenerateRecords is the maximum number of records $GENERATE can produce
// to prevent memory exhaustion from maliciously large ranges.
const maxGenerateRecords = 65536

// RecordChange represents a single record addition or deletion
// Used for IXFR (Incremental Zone Transfer) journaling
type RecordChange struct {
	Name  string
	Type  uint16 // protocol.TypeA, protocol.TypeAAAA, etc.
	TTL   uint32
	RData string
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

	// ZONEMD is the zone message digest for integrity verification (RFC 8976).
	// Computed on zone load if ZONEMD is enabled in config.
	ZONEMD *ZONEMD

	// mu protects Records, SOA, NS, and ZONEMD from concurrent access.
	mu sync.RWMutex
}

// Record represents a single DNS resource record in a zone.
type Record struct {
	Name  string // Domain name (relative or absolute)
	TTL   uint32 // Time to live in seconds
	Class string // Usually "IN" for Internet
	Type  string // Record type (A, AAAA, CNAME, etc.)
	RData string // Record data (type-specific)
	Line  int    // Line number in source file (for error reporting)
}

// SOARecord represents a Start of Authority record.
type SOARecord struct {
	Name    string // Zone name
	TTL     uint32
	MName   string // Primary name server
	RName   string // Responsible person's email
	Serial  uint32 // Zone serial number
	Refresh uint32 // Refresh interval
	Retry   uint32 // Retry interval
	Expire  uint32 // Expire interval
	Minimum uint32 // Minimum TTL (negative caching)
}

// NSRecord represents an NS record.
type NSRecord struct {
	Name    string // Domain name
	TTL     uint32
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
	Name  string
	TTL   uint32
	CName string // Canonical name
}

// MXRecord represents an MX record.
type MXRecord struct {
	Name       string
	TTL        uint32
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
	Name     string
	TTL      uint32
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

// Lock acquires the the zone's write lock.
func (z *Zone) Lock() {
	z.mu.Lock()
}

// Unlock releases the zone's write lock.
func (z *Zone) Unlock() {
	z.mu.Unlock()
}

// RLock acquires the the zone's read lock.
func (z *Zone) RLock() {
	z.mu.RLock()
}

// RUnlock releases the zone's read lock.
func (z *Zone) RUnlock() {
	z.mu.RUnlock()
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
	filename     string
	scanner      *bufio.Scanner
	lineNum      int
	zone         *Zone
	lastOwner    string // Last seen owner name (for continuation lines)
	parenDepth   int    // Parenthesis nesting depth for multi-line records
	lineBuf      string // Accumulated line content across parenthesized spans
	lineStart    int    // Line number where the current multi-line record started
	includeDepth int    // Current $INCLUDE nesting depth (0 = top-level file)
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

	case "$GENERATE":
		return p.handleGenerate(fields[1:])

	case "$INCLUDE":
		return p.handleInclude(fields[1:])

	default:
		return fmt.Errorf("unknown control directive: %s", directive)
	}

	return nil
}

// handleInclude processes the $INCLUDE directive per RFC 1035.
// Syntax: $INCLUDE filename [origin]
//
// The named file is read and parsed at the current point in the zone.
// If an optional origin is given, it temporarily overrides $ORIGIN for
// the scope of the included file only. After parsing completes, the
// original origin is restored.
//
// Nested includes are allowed up to maxIncludeDepth to prevent infinite
// recursion from circular references.
func (p *parser) handleInclude(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("$INCLUDE requires a filename")
	}

	if p.includeDepth >= maxIncludeDepth {
		return fmt.Errorf("$INCLUDE depth limit exceeded (max %d)", maxIncludeDepth)
	}

	includeFile := args[0]

	// SECURITY: Check for path traversal in the include path itself
	// Block obvious traversal attempts before any path resolution
	if strings.Contains(includeFile, "..") {
		return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
	}

	// SECURITY: Absolute paths are rejected unconditionally. The previous
	// implementation skipped the zone-directory confinement check when
	// filepath.IsAbs(args[0]) was true, so `$INCLUDE /etc/shadow` reached
	// os.Open. Zone authors must use paths relative to the parent zone file.
	if filepath.IsAbs(includeFile) {
		return fmt.Errorf("$INCLUDE absolute path not allowed: %s", includeFile)
	}

	// Resolve relative to the directory of the current file
	if p.filename != "" {
		includeFile = filepath.Join(filepath.Dir(p.filename), includeFile)
	}

	// Validate the resolved path stays within the zone directory.
	cleanPath := filepath.Clean(includeFile)
	if p.filename != "" {
		zoneDir := filepath.Dir(p.filename)
		rel, err := filepath.Rel(zoneDir, cleanPath)
		if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
			return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
		}
	}

	// Save current origin so we can restore it after the include
	savedOrigin := p.zone.Origin

	// Check for symlinks to prevent path disclosure
	info, err := os.Lstat(includeFile)
	if err != nil {
		p.zone.Origin = savedOrigin
		return fmt.Errorf("$INCLUDE %s: %w", includeFile, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		p.zone.Origin = savedOrigin
		return fmt.Errorf("$INCLUDE %s: symlinks are not allowed", includeFile)
	}

	// If an origin override was specified, apply it for the included file
	if len(args) >= 2 {
		p.zone.Origin = canonicalize(args[1])
	}

	f, err := os.Open(includeFile)
	if err != nil {
		// Restore origin before returning error
		p.zone.Origin = savedOrigin
		return fmt.Errorf("$INCLUDE %s: %w", includeFile, err)
	}
	defer f.Close()

	// Create a child parser that shares the same zone and inherits state
	child := &parser{
		filename:     includeFile,
		scanner:      bufio.NewScanner(f),
		zone:         p.zone,
		lastOwner:    p.lastOwner,
		includeDepth: p.includeDepth + 1,
	}

	if _, err := child.parse(); err != nil {
		p.zone.Origin = savedOrigin
		return err
	}

	// Restore the origin after the included file has been parsed
	p.zone.Origin = savedOrigin

	return nil
}

// handleGenerate processes the $GENERATE directive (BIND-compatible).
// Syntax: $GENERATE <start>-<stop>[/<step>] <lhs> [ttl] [class] <type> <rhs>
// The '$' character in lhs and rhs is replaced by the current iteration value.
// Modifiers: ${<offset>,<width>,<radix>} where offset is added to the iterator,
// width is zero-padded field width, and radix is d (decimal), o (octal), or x (hex).
func (p *parser) handleGenerate(args []string) error {
	if len(args) < 4 {
		return fmt.Errorf("$GENERATE requires at least: range lhs type rhs")
	}

	// Parse range: start-stop or start-stop/step
	start, stop, step, err := parseGenerateRange(args[0])
	if err != nil {
		return fmt.Errorf("$GENERATE range: %w", err)
	}

	// Check iteration count against limit to prevent memory exhaustion
	// count = number of records = ((stop - start) / step) + 1
	if step > 0 {
		count := (stop-start)/step + 1
		if count < 0 || count > maxGenerateRecords {
			return fmt.Errorf("$GENERATE range too large: %d records (max %d)", count, maxGenerateRecords)
		}
	}

	// Remaining args form a record template: lhs [ttl] [class] type rhs
	template := strings.Join(args[1:], " ")

	for i := start; i <= stop; i += step {
		expanded := expandGenerate(template, i)
		if err := p.parseRecord(expanded); err != nil {
			return fmt.Errorf("$GENERATE at iteration %d: %w", i, err)
		}
	}

	return nil
}

// parseGenerateRange parses "start-stop" or "start-stop/step".
func parseGenerateRange(s string) (start, stop, step int, err error) {
	step = 1

	// Check for step
	slashIdx := strings.IndexByte(s, '/')
	if slashIdx >= 0 {
		stepVal, parseErr := strconv.Atoi(s[slashIdx+1:])
		if parseErr != nil {
			return 0, 0, 0, fmt.Errorf("invalid step %q: %w", s[slashIdx+1:], parseErr)
		}
		if stepVal <= 0 {
			return 0, 0, 0, fmt.Errorf("step must be positive, got %d", stepVal)
		}
		step = stepVal
		s = s[:slashIdx]
	}

	// Parse start-stop
	dashIdx := strings.IndexByte(s, '-')
	if dashIdx < 0 {
		return 0, 0, 0, fmt.Errorf("range must be start-stop, got %q", s)
	}

	start, err = strconv.Atoi(s[:dashIdx])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid start %q: %w", s[:dashIdx], err)
	}

	stop, err = strconv.Atoi(s[dashIdx+1:])
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid stop %q: %w", s[dashIdx+1:], err)
	}

	if start > stop {
		return 0, 0, 0, fmt.Errorf("start (%d) must not exceed stop (%d)", start, stop)
	}

	return start, stop, step, nil
}

// expandGenerate replaces '$' tokens in a template with the iteration value.
// Supports bare '$' and the ${offset,width,radix} modifier syntax.
func expandGenerate(template string, iter int) string {
	var b strings.Builder
	b.Grow(len(template))

	for i := 0; i < len(template); i++ {
		if template[i] != '$' {
			b.WriteByte(template[i])
			continue
		}

		// Check for ${offset,width,radix} modifier
		if i+1 < len(template) && template[i+1] == '{' {
			end := strings.IndexByte(template[i+2:], '}')
			if end >= 0 {
				modifier := template[i+2 : i+2+end]
				b.WriteString(applyGenerateModifier(iter, modifier))
				i = i + 2 + end // skip past '}'
				continue
			}
		}

		// Bare '$' — replace with decimal value
		b.WriteString(strconv.Itoa(iter))
	}

	return b.String()
}

// applyGenerateModifier handles ${offset,width,radix} syntax.
// offset: integer added to the iterator value
// width: minimum field width (zero-padded)
// radix: d=decimal, o=octal, x=hex (default: d)
func applyGenerateModifier(iter int, modifier string) string {
	parts := strings.SplitN(modifier, ",", 3)

	offset := 0
	width := 0
	radix := "d"

	if len(parts) >= 1 && parts[0] != "" {
		if v, err := strconv.Atoi(parts[0]); err == nil {
			offset = v
		}
	}
	if len(parts) >= 2 && parts[1] != "" {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			width = v
		}
	}
	if len(parts) >= 3 && parts[2] != "" {
		radix = strings.ToLower(parts[2])
	}

	val := iter + offset

	var format string
	switch radix {
	case "o":
		format = fmt.Sprintf("%%0%do", width)
	case "x":
		format = fmt.Sprintf("%%0%dx", width)
	default:
		format = fmt.Sprintf("%%0%dd", width)
	}

	return fmt.Sprintf(format, val)
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
var recordTypes = map[string]bool{
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

func isType(field string) bool {
	return recordTypes[strings.ToUpper(field)]
}

var recordClasses = map[string]bool{
	"IN": true, "CS": true, "CH": true, "HS": true,
}

// isClass checks if a field is a valid class.
func isClass(field string) bool {
	return recordClasses[strings.ToUpper(field)]
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

	// Check for overflow: val * multiplier could exceed uint32 max
	maxVal := uint64(1<<32 - 1)
	if val > 0 && multiplier > 0 && val > maxVal/uint64(multiplier) {
		return 0, fmt.Errorf("TTL overflow: %d * %d exceeds uint32 max", val, multiplier)
	}

	return uint32(val) * multiplier, nil
}

// Lookup finds records for a given name and type.
func (z *Zone) Lookup(name, rrtype string) []Record {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.lookupLocked(name, rrtype)
}

// lookupLocked is the lock-free internal lookup.
func (z *Zone) lookupLocked(name, rrtype string) []Record {
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
	z.mu.RLock()
	defer z.mu.RUnlock()
	name = strings.ToLower(canonicalize(name))
	return z.Records[name]
}

// NameExists returns true if the given name has any records in the zone.
// This is needed for wildcard matching — a name that exists but has no
// records of the requested type is NODATA, not a wildcard match.
func (z *Zone) NameExists(name string) bool {
	z.mu.RLock()
	defer z.mu.RUnlock()
	name = strings.ToLower(canonicalize(name))
	return len(z.Records[name]) > 0
}

// LookupWildcard performs RFC 4592 wildcard matching for a query name.
// It is called only after an exact match has failed and the name does not
// exist in the zone (not a NODATA situation).
//
// Algorithm:
//  1. Starting from the query name, strip one label at a time from the left
//     to find the "closest encloser" — the longest ancestor that exists.
//  2. Check if *.closestEncloser exists in the zone.
//  3. If it does, return matching records with the wildcard owner name.
//
// Returns the matching records, the wildcard name used, and whether a match
// was found. The caller must rewrite the owner name to the original query name.
func (z *Zone) LookupWildcard(name, rrtype string) (records []Record, wildcardName string, found bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	name = strings.ToLower(canonicalize(name))
	rrtype = strings.ToUpper(rrtype)
	origin := strings.ToLower(z.Origin)

	// The query name must be within this zone
	if !strings.HasSuffix(name, origin) && name != origin {
		return nil, "", false
	}

	// Strip labels from the left to find the closest encloser
	current := name
	for {
		// Don't go above the zone origin
		if current == origin || current == "." {
			break
		}

		// Strip the leftmost label
		dot := strings.IndexByte(current, '.')
		if dot < 0 || dot+1 >= len(current) {
			break
		}
		parent := current[dot+1:]

		// Check if a wildcard exists at this parent: *.parent
		wildcard := "*." + parent
		if recs, ok := z.Records[wildcard]; ok && len(recs) > 0 {
			// Found a wildcard — filter by requested type
			if rrtype == "" || rrtype == "ANY" {
				return recs, wildcard, true
			}
			var matched []Record
			for _, r := range recs {
				if strings.ToUpper(r.Type) == rrtype {
					matched = append(matched, r)
				}
			}
			// Even if no records match the type, the wildcard name exists,
			// so this is a wildcard NODATA (not NXDOMAIN). Return found=true.
			return matched, wildcard, true
		}

		current = parent
	}

	return nil, "", false
}

// FindDelegation checks if the query name crosses a delegation point
// (zone cut) within this zone. A delegation exists when an intermediate
// name between the zone apex and the query name has NS records.
//
// Per RFC 1034 §4.2.1, the zone apex NS records are NOT a delegation —
// they describe the zone's own nameservers.
//
// Returns the NS records at the delegation point, the delegation name,
// and whether a delegation was found.
func (z *Zone) FindDelegation(name string) (nsRecords []Record, delegationPoint string, found bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	name = strings.ToLower(canonicalize(name))
	origin := strings.ToLower(z.Origin)

	// Query name must be within this zone
	if !strings.HasSuffix(name, origin) && name != origin {
		return nil, "", false
	}

	// If the query is exactly the origin, no delegation is possible
	if name == origin {
		return nil, "", false
	}

	// Build the list of intermediate names from origin toward query name.
	// For example: query=a.b.example.com., origin=example.com.
	// intermediates = [b.example.com.]  (skip origin itself and query name)
	//
	// We walk from the query name upward to find names between it and the origin.
	var intermediates []string
	current := name
	for {
		dot := strings.IndexByte(current, '.')
		if dot < 0 || dot+1 >= len(current) {
			break
		}
		parent := current[dot+1:]
		if parent == origin {
			// current is one label beyond origin — this IS an intermediate
			intermediates = append(intermediates, current)
			break
		}
		intermediates = append(intermediates, current)
		current = parent
	}

	// Check intermediates from closest-to-origin first (most specific delegation wins).
	// Walk in reverse since intermediates are built from query toward origin.
	for i := len(intermediates) - 1; i >= 0; i-- {
		candidate := intermediates[i]
		// Skip the query name itself if it's the only intermediate
		if candidate == name {
			continue
		}
		for _, rec := range z.Records[candidate] {
			if strings.ToUpper(rec.Type) == "NS" {
				// Found a delegation point — collect all NS records
				var ns []Record
				for _, r := range z.Records[candidate] {
					if strings.ToUpper(r.Type) == "NS" {
						ns = append(ns, r)
					}
				}
				return ns, candidate, true
			}
		}
	}

	return nil, "", false
}

// FindDNAME searches for a DNAME record whose owner is a suffix of the given name.
// Per RFC 6672, a DNAME record at a superdomain synthesizes a CNAME for any
// subdomain beneath it.
//
// For example, with zone "example.com." and DNAME "example.com. DNAME bar.example.net.":
//   - Query "foo.example.com." matches the DNAME (owner "example.com." is a suffix)
//   - Synthesized CNAME target = "foo.bar.example.net."
//     (replace suffix "example.com." with "bar.example.net.")
//
// Returns the DNAME record, the synthesized CNAME target name, and whether found.
func (z *Zone) FindDNAME(name string) (dnameRecord Record, synthCNAMETarget string, found bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()

	name = strings.ToLower(canonicalize(name))
	origin := strings.ToLower(z.Origin)

	// Name must be within this zone
	if !strings.HasSuffix(name, origin) && name != origin {
		return Record{}, "", false
	}

	// Build intermediates: from query name toward origin (excluding origin itself).
	var intermediates []string
	current := name
	for {
		dot := strings.IndexByte(current, '.')
		if dot < 0 || dot+1 >= len(current) {
			break
		}
		parent := current[dot+1:]
		if parent == origin {
			break
		}
		intermediates = append(intermediates, current)
		current = parent
	}

	// Check from closest-to-origin (least specific) to most specific DNAME.
	// RFC 6672: if multiple DNAME records could apply, the most specific wins.
	// Walk intermediates in reverse: [a.b.c, a.b, a] → [a, b, a.b, a.b.c]
	for i := len(intermediates) - 1; i >= 0; i-- {
		candidate := intermediates[i]
		for _, rec := range z.Records[candidate] {
			if strings.ToUpper(rec.Type) == "DNAME" {
				// Synthesize CNAME target: replace DNAME owner suffix with target
				dnameOwner := canonicalize(rec.Name)
				synthTarget := strings.TrimSuffix(name, dnameOwner) + rec.RData
				return rec, synthTarget, true
			}
		}
	}

	return Record{}, "", false
}

// FindGlue returns A and AAAA records for the given nameserver name
// if they exist within this zone (glue records).
func (z *Zone) FindGlue(nsName string) []Record {
	z.mu.RLock()
	defer z.mu.RUnlock()

	nsName = strings.ToLower(canonicalize(nsName))
	var glue []Record
	for _, rec := range z.Records[nsName] {
		t := strings.ToUpper(rec.Type)
		if t == "A" || t == "AAAA" {
			glue = append(glue, rec)
		}
	}
	return glue
}

// Validate checks the zone for required records and consistency.
func (z *Zone) Validate() error {
	if z.Origin == "" || z.Origin == "." {
		return fmt.Errorf("zone %q: has no origin", z.Origin)
	}

	if z.SOA == nil {
		return fmt.Errorf("zone %q: missing SOA record", z.Origin)
	}

	if len(z.NS) == 0 {
		return fmt.Errorf("zone %q: missing NS records", z.Origin)
	}

	return nil
}
