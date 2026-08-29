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

	// entNames is the set of empty non-terminals: names that exist in this
	// zone as DNS nodes because they have descendants, but own no records of
	// their own (RFC 4592 §2.2.2). Derived from Records; see ensureENTIndex.
	entNames map[string]struct{}

	// entBuiltFor is len(Records) at the time entNames was built. Records is
	// an exported field that transfer/DDNS code mutates directly, so the set
	// is revalidated against the owner count rather than trusted forever.
	entBuiltFor int

	// mu protects Records, SOA, NS, ZONEMD, and the ENT index from
	// concurrent access.
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

func nameInZone(name, origin string) bool {
	name = strings.ToLower(canonicalize(name))
	origin = strings.ToLower(canonicalize(origin))
	if origin == "." {
		return true
	}
	return name == origin || strings.HasSuffix(name, "."+origin)
}

// makeAbsolute converts a potentially relative name to absolute using the origin.
func makeAbsolute(name, origin string) string {
	name = strings.TrimSpace(name)
	origin = canonicalize(origin)
	if name == "" || name == "@" {
		return origin
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	if origin == "." {
		return name + "."
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
	filename       string
	scanner        *bufio.Scanner
	lineNum        int
	zone           *Zone
	lastOwner      string // Last seen owner name (for continuation lines)
	parenDepth     int    // Parenthesis nesting depth for multi-line records
	lineBuf        string // Accumulated line content across parenthesized spans
	lineStart      int    // Line number where the current multi-line record started
	recordIndented bool   // Whether the current multi-line record's opening line was indented (owner inherited)
	includeDepth   int    // Current $INCLUDE nesting depth (0 = top-level file)
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
				// Multi-line record complete — parse the joined line. Owner
				// inheritance is decided by the record's *opening* line
				// (captured in p.recordIndented), not by this closing-paren
				// line which is usually indented.
				p.parenDepth = 0
				combined := p.lineBuf
				p.lineBuf = ""
				combined = strings.ReplaceAll(combined, "(", " ")
				combined = strings.ReplaceAll(combined, ")", " ")
				combined = strings.Join(strings.Fields(combined), " ")
				if err := p.parseRecordOwned(combined, p.recordIndented); err != nil {
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
			// Start accumulating a multi-line record. Capture whether the
			// opening line was indented (owner inherited) now, before the
			// scanner advances to the continuation/closing lines.
			p.parenDepth = 1
			p.lineStart = p.lineNum
			p.recordIndented = len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t')
			// Strip comments from first line
			if idx := strings.Index(line, ";"); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
			p.lineBuf = line
			continue
		}

		// Parse resource record. Owner inheritance is decided by this line's
		// own leading whitespace (rawLine still holds it here).
		ownerInherited := len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t')
		if err := p.parseRecordOwned(line, ownerInherited); err != nil {
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

	// SECURITY: Absolute paths are rejected unconditionally. The previous
	// implementation skipped the zone-directory confinement check when
	// filepath.IsAbs(args[0]) was true, so `$INCLUDE /etc/shadow` reached
	// os.Open. Zone authors must use paths relative to the parent zone file.
	if filepath.IsAbs(includeFile) {
		return fmt.Errorf("$INCLUDE absolute path not allowed: %s", includeFile)
	}

	// SECURITY: Validate the include path is local (no traversal).
	// filepath.IsLocal replaces the weaker strings.Contains("..") blacklist (LOW-007).
	if !filepath.IsLocal(includeFile) {
		return fmt.Errorf("$INCLUDE path traversal attempt blocked: %s", includeFile)
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
		expanded, err := expandGenerate(template, i)
		if err != nil {
			return fmt.Errorf("$GENERATE at iteration %d: %w", i, err)
		}
		// $GENERATE templates always carry an explicit owner (the lhs), so the
		// owner is never inherited.
		if err := p.parseRecordOwned(expanded, false); err != nil {
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
func expandGenerate(template string, iter int) (string, error) {
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
				value, err := applyGenerateModifier(iter, modifier)
				if err != nil {
					return "", err
				}
				b.WriteString(value)
				i = i + 2 + end // skip past '}'
				continue
			}
		}

		// Bare '$' — replace with decimal value
		b.WriteString(strconv.Itoa(iter))
	}

	return b.String(), nil
}

// applyGenerateModifier handles ${offset,width,radix} syntax.
// offset: integer added to the iterator value
// width: minimum field width (zero-padded)
// radix: d=decimal, o=octal, x=hex (default: d)
func applyGenerateModifier(iter int, modifier string) (string, error) {
	parts := strings.SplitN(modifier, ",", 3)

	offset := 0
	width := 0
	radix := "d"

	if len(parts) >= 1 && parts[0] != "" {
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return "", fmt.Errorf("invalid $GENERATE offset %q: %w", parts[0], err)
		}
		offset = v
	}
	if len(parts) >= 2 && parts[1] != "" {
		v, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", fmt.Errorf("invalid $GENERATE width %q: %w", parts[1], err)
		}
		if v < 0 {
			return "", fmt.Errorf("invalid $GENERATE width %d", v)
		}
		width = v
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
	case "d":
		format = fmt.Sprintf("%%0%dd", width)
	default:
		return "", fmt.Errorf("invalid $GENERATE radix %q", radix)
	}

	return fmt.Sprintf(format, val), nil
}

// stripZoneComment strips a BIND-style ';' comment from line, ignoring
// semicolons that appear inside double-quoted strings or after a backslash
// escape. Per RFC 1035 §5.1, TXT/character-string RDATA can legitimately
// contain semicolons inside quotes.
func stripZoneComment(line string) string {
	inQuote := false
	escape := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' {
			escape = true
			continue
		}
		if c == '"' {
			inQuote = !inQuote
			continue
		}
		if c == ';' && !inQuote {
			return line[:i]
		}
	}
	return line
}

// parseRecord parses a single resource record line, inferring owner-name
// inheritance from the current scanner line's leading whitespace. This wrapper
// preserves the historical signature for direct callers (tests). Production
// callers in the main parse loop use parseRecordOwned with an explicit
// inheritance flag, because for a parenthesized multi-line record the scanner
// is parked on the (usually indented) closing-paren line, not the record's
// opening line — reading scanner.Text() there would wrongly treat the whole
// record as a continuation and file it under the previous owner (breaking
// multi-line TXT/DKIM/SPF/DNSKEY/RRSIG records).
func (p *parser) parseRecord(line string) error {
	rawLine := p.scanner.Text()
	ownerInherited := len(rawLine) > 0 && (rawLine[0] == ' ' || rawLine[0] == '\t')
	return p.parseRecordOwned(line, ownerInherited)
}

// parseRecordOwned parses a single resource record line. ownerInherited is true
// when the record's opening line began with whitespace (RFC 1035 §5.1), meaning
// the owner name is inherited from the previous record rather than present on
// the line.
func (p *parser) parseRecordOwned(line string, ownerInherited bool) error {
	// Remove comments. A naive strings.Index(";") truncates RDATA inside
	// quoted strings (e.g. TXT records containing literal semicolons), so we
	// scan the line ourselves and ignore ';' that appears inside "..." or
	// after a backslash escape.
	line = stripZoneComment(line)

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

	// First field: owner name. RFC 1035 §5.1 says a line whose first
	// character is whitespace inherits the previous record's owner name.
	// ownerInherited is computed by the caller from the record's *opening*
	// line (not the scanner's current line, which for a multi-line record is
	// the closing-paren line).
	if !ownerInherited {
		// Line starts with owner name
		record.Name = fields[fieldIdx]
		fieldIdx++
		p.lastOwner = record.Name
	} else {
		// Continuation line - use last owner
		record.Name = p.lastOwner
	}

	// Look for TTL, Class, and Type in the next fields
	ttlSet := false
	for fieldIdx < len(fields) && !isType(fields[fieldIdx]) {
		field := fields[fieldIdx]

		// Check if it's a TTL
		if ttl, err := parseTTL(field); err == nil {
			record.TTL = ttl
			ttlSet = true
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

	// Use the zone default TTL only when no TTL field was present on the record.
	// An explicit TTL of 0 (RFC 2181 §8 — "do not cache") is a deliberate value
	// and must be preserved, not silently replaced by $TTL.
	if !ttlSet {
		record.TTL = p.zone.DefaultTTL
	}

	// Make name absolute and lowercase
	absName := strings.ToLower(makeAbsolute(record.Name, p.zone.Origin))

	// Keep Record.Name in step with the map key. Leaving the file's relative
	// owner ("ns1.sub") on the record while keying the map by the absolute
	// name broke every consumer that reads Record.Name instead of the key —
	// most visibly delegation glue, whose owner name then failed to match the
	// NS target and was dropped from the referral, leaving the child zone
	// unreachable.
	record.Name = absName

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
	escaped := false
	inlineQuote := false

	for _, r := range line {
		if inQuotes && escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		switch r {
		case '\\':
			if inQuotes {
				escaped = true
			} else {
				current.WriteRune(r)
			}
		case '"':
			if inQuotes {
				// End of quoted string
				if !inlineQuote {
					fields = append(fields, current.String())
					current.Reset()
				}
				inQuotes = false
				inlineQuote = false
			} else {
				// Start of quoted string
				if current.Len() > 0 {
					if strings.HasSuffix(current.String(), "=") {
						inlineQuote = true
					} else {
						fields = append(fields, current.String())
						current.Reset()
					}
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
			// Ignore parentheses ONLY when they appear as zone-file
			// line-continuation markers, i.e. outside a quoted string.
			// A TXT record like `"v=spf1 include:(_spf.example) ~all"`
			// previously had the parens stripped — and worse, the `(`
			// flushed the in-progress quoted field early, yielding
			// "v=spf1 include:" followed by orphan tokens for "_spf...
			// ~all" outside any field. With this guard the parens stay
			// inside the quoted run as literal characters.
			if inQuotes {
				current.WriteRune(r)
				continue
			}
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		case ')':
			// End of multi-line record — same in-quotes guard.
			if inQuotes {
				current.WriteRune(r)
			}
		default:
			current.WriteRune(r)
		}
	}
	if escaped {
		current.WriteRune('\\')
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
	"DNSKEY": true, "DS": true, "CDNSKEY": true, "CDS": true, "NSEC": true, "RRSIG": true,
	"TLSA": true, "SSHFP": true, "SPF": true, "DKIM": true,
	"AFSDB": true, "APL": true, "CERT": true, "DHCID": true,
	"DNAME": true, "HINFO": true, "HIP": true, "IPSECKEY": true,
	"KEY": true, "KX": true, "LOC": true, "NAPTR": true,
	"NSEC3": true, "NSEC3PARAM": true, "OPENPGPKEY": true,
	"RP": true, "SIG": true, "TA": true,
	"SVCB": true, "HTTPS": true, "URI": true, "ZONEMD": true,
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
		if recordTypeMatches(record.Type, rrtype) {
			results = append(results, record)
		}
	}
	return results
}

func recordTypeMatches(recordType, queryType string) bool {
	recordType = strings.ToUpper(recordType)
	queryType = strings.ToUpper(queryType)
	// QTYPE=ANY (RFC 1035 §3.2.3) requests every type at the name, so it
	// matches any record. Without this, an exact-name ANY query matched
	// nothing and the handler answered NODATA — telling the client the name
	// holds no data at all, and inviting it to cache that for the SOA
	// minimum, even though the name is fully populated. LookupWildcard
	// already special-cased ANY, so the wildcard and exact-match paths
	// disagreed on the same query.
	if queryType == "ANY" {
		return true
	}
	return recordType == queryType || (recordType == "DKIM" && queryType == "TXT")
}

// LookupAll finds all records for a given name.
func (z *Zone) LookupAll(name string) []Record {
	z.mu.RLock()
	defer z.mu.RUnlock()
	name = strings.ToLower(canonicalize(name))
	return cloneRecords(z.Records[name])
}

// GetDefaultTTL returns the zone's default TTL. Thread-safe.
func (z *Zone) GetDefaultTTL() uint32 {
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.DefaultTTL
}

// GetOrigin returns the zone's origin name. Thread-safe (Origin is set
// at construction and never mutated, but the method exists so callers
// don't reach into the struct field directly).
func (z *Zone) GetOrigin() string {
	return z.Origin
}

// RecordsByType returns all records matching the given type (case-insensitive).
// The returned slice is a copy and safe to use without holding the zone lock.
func (z *Zone) RecordsByType(rrtype string) []Record {
	z.mu.RLock()
	defer z.mu.RUnlock()
	rrtype = strings.ToUpper(rrtype)
	var results []Record
	for _, ownerRecords := range z.Records {
		for _, rec := range ownerRecords {
			if strings.ToUpper(rec.Type) == rrtype {
				results = append(results, rec)
			}
		}
	}
	return results
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

// NodeExists reports whether name exists in this zone as a DNS node — either
// because it owns records, or because it is an empty non-terminal: a name
// with descendants but no records of its own (RFC 4592 §2.2.2).
//
// This is the existence test the negative-answer path needs, and NameExists is
// not it. Answering NXDOMAIN for an empty non-terminal claims that nothing at
// or below the name exists, which is false — and RFC 8020 resolvers take that
// claim literally, so a cached NXDOMAIN for "b.example.com" makes them refuse
// "a.b.example.com" too. A zone could make its own populated names
// unresolvable that way. The correct answer for an empty non-terminal is
// NODATA.
func (z *Zone) NodeExists(name string) bool {
	z.ensureENTIndex()
	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.nodeExistsLocked(name)
}

// nodeExistsLocked is NodeExists without locking or index refresh. Callers
// must hold at least the read lock and must have called ensureENTIndex first.
func (z *Zone) nodeExistsLocked(name string) bool {
	name = strings.ToLower(canonicalize(name))
	if len(z.Records[name]) > 0 {
		return true
	}
	// The apex exists by definition — it is the zone cut this zone is named
	// for. A well-formed zone always carries an SOA there so the Records
	// lookup above would find it, but the closest-encloser search must not
	// depend on that: terminating it at the apex is what bounds the walk.
	if name == strings.ToLower(canonicalize(z.Origin)) {
		return true
	}
	_, ok := z.entNames[name]
	return ok
}

// ensureENTIndex rebuilds the empty-non-terminal set when it is missing or
// stale. Called before taking the read lock, never while holding it.
func (z *Zone) ensureENTIndex() {
	z.mu.RLock()
	fresh := z.entNames != nil && z.entBuiltFor == len(z.Records)
	z.mu.RUnlock()
	if fresh {
		return
	}

	z.mu.Lock()
	defer z.mu.Unlock()
	if z.entNames == nil || z.entBuiltFor != len(z.Records) {
		z.rebuildENTIndexLocked()
	}
}

// rebuildENTIndexLocked recomputes entNames. Must hold the write lock.
//
// Every owner name contributes its ancestors up to (not including) the origin;
// an ancestor that owns records is not an empty non-terminal and is left out,
// since nodeExistsLocked finds it in Records directly.
func (z *Zone) rebuildENTIndexLocked() {
	origin := strings.ToLower(canonicalize(z.Origin))
	ents := make(map[string]struct{})

	for owner := range z.Records {
		name := owner
		for {
			dot := strings.IndexByte(name, '.')
			if dot < 0 || dot+1 >= len(name) {
				break
			}
			name = name[dot+1:]
			if name == origin || !nameInZone(name, origin) {
				break
			}
			if _, seen := ents[name]; seen {
				// This ancestor chain was already walked from another owner.
				break
			}
			if len(z.Records[name]) == 0 {
				ents[name] = struct{}{}
			}
		}
	}

	z.entNames = ents
	z.entBuiltFor = len(z.Records)
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
	z.ensureENTIndex() // needs the read lock; must run before we take it
	z.mu.RLock()
	defer z.mu.RUnlock()

	name = strings.ToLower(canonicalize(name))
	rrtype = strings.ToUpper(rrtype)
	origin := strings.ToLower(z.Origin)

	// The query name must be within this zone
	if !nameInZone(name, origin) {
		return nil, "", false
	}

	// Step 1: find the closest encloser — the longest ancestor of the query
	// name that exists as a node, counting empty non-terminals.
	//
	// The loop used to keep climbing past existing ancestors until it found
	// SOME "*.ancestor", which is not what RFC 4592 §2.2.1 defines. With
	// "*.wild.example." and "deep.sub.wild.example." both in the zone, a query
	// for "x.deep.sub.wild.example." was answered from "*.wild.example." even
	// though its closest encloser is "deep.sub.wild.example." — the zone
	// manufactured answers for names it does not cover, where the correct
	// reply is NXDOMAIN.
	closestEncloser := ""
	current := name
	for {
		if current == origin || current == "." {
			break
		}
		dot := strings.IndexByte(current, '.')
		if dot < 0 || dot+1 >= len(current) {
			break
		}
		parent := current[dot+1:]
		if !nameInZone(parent, origin) {
			break
		}
		if z.nodeExistsLocked(parent) {
			closestEncloser = parent
			break
		}
		current = parent
	}
	if closestEncloser == "" {
		return nil, "", false
	}

	// Step 2: the source of synthesis is the wildcard at the closest encloser,
	// and nowhere else (RFC 4592 §2.2.1).
	wildcard := "*." + closestEncloser
	recs, ok := z.Records[wildcard]
	if !ok || len(recs) == 0 {
		return nil, "", false
	}

	if rrtype == "" || rrtype == "ANY" {
		return cloneRecords(recs), wildcard, true
	}
	var matched []Record
	for _, r := range recs {
		if recordTypeMatches(r.Type, rrtype) {
			matched = append(matched, r)
		}
	}
	// Even if no records match the type, the wildcard name exists, so this is
	// a wildcard NODATA (not NXDOMAIN). Return found=true.
	return matched, wildcard, true
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
	if !nameInZone(name, origin) {
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
	if !nameInZone(name, origin) {
		return Record{}, "", false
	}

	// Walk parent names from most-specific to least-specific. A DNAME does
	// not synthesize for its owner name itself; it only applies below that
	// owner, so start at the query's immediate parent and include the origin.
	current := name
	for {
		dot := strings.IndexByte(current, '.')
		if dot < 0 || dot+1 >= len(current) {
			break
		}
		parent := current[dot+1:]
		for _, rec := range z.Records[parent] {
			if strings.ToUpper(rec.Type) == "DNAME" {
				// Synthesize CNAME target: replace DNAME owner suffix with target
				dnameOwner := parent
				synthTarget := strings.TrimSuffix(name, dnameOwner) + rec.RData
				rec.Name = parent
				return rec, synthTarget, true
			}
		}
		if parent == origin {
			break
		}
		current = parent
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
