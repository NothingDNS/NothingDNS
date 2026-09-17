package zone

import (
	"fmt"
	"sort"
	"strings"
)

// WriteZone serializes a Zone to BIND format string.
func WriteZone(z *Zone) (string, error) {
	if z == nil {
		return "", fmt.Errorf("nil zone")
	}

	z.RLock()
	defer z.RUnlock()

	var b strings.Builder

	// $ORIGIN
	b.WriteString("$ORIGIN ")
	b.WriteString(z.Origin)
	b.WriteString("\n")

	// $TTL
	if z.DefaultTTL > 0 {
		b.WriteString(fmt.Sprintf("$TTL %d\n", z.DefaultTTL))
	}
	b.WriteString("\n")

	// SOA record
	if z.SOA != nil {
		ttl := z.SOA.TTL
		if ttl == 0 {
			ttl = z.DefaultTTL
		}
		b.WriteString(fmt.Sprintf("@\t%d\tIN\tSOA\t%s %s (\n", ttl, z.SOA.MName, z.SOA.RName))
		b.WriteString(fmt.Sprintf("\t\t%d\t; serial\n", z.SOA.Serial))
		b.WriteString(fmt.Sprintf("\t\t%d\t; refresh\n", z.SOA.Refresh))
		b.WriteString(fmt.Sprintf("\t\t%d\t; retry\n", z.SOA.Retry))
		b.WriteString(fmt.Sprintf("\t\t%d\t; expire\n", z.SOA.Expire))
		b.WriteString(fmt.Sprintf("\t\t%d\t; minimum\n", z.SOA.Minimum))
		b.WriteString("\t)\n\n")
	}

	// NS records at apex. Records is the source of truth: records added or
	// removed through the API never touch z.NS, and zones loaded from the KV
	// store have no z.NS at all, so exporting from z.NS dropped every NS.
	apexNS := 0
	for _, r := range z.Records[z.Origin] {
		if strings.ToUpper(r.Type) != "NS" {
			continue
		}
		ttl := r.TTL
		if ttl == 0 {
			ttl = z.DefaultTTL
		}
		b.WriteString(fmt.Sprintf("@\t%d\tIN\tNS\t%s\n", ttl, stripZoneControlChars(r.RData)))
		apexNS++
	}
	if apexNS == 0 {
		for _, ns := range z.NS {
			ttl := ns.TTL
			if ttl == 0 {
				ttl = z.DefaultTTL
			}
			b.WriteString(fmt.Sprintf("@\t%d\tIN\tNS\t%s\n", ttl, ns.NSDName))
			apexNS++
		}
	}
	if apexNS > 0 {
		b.WriteString("\n")
	}

	// Collect all record names and sort for deterministic output
	names := make([]string, 0, len(z.Records))
	for name := range z.Records {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		records := z.Records[name]
		for _, r := range records {
			// Skip SOA and NS at apex — already written above
			if name == z.Origin && (strings.ToUpper(r.Type) == "SOA" || strings.ToUpper(r.Type) == "NS") {
				continue
			}

			rname := stripZoneControlChars(relativize(r.Name, z.Origin))
			ttl := r.TTL
			if ttl == 0 {
				ttl = z.DefaultTTL
			}

			b.WriteString(fmt.Sprintf("%s\t%d\t%s\t%s\t%s\n",
				rname, ttl, r.Class, r.Type, formatRDataForZone(r)))
		}
	}

	return b.String(), nil
}

// ValidateRecordData rejects a record whose owner name or RDATA contains a
// newline, carriage return, or NUL. These characters never appear in a valid
// single-line presentation-format record, and writing them into the text zone
// file (see formatRDataForZone) would inject additional, attacker-controlled
// zone-file lines. Enforced at every untrusted write path (API, DDNS).
func ValidateRecordData(name, rdata string) error {
	// Zone-file-hostile characters in the name: the owner is written into
	// the zone file unquoted, so a semicolon, whitespace, quote, or
	// parenthesis corrupts the written file — the reload truncates at the
	// semicolon or mis-tokenizes at whitespace. DNS names cannot legally
	// contain them anyway (RFC 1035 §2.3.1).
	const nameHostile = "; \t\"()"
	if i := strings.IndexAny(name, nameHostile+"\n\r\x00"); i >= 0 {
		return fmt.Errorf("record name contains a character that breaks the zone-file format (semicolon, space, quote, or parenthesis)")
	}
	if i := strings.IndexAny(rdata, "\n\r\x00"); i >= 0 {
		return fmt.Errorf("record data contains a control character (\\n/\\r/NUL) that could inject a zone-file line")
	}
	return nil
}

// stripZoneControlChars is a defense-in-depth safety net at the serialization
// boundary: even if a record with control characters somehow reaches the
// writer, it can never corrupt the zone file or inject a line.
func stripZoneControlChars(s string) string {
	if !strings.ContainsAny(s, "\n\r\x00") {
		return s
	}
	return strings.NewReplacer("\n", "", "\r", "", "\x00", "").Replace(s)
}

func formatRDataForZone(r Record) string {
	switch strings.ToUpper(r.Type) {
	case "TXT", "SPF", "DKIM":
		data := stripZoneControlChars(r.RData)
		// Records added through the API are already in presentation form
		// ("v=spf1 mx -all"); quoting them again wrote literal quotes into
		// the value. The zone-file parser stores raw text, which is quoted.
		if isQuotedCharacterStrings(data) {
			return data
		}
		return quoteZoneCharacterString(data)
	default:
		return stripZoneControlChars(r.RData)
	}
}

// isQuotedCharacterStrings reports whether s is one or more complete quoted
// character-strings separated by whitespace, e.g. `"a" "b\"c"`.
func isQuotedCharacterStrings(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for s != "" {
		if s[0] != '"' {
			return false
		}
		i := 1
		for ; i < len(s); i++ {
			if s[i] == '\\' {
				i++
				continue
			}
			if s[i] == '"' {
				break
			}
		}
		if i >= len(s) {
			return false // unterminated
		}
		s = s[i+1:]
		trimmed := strings.TrimLeft(s, " \t")
		if trimmed != "" && len(trimmed) == len(s) {
			return false // no separator between strings
		}
		s = trimmed
	}
	return true
}

func quoteZoneCharacterString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

// relativize converts an absolute name to relative within the zone origin.
func relativize(name, origin string) string {
	if name == origin {
		return "@"
	}
	if strings.HasSuffix(name, "."+origin) {
		return strings.TrimSuffix(name, "."+origin)
	}
	return name
}
