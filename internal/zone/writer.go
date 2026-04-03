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

	// NS records at apex
	for _, ns := range z.NS {
		ttl := ns.TTL
		if ttl == 0 {
			ttl = z.DefaultTTL
		}
		b.WriteString(fmt.Sprintf("@\t%d\tIN\tNS\t%s\n", ttl, ns.NSDName))
	}
	if len(z.NS) > 0 {
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

			rname := relativize(r.Name, z.Origin)
			ttl := r.TTL
			if ttl == 0 {
				ttl = z.DefaultTTL
			}

			b.WriteString(fmt.Sprintf("%s\t%d\t%s\t%s\t%s\n",
				rname, ttl, r.Class, r.Type, r.RData))
		}
	}

	return b.String(), nil
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
