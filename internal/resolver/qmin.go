// Package resolver — QNAME Minimization (RFC 7816)
//
// When enabled, the resolver reveals only the next label to each
// authoritative server instead of the full query name. This improves
// privacy by not exposing the complete domain name to every server
// along the delegation chain.
//
// Algorithm:
//  1. At each delegation step, compute the known zone cut (e.g., "com.")
//  2. Instead of querying for "www.example.com." at "com." servers,
//     query for "example.com." (one label beyond the cut) with type NS.
//  3. If a referral or NXDOMAIN is received, proceed normally.
//  4. Once we reach the final zone, query for the full name + original type.
package resolver

import (
	"strings"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// minimizedName returns the query name minimized to one label beyond the
// known zone cut. If the target name is already at or within the zone cut,
// the full name is returned unchanged.
//
// Example:
//
//	minimizedName("www.example.com.", ".") → "com."
//	minimizedName("www.example.com.", "com.") → "example.com."
//	minimizedName("www.example.com.", "example.com.") → "www.example.com."
func minimizedName(target, zoneCut string) string {
	target = strings.TrimSuffix(target, ".")
	zoneCut = strings.TrimSuffix(zoneCut, ".")

	if target == zoneCut || target == "" {
		return target + "."
	}

	// Strip the zone cut suffix to get the remaining labels
	var remaining string
	if zoneCut == "" {
		remaining = target
	} else {
		suffix := "." + zoneCut
		if !strings.HasSuffix(target, suffix) {
			// Target is not under this zone cut — return full name
			return target + "."
		}
		remaining = strings.TrimSuffix(target, suffix)
	}

	// Find the last label in remaining (closest to the zone cut)
	parts := strings.Split(remaining, ".")
	lastLabel := parts[len(parts)-1]

	// Build minimized name: lastLabel.zoneCut.
	if zoneCut == "" {
		return lastLabel + "."
	}
	return lastLabel + "." + zoneCut + "."
}

// zoneCutFromNS extracts the zone name from the NS records in the
// authority section of a referral response. Returns "." if no NS
// records are found.
func zoneCutFromNS(authorities []*protocol.ResourceRecord) string {
	for _, rr := range authorities {
		if rr.Type == protocol.TypeNS {
			return rr.Name.String()
		}
	}
	return "."
}

// isMinimizedTarget returns true if the minimized name equals the full
// target name, meaning we've reached the final zone and should send
// the original query type instead of NS.
func isMinimizedTarget(minimized, target string) bool {
	return strings.EqualFold(minimized, target)
}
