// Package resolver — DNS 0x20 Encoding (Vixie/Dagon)
//
// The 0x20 bit hack randomizes the case of ASCII letters in DNS query
// names sent to upstream servers. Since DNS names are case-insensitive
// (RFC 1035 §2.3.3) but the response MUST echo the exact query name
// back (RFC 1035 §4.1.1), this provides roughly 2^N additional bits of
// entropy for N letters in the name, making cache-poisoning attacks
// significantly harder.
package resolver

import (
	"math/rand"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// Encode0x20 randomly toggles the case of ASCII letters in a DNS name.
// Dots and non-alpha characters are left untouched. The trailing dot
// (if present) is preserved.
func Encode0x20(name string) string {
	buf := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if isASCIILetter(c) {
			if rand.Intn(2) == 0 {
				c = toUpper(c)
			} else {
				c = toLower(c)
			}
		}
		buf[i] = c
	}
	return string(buf)
}

// Verify0x20 checks that the response echoes back the exact case of
// the query name. Returns true if they match byte-for-byte.
func Verify0x20(query, response string) bool {
	return query == response
}

// verify0x20Response checks that the question section of the response
// echoes back the exact 0x20-encoded query name. Returns true if the
// response has at least one question and its name matches byte-for-byte.
func verify0x20Response(encodedName string, resp *protocol.Message) bool {
	if len(resp.Questions) == 0 {
		return false
	}
	return Verify0x20(encodedName, resp.Questions[0].Name.String())
}

func isASCIILetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func toUpper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 0x20
	}
	return c
}

func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 0x20
	}
	return c
}
