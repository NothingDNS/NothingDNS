package main

import (
	"strings"
	"testing"
)

// F712: numbers decoded from API JSON are float64, and "%v" prints those of
// seven digits or more in exponent form: a 2024010101 SOA serial or 2592000
// TTL came out as 2.024010101e+09 / 2.592e+06 in dnsctl output.
func TestJSONNumbersPrintAsIntegers(t *testing.T) {
	out := captureOutput(func() {
		printJSON("serial", float64(2024010101), "")
		printJSON("ttl", float64(2592000), "")
		printJSON("hits", float64(1234567), "")
		printJSON("small", float64(300), "")
		printJSON("ratio", 0.25, "")
	})
	for _, want := range []string{"serial: 2024010101", "ttl: 2592000", "hits: 1234567", "small: 300", "ratio: 0.25"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "e+") {
		t.Errorf("exponent notation in output:\n%s", out)
	}
}
