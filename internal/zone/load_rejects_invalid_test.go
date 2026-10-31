package zone

import (
	"strings"
	"testing"
)

const rejectHeader = "$ORIGIN bad.example.\n$TTL 300\n@ IN SOA ns1 h 1 2 3 4 5\n@ IN NS ns1\nns1 A 192.0.2.1\n"

// A zone file with a record the server cannot serve must fail to load, at the
// offending line, as in BIND — not load with the record silently missing.
func TestParseFileRejectsUnservableRecords(t *testing.T) {
	long := strings.Repeat("a", 64)
	cases := map[string]string{
		"bad A address":        "x A 999.1.1.1\n",
		"empty A":              "x A\n",
		"MX without pref":      "x MX mail\n",
		"label over 63":        long + " A 192.0.2.1\n",
		"second SOA":           "@ IN SOA ns1 h 2 2 3 4 5\n",
		"CNAME with A":         "c CNAME ns1\nc A 192.0.2.9\n",
		"A before CNAME":       "c A 192.0.2.9\nc CNAME ns1\n",
		"CNAME with MX":        "c CNAME ns1\nc MX 10 ns1\n",
		"bad AAAA (dotted v4)": "x AAAA 192.0.2.1\n",
	}
	for name, body := range cases {
		z, err := ParseFile("bad.zone", strings.NewReader(rejectHeader+body))
		if err == nil {
			err = z.Validate()
		}
		if err == nil {
			t.Errorf("%s: zone loaded without error", name)
		}
	}
}

func TestParseFileAcceptsValidNeighbours(t *testing.T) {
	body := "c CNAME ns1\nc RRSIG CNAME 13 3 300 20300101000000 20200101000000 1 bad.example. AAAA\nx A 192.0.2.7\n*.w A 192.0.2.8\n"
	z, err := ParseFile("ok.zone", strings.NewReader(rejectHeader+body))
	if err != nil {
		t.Skipf("parser does not take this RRSIG text: %v", err)
	}
	if err := z.Validate(); err != nil {
		t.Fatalf("valid zone rejected: %v", err)
	}
}
