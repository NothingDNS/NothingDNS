package zone

// Round-29 regression guard: ValidateRecordData's name check covered only
// \n/\r/NUL, so owner names containing zone-file-hostile characters
// (semicolon, space, quote, paren) passed validation and were written into
// the zone file unquoted — the reload then truncated at the semicolon,
// mis-tokenized at whitespace, or failed outright (the silent-rename and
// unloadable-file shapes). The gate now rejects them; this test pins it.

import (
	"strings"
	"testing"
)

func TestValidateRecordDataRejectsZoneFileHostileNames(t *testing.T) {
	hostile := []string{
		"bad;name.example.com.",  // comment injection on reload
		"bad name.example.com.",  // field splitting on reload
		`bad"name.example.com.`,  // quoting state machine on reload
		"bad(name.example.com.",  // paren continuation on reload
		"bad)name.example.com.",  // paren continuation on reload
		"bad\tname.example.com.", // tab splits fields
	}
	for _, name := range hostile {
		if err := ValidateRecordData(name, "192.0.2.1"); err == nil {
			t.Fatalf("FAIL: zone-file-hostile owner name %q was accepted by ValidateRecordData", name)
		}
	}
}

func TestValidateRecordDataAcceptsSafeNames(t *testing.T) {
	safe := []string{
		"www.example.com.",
		"_d.example.com.",     // the round-10/10-era covered-name shape
		"_test.example.com.",  // underscore labels (DKIM/ACME selectors)
		"*.wild.example.com.", // wildcard labels
		"Mixed.Case.Example.com.",
	}
	for _, name := range safe {
		if err := ValidateRecordData(name, "192.0.2.1"); err != nil {
			t.Fatalf("FAIL: safe owner name %q was rejected: %v", name, err)
		}
	}
}

func TestWriteZoneNormalNameRoundTrips(t *testing.T) {
	z := NewZone("example.com.")
	z.Records["www.example.com."] = []Record{{
		Name:  "www.example.com.",
		Type:  "A",
		Class: "IN",
		TTL:   300,
		RData: "192.0.2.3",
	}}

	written, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}

	roundTripped, err := ParseFile("writer-roundtrip-normal.zone", strings.NewReader(written))
	if err != nil {
		t.Fatalf("ParseFile on the written zone: %v", err)
	}

	if _, ok := roundTripped.Records["www.example.com."]; !ok {
		t.Fatalf("FAIL: the normal record did not survive the zone-file round trip")
	}
}

// Zones created through the API keep apex NS only in Records (z.NS is empty
// after a KV reload and stale after API edits), and their TXT data is already
// quoted. Exports dropped every NS and double-quoted TXT values.
func TestWriteZoneAPIRecordsExportNSAndTXTOnce(t *testing.T) {
	z := NewZone("example.com.")
	z.DefaultTTL = 3600
	z.SOA = &SOARecord{TTL: 3600, MName: "ns1.example.com.", RName: "admin.example.com.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}
	z.Records["example.com."] = []Record{
		{Name: "example.com.", Type: "NS", Class: "IN", TTL: 3600, RData: "ns1.example.com."},
		{Name: "example.com.", Type: "NS", Class: "IN", TTL: 3600, RData: "ns2.example.com."},
		{Name: "example.com.", Type: "TXT", Class: "IN", TTL: 300, RData: `"v=spf1 mx -all"`},
	}
	z.Records["raw.example.com."] = []Record{
		{Name: "raw.example.com.", Type: "TXT", Class: "IN", TTL: 300, RData: `plain text`},
	}

	written, err := WriteZone(z)
	if err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if got := strings.Count(written, "\tNS\t"); got != 2 {
		t.Fatalf("exported %d NS records, want 2:\n%s", got, written)
	}
	if !strings.Contains(written, "@\t300\tIN\tTXT\t\"v=spf1 mx -all\"\n") {
		t.Fatalf("API TXT must be written quoted once:\n%s", written)
	}
	if !strings.Contains(written, "raw\t300\tIN\tTXT\t\"plain text\"\n") {
		t.Fatalf("raw TXT must be quoted:\n%s", written)
	}

	parsed, err := ParseFile("export-roundtrip.zone", strings.NewReader(written))
	if err != nil {
		t.Fatalf("ParseFile on the export: %v", err)
	}
	if len(parsed.NS) != 2 {
		t.Fatalf("round trip kept %d NS records, want 2", len(parsed.NS))
	}
	var txt string
	for _, r := range parsed.Records["example.com."] {
		if r.Type == "TXT" {
			txt = r.RData
		}
	}
	if txt != "v=spf1 mx -all" {
		t.Fatalf("round-tripped TXT = %q, want v=spf1 mx -all", txt)
	}
}

func TestIsQuotedCharacterStrings(t *testing.T) {
	for s, want := range map[string]bool{
		`"a"`:          true,
		`"a" "b"`:      true,
		`"a\"b"`:       true,
		`plain`:        false,
		`"a`:           false,
		`"a""b"`:       false,
		`"a" b`:        false,
		``:             false,
		`"v=DKIM1; k"`: true,
	} {
		if got := isQuotedCharacterStrings(s); got != want {
			t.Errorf("isQuotedCharacterStrings(%q) = %v, want %v", s, got, want)
		}
	}
}
