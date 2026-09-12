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
		"_d.example.com.",       // the round-10/10-era covered-name shape
		"_test.example.com.",    // underscore labels (DKIM/ACME selectors)
		"*.wild.example.com.",   // wildcard labels
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
