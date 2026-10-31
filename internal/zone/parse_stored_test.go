package zone

import (
	"strings"
	"testing"
)

// Zone text the server stored or replicated itself keeps loading when it holds
// a record ParseFile refuses: the record is skipped with a warning and the rest
// of the zone is kept.
func TestParseStoredSkipsUnservableRecords(t *testing.T) {
	long := strings.Repeat("a", 64)
	cases := map[string]string{
		"hostname as A":   "r1 A r1-137.bad.example.\n",
		"bad A address":   "x A 999.1.1.1\n",
		"MX without pref": "x MX mail\n",
		"label over 63":   long + " A 192.0.2.1\n",
		"second SOA":      "@ IN SOA ns1 h 2 2 3 4 5\n",
	}
	for name, body := range cases {
		text := rejectHeader + body + "keep A 192.0.2.50\n"
		if _, err := ParseFile("bad.zone", strings.NewReader(text)); err == nil {
			t.Errorf("%s: ParseFile accepted the record; this test needs one it refuses", name)
		}
		z, err := ParseStored("bad.zone", strings.NewReader(text))
		if err != nil {
			t.Errorf("%s: ParseStored failed: %v", name, err)
			continue
		}
		if warning, err := z.ValidateStored(); err != nil || warning != "" {
			t.Errorf("%s: ValidateStored = %q, %v", name, warning, err)
		}
		if len(z.Warnings) != 1 || !strings.Contains(z.Warnings[0], "skipping") {
			t.Errorf("%s: warnings = %q, want one skipped record", name, z.Warnings)
		}
		if len(z.Records["keep.bad.example."]) != 1 {
			t.Errorf("%s: records after the skipped one were lost", name)
		}
		if z.SOA == nil || z.SOA.Serial != 1 {
			t.Errorf("%s: SOA = %+v, want the first one (serial 1)", name, z.SOA)
		}
	}
}

// ValidateStored still refuses a zone without its SOA or apex NS, but keeps one
// holding a CNAME next to other data, with a warning.
func TestValidateStored(t *testing.T) {
	z, err := ParseStored("c.zone", strings.NewReader(rejectHeader+"c CNAME ns1\nc A 192.0.2.9\n"))
	if err != nil {
		t.Fatal(err)
	}
	warning, err := z.ValidateStored()
	if err != nil || !strings.Contains(warning, "CNAME and other data") {
		t.Errorf("ValidateStored = %q, %v; want a CNAME warning and no error", warning, err)
	}
	if z.Validate() == nil {
		t.Error("Validate accepted CNAME and other data")
	}

	noNS, err := ParseStored("n.zone", strings.NewReader("$ORIGIN n.example.\n$TTL 300\n@ IN SOA ns1 h 1 2 3 4 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noNS.ValidateStored(); err == nil {
		t.Error("ValidateStored accepted a zone without apex NS")
	}
}
