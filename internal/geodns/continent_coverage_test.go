package geodns

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isoAlpha2 lists every officially assigned ISO 3166-1 alpha-2 code plus the
// user-assigned XK (Kosovo) that GeoLite2/GeoIP2 databases emit.
const isoAlpha2 = `AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK`

// Every country a GeoIP database can return must map to a continent, or its
// clients skip continent-level rules and silently get the rule default.
func TestCountryToContinentCoversEveryISOCode(t *testing.T) {
	valid := map[string]bool{"AF": true, "AN": true, "AS": true, "EU": true, "NA": true, "OC": true, "SA": true}
	codes := strings.Fields(isoAlpha2)
	if len(codes) < 249 {
		t.Fatalf("ISO code list truncated: %d codes", len(codes))
	}
	for _, c := range codes {
		got := countryToContinent(c)
		if got == "" {
			t.Errorf("countryToContinent(%q) is empty: no continent mapping", c)
		} else if !valid[got] {
			t.Errorf("countryToContinent(%q) = %q, not a continent code", c, got)
		}
	}
}

func TestCountryToContinentTerritories(t *testing.T) {
	for country, want := range map[string]string{
		"HK": "AS", "MO": "AS", "PS": "AS", // Asia
		"PR": "NA", "GL": "NA", "VI": "NA", "KY": "NA", // North America
		"SS": "AF", "RE": "AF", "EH": "AF", // Africa
		"GU": "OC", "PF": "OC", "NC": "OC", // Oceania
		"XK": "EU", "FO": "EU", "GI": "EU", // Europe
		"FK": "SA", "GF": "SA", // South America
		"AQ": "AN",                         // Antarctica
		"DE": "EU", "US": "NA", "AF": "AS", // existing entries unchanged (AF = Afghanistan)
	} {
		if got := countryToContinent(country); got != want {
			t.Errorf("countryToContinent(%q) = %q, want %q", country, got, want)
		}
	}
}

// End to end through a real MMDB: a client whose country is a territory must
// receive its continent-level record, not the rule default.
func TestResolveContinentRuleReachesTerritoryClients(t *testing.T) {
	resolveFor := func(t *testing.T, iso string) string {
		t.Helper()
		b := &mmdbBuilder{}
		ref, err := b.addData(map[string]interface{}{"country": map[string]interface{}{"iso_code": iso}})
		if err != nil {
			t.Fatal(err)
		}
		b.addNode(ref, ref)
		fixture, err := b.build(4)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "c.mmdb")
		if err := os.WriteFile(path, fixture, 0o600); err != nil {
			t.Fatal(err)
		}
		e := NewEngine(Config{Enabled: true})
		if err := e.LoadMMDB(path); err != nil {
			t.Fatal(err)
		}
		e.SetRule("cdn.example.com.", "A", &GeoRecord{
			Records: map[string]string{"AS": "10.0.0.1", "EU": "10.0.0.2", "NA": "10.0.0.3", "AF": "10.0.0.4"},
			Default: "10.9.9.9",
		})
		return e.Resolve("cdn.example.com.", "A", net.ParseIP("203.0.113.9"))
	}

	cases := []struct{ name, iso, want string }{
		{"control: DE is EU", "DE", "10.0.0.2"},
		{"HK is Asia", "HK", "10.0.0.1"},
		{"PS is Asia", "PS", "10.0.0.1"},
		{"PR is North America", "PR", "10.0.0.3"},
		{"SS is Africa", "SS", "10.0.0.4"},
		{"unmapped code still falls to default", "ZZ", "10.9.9.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveFor(t, tc.iso); got != tc.want {
				t.Fatalf("country %s: got %q, want %q", tc.iso, got, tc.want)
			}
		})
	}
}
