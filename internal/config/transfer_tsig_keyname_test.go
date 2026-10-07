package config

import (
	"fmt"
	"strings"
	"testing"
)

// F503 (P2-E4): TSIG key names (transfer.tsig_keys[].name and
// slave_zones[].tsig_key_name) are validated as wire domain names and
// compared in canonical form (lower-case, absolute), as internal/transfer's
// KeyStore matches them.

const keynameSecretA = "RjUwMy1zbGF2ZS1zZWNyZXQtQUFBQUFBQUFBQUFBQUE="
const keynameSecretB = "RjUwMy1zbGF2ZS1zZWNyZXQtQkJCQkJCQkJCQkJCQkI="

func keynameTSIGErrs(t *testing.T, y string) []string {
	t.Helper()
	cfg, err := UnmarshalYAML(y)
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	var out []string
	for _, e := range cfg.Validate() {
		if strings.Contains(e, "tsig") {
			out = append(out, e)
		}
	}
	return out
}

func keynameSlaves(n1, s1, n2, s2 string) string {
	return fmt.Sprintf(`
slave_zones:
  - zone_name: a.example.
    masters:
      - 192.0.2.1:53
    tsig_key_name: "%s"
    tsig_secret: "%s"
  - zone_name: b.example.
    masters:
      - 192.0.2.1:53
    tsig_key_name: "%s"
    tsig_secret: "%s"
`, n1, s1, n2, s2)
}

func keynameKeys(names ...string) string {
	y := "\ntransfer:\n  tsig_keys:\n"
	for _, n := range names {
		y += fmt.Sprintf("    - name: \"%s\"\n      secret: \"%s\"\n", n, keynameSecretA)
	}
	return y
}

func TestValidateTSIGKeyName_Canonical(t *testing.T) {
	cases := []struct {
		name, yaml, want string
	}{
		{"tsig_keys relative name", keynameKeys("xfr-key"), ""},
		{"tsig_keys mixed case", keynameKeys("XFR-Key.example."), ""},
		{"tsig_keys duplicate after canonicalization", keynameKeys("xfr-key", "XFR-Key."), "duplicate key name"},
		{"tsig_keys whitespace", keynameKeys("bad key"), "invalid key name"},
		{"tsig_keys empty label", keynameKeys("a..b"), "invalid key name"},
		{"tsig_keys root", keynameKeys("."), "name is required"},
		{"tsig_keys label too long", keynameKeys(strings.Repeat("x", 64) + ".example."), "invalid key name"},
		{"slave same key same secret", keynameSlaves("xfr-key", keynameSecretA, "XFR-Key.", keynameSecretA), ""},
		{"slave distinct keys", keynameSlaves("k1.", keynameSecretA, "k2.", keynameSecretB), ""},
		{"slave same canonical key different secret", keynameSlaves("xfr-key", keynameSecretA, "XFR-Key.", keynameSecretB), "different tsig_secret"},
		{"slave invalid key name", keynameSlaves("a..b", keynameSecretA, "k2.", keynameSecretB), "invalid tsig_key_name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := keynameTSIGErrs(t, tc.yaml)
			if tc.want == "" {
				if len(errs) != 0 {
					t.Fatalf("unexpected errors: %v", errs)
				}
				return
			}
			if len(errs) != 1 || !strings.Contains(errs[0], tc.want) {
				t.Fatalf("errors = %v, want exactly one containing %q", errs, tc.want)
			}
		})
	}
}
