package config

import (
	"strings"
	"testing"
)

// TestNSEC3IterationsCapped_F516: dnssec.signing.nsec3.iterations above 150
// is rejected at load (RFC 9276 §3.2: validators may treat such NSEC3 as
// insecure or bogus, and the server's online NSEC3 hashing refuses it, so
// every negative answer would go out unproven). 0..150 stay valid.
func TestNSEC3IterationsCapped_F516(t *testing.T) {
	errsFor := func(iterations string) []string {
		cfg, err := UnmarshalYAML(`dnssec:
  enabled: true
  signing:
    enabled: true
    keys:
      - private_key: /etc/nothingdns/k.private
        type: ksk
        algorithm: 13
    nsec3:
      iterations: ` + iterations + "\n")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		var out []string
		for _, e := range cfg.Validate() {
			if strings.Contains(e, "nsec3") {
				out = append(out, e)
			}
		}
		return out
	}
	for _, ok := range []string{"0", "150"} {
		if errs := errsFor(ok); len(errs) != 0 {
			t.Errorf("iterations %s rejected: %v", ok, errs)
		}
	}
	for _, bad := range []string{"151", "65535"} {
		if errs := errsFor(bad); len(errs) != 1 || !strings.Contains(errs[0], "dnssec.signing.nsec3.iterations") {
			t.Errorf("iterations %s: errors %v, want one nsec3.iterations error", bad, errs)
		}
	}
}
