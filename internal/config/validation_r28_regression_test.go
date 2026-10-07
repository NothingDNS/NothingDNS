package config

import (
	"strings"
	"testing"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// F187: zero/negative durations whose runtime consumers do not fall back to a
// default must be rejected at load (negative resolution.timeout SERVFAILs all
// recursion, non-positive signature_validity signs already-expired RRSIGs,
// non-positive cookie secret_rotation invalidates every issued server cookie).
func TestValidateRejectsNonPositiveDurations_F187(t *testing.T) {
	set := map[string]func(*Config, string){
		"resolution: invalid timeout":     func(c *Config, v string) { c.Resolution.Timeout = v },
		"cookie: invalid secret_rotation": func(c *Config, v string) { c.Cookie.SecretRotation = v },
		"dnssec.signing: invalid signature_validity": func(c *Config, v string) {
			c.DNSSEC.Enabled = true
			c.DNSSEC.Signing.Enabled = true
			c.DNSSEC.Signing.Keys = []KeyConfig{{PrivateKey: "/k", Type: "ksk", Algorithm: 15}}
			c.DNSSEC.Signing.SignatureValidity = v
		},
	}
	for want, mutate := range set {
		for _, v := range []string{"0s", "-1ns", "-48h"} {
			c := DefaultConfig()
			mutate(c, v)
			if !containsErr(c.Validate(), want) {
				t.Errorf("%s=%q accepted; want error containing %q", want, v, want)
			}
		}
		for _, v := range []string{"", "1ns", "720h"} {
			c := DefaultConfig()
			mutate(c, v)
			if containsErr(c.Validate(), want) {
				t.Errorf("%s=%q rejected; want accepted", want, v)
			}
		}
	}
}

// F188: ACL query-type validation must accept exactly what the runtime ACL
// compiler (protocol.StringToType) accepts.
func TestValidateACLTypesMatchRuntimeTable_F188(t *testing.T) {
	for name := range protocol.StringToType {
		c := DefaultConfig()
		c.ACL = []ACLRule{{Name: "r", Networks: []string{"10.0.0.0/8"}, Types: []string{name}, Action: "deny"}}
		if containsErr(c.Validate(), "acl[0]") {
			t.Errorf("ACL type %q is accepted by the runtime ACL compiler but rejected by Validate", name)
		}
	}
	for _, bad := range []string{"TYPE123", "DLV", "TKEY", "INVALID", ""} {
		c := DefaultConfig()
		c.ACL = []ACLRule{{Name: "r", Networks: []string{"10.0.0.0/8"}, Types: []string{bad}, Action: "deny"}}
		if !containsErr(c.Validate(), "acl[0]: invalid query type") {
			t.Errorf("ACL type %q is rejected by the runtime ACL compiler but accepted by Validate", bad)
		}
	}
}

func containsErr(errs []string, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e, sub) {
			return true
		}
	}
	return false
}
