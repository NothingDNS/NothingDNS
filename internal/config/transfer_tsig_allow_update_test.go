package config

import (
	"strings"
	"testing"
)

// F452 (P2-C2): transfer.tsig_keys[].allow_update grants a key RFC 2136
// UPDATE rights to the listed zones.

func TestUnmarshalYAMLTransferTSIGKeyAllowUpdate(t *testing.T) {
	cfg, err := UnmarshalYAML(`
transfer:
  tsig_keys:
    - name: ddns.example.
      secret: "` + tsigKeysTestSecret + `"
      allow_update:
        - example.com.
        - example.net
    - name: xfr.example.
      secret: "` + tsigKeysTestSecret + `"
`)
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	keys := cfg.Transfer.TSIGKeys
	if len(keys) != 2 {
		t.Fatalf("tsig_keys = %d entries, want 2", len(keys))
	}
	if got := strings.Join(keys[0].AllowUpdate, ","); got != "example.com.,example.net" {
		t.Errorf("key 0 allow_update = %q", got)
	}
	if len(keys[1].AllowUpdate) != 0 {
		t.Errorf("key 1 allow_update = %v, want none (secure default)", keys[1].AllowUpdate)
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Errorf("Validate: %v", errs)
	}
}

func TestValidateTransferTSIGKeyAllowUpdate(t *testing.T) {
	cases := []struct {
		name  string
		zones []string
		want  string
	}{
		{"valid", []string{"example.com.", "Example.NET", "."}, ""},
		{"empty", []string{" "}, "empty zone name"},
		{"wildcard", []string{"*.example.com."}, "not a wildcard"},
		{"empty label", []string{"bad..name"}, "invalid zone name"},
		{"space", []string{"bad name.com."}, "invalid zone name"},
		{"duplicate", []string{"example.com.", "EXAMPLE.com"}, "duplicate zone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{Transfer: TransferConfig{TSIGKeys: []TransferTSIGKeyConfig{{
				Name: "k.example.", Algorithm: "hmac-sha256", Secret: tsigKeysTestSecret, AllowUpdate: tc.zones,
			}}}}
			errs := strings.Join(c.validateTransfer(), "\n")
			if tc.want == "" {
				if errs != "" {
					t.Fatalf("unexpected errors: %s", errs)
				}
				return
			}
			if !strings.Contains(errs, "allow_update") || !strings.Contains(errs, tc.want) {
				t.Fatalf("errors %q, want %q", errs, tc.want)
			}
		})
	}
}
