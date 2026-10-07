package config

import (
	"strings"
	"testing"
)

// X6 (F367): transfer.tsig_keys parse and validation, and the slave-zone TSIG
// secret format the transfer manager now decodes (F368).

const tsigKeysTestSecret = "WDYtbWFzdGVyLWtleS0wMTIzNDU2Nzg5LWFiY2RlZiE=" // base64, 32 bytes

func TestUnmarshalYAMLTransferTSIGKeys(t *testing.T) {
	cfg, err := UnmarshalYAML(`
transfer:
  allow_list:
    - 192.0.2.0/24
  require_tsig: true
  tsig_keys:
    - name: xfr-a.example.
      secret: "` + tsigKeysTestSecret + `"
    - name: xfr-b.example.
      algorithm: hmac-sha512
      secret: "` + tsigKeysTestSecret + `"
      allowed_cidrs:
        - 192.0.2.10/32
`)
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	keys := cfg.Transfer.TSIGKeys
	if len(keys) != 2 {
		t.Fatalf("tsig_keys = %d entries, want 2", len(keys))
	}
	if keys[0].Name != "xfr-a.example." || keys[0].Algorithm != "hmac-sha256" || keys[0].Secret != tsigKeysTestSecret || len(keys[0].AllowedCIDRs) != 0 {
		t.Errorf("key 0 = %+v, want default algorithm hmac-sha256", keys[0])
	}
	if keys[1].Algorithm != "hmac-sha512" || len(keys[1].AllowedCIDRs) != 1 || keys[1].AllowedCIDRs[0] != "192.0.2.10/32" {
		t.Errorf("key 1 = %+v", keys[1])
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Errorf("Validate: %v", errs)
	}
	for _, e := range cfg.ValidateProduction() {
		if strings.Contains(e, "transfer") {
			t.Errorf("production: %s", e)
		}
	}
}

func TestValidateTransferTSIGKeys(t *testing.T) {
	cases := []struct {
		name string
		keys []TransferTSIGKeyConfig
		want string
	}{
		{"missing name", []TransferTSIGKeyConfig{{Algorithm: "hmac-sha256", Secret: tsigKeysTestSecret}}, "name is required"},
		{"duplicate", []TransferTSIGKeyConfig{{Name: "k.example.", Algorithm: "hmac-sha256", Secret: tsigKeysTestSecret}, {Name: "K.example", Algorithm: "hmac-sha256", Secret: tsigKeysTestSecret}}, "duplicate key name"},
		{"md5", []TransferTSIGKeyConfig{{Name: "k.", Algorithm: "hmac-md5", Secret: tsigKeysTestSecret}}, "unsupported algorithm"},
		{"not base64", []TransferTSIGKeyConfig{{Name: "k.", Algorithm: "hmac-sha256", Secret: "not*base64"}}, "not valid base64"},
		{"short", []TransferTSIGKeyConfig{{Name: "k.", Algorithm: "hmac-sha256", Secret: "c2hvcnQ="}}, "at least 16 bytes"},
		{"bad cidr", []TransferTSIGKeyConfig{{Name: "k.", Algorithm: "hmac-sha256", Secret: tsigKeysTestSecret, AllowedCIDRs: []string{"300.0.0.0/8"}}}, "invalid CIDR"},
	}
	for _, tc := range cases {
		cfg := &Config{Transfer: TransferConfig{TSIGKeys: tc.keys}}
		if got := strings.Join(cfg.validateTransfer(), "; "); !strings.Contains(got, tc.want) {
			t.Errorf("%s: errors %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestValidateProductionRequireTSIGNeedsKeys(t *testing.T) {
	cfg := &Config{Transfer: TransferConfig{AllowList: []string{"192.0.2.0/24"}, RequireTSIG: true}}
	if got := strings.Join(cfg.validateProduction(), "; "); !strings.Contains(got, "transfer.tsig_keys") {
		t.Errorf("require_tsig without keys not flagged: %q", got)
	}
	cfg.Transfer.TSIGKeys = []TransferTSIGKeyConfig{{Name: "k.", Algorithm: "hmac-sha256", Secret: tsigKeysTestSecret}}
	if got := strings.Join(cfg.validateProduction(), "; "); strings.Contains(got, "transfer") {
		t.Errorf("configured key still flagged: %q", got)
	}
}

func TestValidateSlaveZoneTSIGSecretFormat(t *testing.T) {
	base := SlaveZoneConfig{ZoneName: "example.com.", Masters: []string{"192.0.2.1:53"}, TransferType: "axfr", Timeout: "30s", RetryInterval: "5m"}
	cases := []struct {
		name, keyName, secret, want string
	}{
		{"name without secret", "k.", "", "must be set together"},
		{"secret without name", "", tsigKeysTestSecret, "must be set together"},
		{"not base64", "k.", "this-is-not-base64-but-long-enough!!", "not valid base64"},
		{"valid", "k.", tsigKeysTestSecret, ""},
	}
	for _, tc := range cases {
		s := base
		s.TSIGKeyName, s.TSIGSecret = tc.keyName, tc.secret
		cfg := &Config{SlaveZones: []SlaveZoneConfig{s}}
		got := strings.Join(cfg.validateSlaveZones(), "; ")
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%s: errors %q, want %q", tc.name, got, tc.want)
		}
	}
}
