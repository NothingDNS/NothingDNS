package config

import (
	"strings"
	"testing"
)

// F547: transfer.also_notify / transfer.notify_key parse and validation.

func TestUnmarshalYAMLTransferAlsoNotify(t *testing.T) {
	cfg, err := UnmarshalYAML(`
transfer:
  also_notify:
    - 192.0.2.2:53
    - "[2001:db8::2]:5300"
  notify_key: Notify-Key.Example
  tsig_keys:
    - name: notify-key.example.
      secret: "` + tsigKeysTestSecret + `"
`)
	if err != nil {
		t.Fatalf("UnmarshalYAML: %v", err)
	}
	if got := cfg.Transfer.AlsoNotify; len(got) != 2 || got[0] != "192.0.2.2:53" || got[1] != "[2001:db8::2]:5300" {
		t.Fatalf("also_notify = %v", got)
	}
	if cfg.Transfer.NotifyKey != "Notify-Key.Example" {
		t.Fatalf("notify_key = %q", cfg.Transfer.NotifyKey)
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Errorf("Validate: %v", errs)
	}
}

func TestTransferAlsoNotifyDefaultsEmpty(t *testing.T) {
	cfg, err := UnmarshalYAML("transfer:\n  require_tsig: false\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Transfer.AlsoNotify) != 0 || cfg.Transfer.NotifyKey != "" {
		t.Fatalf("defaults: also_notify=%v notify_key=%q, want empty (NOTIFY off)", cfg.Transfer.AlsoNotify, cfg.Transfer.NotifyKey)
	}
	if len(DefaultConfig().Transfer.AlsoNotify) != 0 {
		t.Fatal("DefaultConfig must not send NOTIFY anywhere")
	}
}

func TestValidateTransferAlsoNotify(t *testing.T) {
	cases := []struct {
		name    string
		targets []string
		key     string
		want    string
	}{
		{"hostname", []string{"ns2.example.com:53"}, "", "must be IP:port"},
		{"no port", []string{"192.0.2.2"}, "", "must be IP:port"},
		{"port zero", []string{"192.0.2.2:0"}, "", "invalid port"},
		{"port range", []string{"192.0.2.2:70000"}, "", "invalid port"},
		{"duplicate", []string{"192.0.2.2:53", "192.0.2.2:53"}, "", "duplicate target"},
		{"unknown key", []string{"192.0.2.2:53"}, "missing.example.", "does not name a transfer.tsig_keys entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Transfer.AlsoNotify = tc.targets
			cfg.Transfer.NotifyKey = tc.key
			errs := strings.Join(cfg.validateTransfer(), "\n")
			if !strings.Contains(errs, tc.want) {
				t.Fatalf("errors %q, want one containing %q", errs, tc.want)
			}
		})
	}
	// Control: valid IPv4/IPv6 targets.
	cfg := DefaultConfig()
	cfg.Transfer.AlsoNotify = []string{"127.0.0.1:5354", "[::1]:53"}
	if errs := cfg.validateTransfer(); len(errs) != 0 {
		t.Fatalf("valid targets rejected: %v", errs)
	}
}
