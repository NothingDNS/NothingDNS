package config

import (
	"strings"
	"testing"
)

func TestPprofBindParseAndValidate(t *testing.T) {
	off, err := UnmarshalYAML("metrics:\n  enabled: false\n")
	if err != nil {
		t.Fatal(err)
	}
	if off.Metrics.PprofBind != "" {
		t.Fatalf("pprof must be off by default, got %q", off.Metrics.PprofBind)
	}
	for _, e := range off.validateMetrics() {
		t.Fatalf("unexpected error with pprof off: %s", e)
	}

	cases := []struct {
		bind string
		bad  bool
	}{
		{"127.0.0.1:6060", false},
		{"[::1]:6060", false},
		{"localhost:6060", false},
		{"0.0.0.0:6060", true},
		{":6060", true},
		{"10.0.0.5:6060", true},
		{"127.0.0.1", true},
	}
	for _, tc := range cases {
		cfg, err := UnmarshalYAML("metrics:\n  pprof_bind: \"" + tc.bind + "\"\n")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Metrics.PprofBind != tc.bind {
			t.Fatalf("parsed %q, want %q", cfg.Metrics.PprofBind, tc.bind)
		}
		errs := strings.Join(cfg.validateMetrics(), ";")
		if tc.bad != strings.Contains(errs, "pprof_bind") {
			t.Fatalf("bind %q: bad=%v errors=%q", tc.bind, tc.bad, errs)
		}
	}
}
