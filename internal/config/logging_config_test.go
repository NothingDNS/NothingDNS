package config

import "testing"

// TestUnmarshalLogging_FileOutput is a regression guard for the systemd/logrotate
// wiring: the deploy/nothingdns.service unit pins stdout/stderr to
// /var/log/nothingdns/server.log, which only rotates if an operator wires
// logging.output to that file path. This test pins that the file-output
// branch of LoggingConfig parses cleanly so a future YAML-parser regression
// surfaces here instead of silently breaking rotation in production.
func TestUnmarshalLogging_FileOutput(t *testing.T) {
	const input = `
logging:
  level: info
  format: json
  output: file:/var/log/nothingdns/server.log
  query_log: true
  query_log_file: /var/log/nothingdns/query.log
`
	cfg, err := UnmarshalYAML(input)
	if err != nil {
		t.Fatalf("UnmarshalYAML failed: %v", err)
	}
	if got, want := cfg.Logging.Output, "file:/var/log/nothingdns/server.log"; got != want {
		t.Errorf("Logging.Output = %q, want %q", got, want)
	}
	if !cfg.Logging.QueryLog {
		t.Errorf("Logging.QueryLog = false, want true")
	}
	if got, want := cfg.Logging.QueryLogFile, "/var/log/nothingdns/query.log"; got != want {
		t.Errorf("Logging.QueryLogFile = %q, want %q", got, want)
	}
	if got, want := cfg.Logging.Level, "info"; got != want {
		t.Errorf("Logging.Level = %q, want %q", got, want)
	}
	if got, want := cfg.Logging.Format, "json"; got != want {
		t.Errorf("Logging.Format = %q, want %q", got, want)
	}
}

// TestUnmarshalLogging_Defaults pins the empty-config defaults that the
// logrotate logic depends on. If any default drifts (e.g. query_log flipping
// to true) the systemd+logrotate wiring stops being a no-op only by accident;
// this test makes that drift visible.
func TestUnmarshalLogging_Defaults(t *testing.T) {
	cfg, err := UnmarshalYAML("")
	if err != nil {
		t.Fatalf("UnmarshalYAML(\"\") failed: %v", err)
	}
	if got, want := cfg.Logging.Output, "stdout"; got != want {
		t.Errorf("default Logging.Output = %q, want %q", got, want)
	}
	if cfg.Logging.QueryLog {
		t.Errorf("default Logging.QueryLog = true, want false (must be opt-in)")
	}
}
