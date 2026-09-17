package config

import "fmt"

// LoggingConfig contains logging settings.
type LoggingConfig struct {
	// Log level (debug, info, warn, error)
	Level string `yaml:"level"`

	// Log format (json, text)
	Format string `yaml:"format"`

	// Log output: stdout, stderr, or an absolute file path (opened in append
	// mode; rotate with logrotate copytruncate)
	Output string `yaml:"output"`

	// Query logging
	QueryLog bool `yaml:"query_log"`

	// Query log file (absolute path; if empty, query log lines go to stdout)
	QueryLogFile string `yaml:"query_log_file"`
}

func unmarshalLogging(node *Node, cfg *LoggingConfig) error {
	if node.Type != NodeMapping {
		return fmt.Errorf("expected mapping")
	}

	cfg.Level = node.GetString("level")
	if cfg.Level == "" {
		cfg.Level = "info"
	}
	cfg.Format = node.GetString("format")
	if cfg.Format == "" {
		cfg.Format = "text"
	}
	cfg.Output = node.GetString("output")
	if cfg.Output == "" {
		cfg.Output = "stdout"
	}
	cfg.QueryLog = getBool(node, "query_log", cfg.QueryLog)
	cfg.QueryLogFile = node.GetString("query_log_file")

	return nil
}
