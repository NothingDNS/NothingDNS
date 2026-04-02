package audit

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// QueryAuditEntry represents a single query audit log entry.
type QueryAuditEntry struct {
	Timestamp  string
	ClientIP   string
	QueryName  string
	QueryType  string
	Rcode       string
	Latency     time.Duration
	CacheHit    bool
	Upstream   string
}

// AuditLogger writes structured query audit logs.
type AuditLogger struct {
	mu      sync.Mutex
	output  io.Writer
	file   *os.File
	enabled bool
}

// NewAuditLogger creates a new audit logger.
// If queryLogFile is non-empty, opens the file for append.
// Otherwise uses stdout.
func NewAuditLogger(queryLog bool, queryLogFile string) (*AuditLogger, error) {
	if !queryLog {
		return &AuditLogger{enabled: false}, nil
	}

	var output io.Writer = os.Stdout
	var file *os.File

	if queryLogFile != "" {
		f, err := os.OpenFile(queryLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening query log file %s: %w", queryLogFile, err)
		}
		file = f
		output = f
	}

	return &AuditLogger{
		output:  output,
		file:    file,
		enabled: true,
	}, nil
}

// LogQuery writes a query audit entry.
func (a *AuditLogger) LogQuery(entry QueryAuditEntry) {
	if !a.enabled {
		return
	}

	line := formatAuditLine(entry)

	a.mu.Lock()
	a.output.Write([]byte(line))
	a.output.Write([]byte{'\n'})
	a.mu.Unlock()
}

// Close closes the audit logger and flushes any buffered output.
func (a *AuditLogger) Close() {
	if a.file != nil {
		a.file.Close()
	}
}

func formatAuditLine(e QueryAuditEntry) string {
	cacheHit := "miss"
	if e.CacheHit {
		cacheHit = "hit"
	}
	upstream := "-"
	if e.Upstream != "" {
		upstream = e.Upstream
	}
	return fmt.Sprintf("%s client=%s query=%s type=%s rcode=%s latency=%s cache=%s upstream=%s",
		e.Timestamp,
		e.ClientIP,
		e.QueryName,
		e.QueryType,
		e.Rcode,
		e.Latency.Round(time.Microsecond),
		cacheHit,
		upstream,
	)
}
