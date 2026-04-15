package audit

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// sanitizeLogField removes newlines and control characters that could
// inject false entries into structured log files.
func sanitizeLogField(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}

// QueryAuditEntry represents a single query audit log entry.
type QueryAuditEntry struct {
	RequestID string // Unique correlation ID for end-to-end tracing
	Timestamp string
	ClientIP  string
	QueryName string
	QueryType string
	Rcode     string
	Latency   time.Duration
	CacheHit  bool
	Upstream  string
}

// AXFRAuditEntry represents an AXFR (full zone transfer) audit log entry.
type AXFRAuditEntry struct {
	RequestID   string
	Timestamp   string
	ClientIP    string
	Zone        string
	Action      string // "request", "completed", "failed"
	RecordCount int
	Latency     time.Duration
}

// IXFRAuditEntry represents an IXFR (incremental zone transfer) audit log entry.
type IXFRAuditEntry struct {
	RequestID   string
	Timestamp   string
	ClientIP    string
	Zone        string
	Action      string // "request", "completed", "failed"
	RecordCount int
	Latency     time.Duration
}

// NOTIFYAuditEntry represents a NOTIFY (zone update notification) audit log entry.
type NOTIFYAuditEntry struct {
	RequestID string
	Timestamp string
	ClientIP  string // the notifying server
	Zone      string
	Action    string // "received", "accepted", "rejected"
}

// UpdateAuditEntry represents a DDNS UPDATE (RFC 2136) audit log entry.
type UpdateAuditEntry struct {
	RequestID string
	Timestamp string
	ClientIP  string
	Zone      string
	Action    string // "request", "success", "failure"
	Rcode     string
	Added     int
	Deleted   int
}

// ReloadAuditEntry represents a configuration reload audit log entry.
type ReloadAuditEntry struct {
	Timestamp string
	Action    string // "start", "complete", "failed"
	Zones     int    // number of zones reloaded
	Error     string
}

// AuditLogger writes structured audit logs for security-sensitive operations.
type AuditLogger struct {
	mu      sync.Mutex
	output  io.Writer
	file    *os.File
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

	line := formatQueryAuditLine(entry)

	a.mu.Lock()
	a.output.Write([]byte(line))
	a.output.Write([]byte{'\n'})
	a.mu.Unlock()
}

// LogAXFR writes an AXFR audit entry.
func (a *AuditLogger) LogAXFR(entry AXFRAuditEntry) {
	if !a.enabled {
		return
	}
	line := formatAXFRAuditLine(entry)
	a.mu.Lock()
	a.output.Write([]byte(line))
	a.output.Write([]byte{'\n'})
	a.mu.Unlock()
}

// LogIXFR writes an IXFR audit entry.
func (a *AuditLogger) LogIXFR(entry IXFRAuditEntry) {
	if !a.enabled {
		return
	}
	line := formatIXFRAuditLine(entry)
	a.mu.Lock()
	a.output.Write([]byte(line))
	a.output.Write([]byte{'\n'})
	a.mu.Unlock()
}

// LogNOTIFY writes a NOTIFY audit entry.
func (a *AuditLogger) LogNOTIFY(entry NOTIFYAuditEntry) {
	if !a.enabled {
		return
	}
	line := formatNOTIFYAuditLine(entry)
	a.mu.Lock()
	a.output.Write([]byte(line))
	a.output.Write([]byte{'\n'})
	a.mu.Unlock()
}

// LogUpdate writes a DDNS UPDATE audit entry.
func (a *AuditLogger) LogUpdate(entry UpdateAuditEntry) {
	if !a.enabled {
		return
	}
	line := formatUpdateAuditLine(entry)
	a.mu.Lock()
	a.output.Write([]byte(line))
	a.output.Write([]byte{'\n'})
	a.mu.Unlock()
}

// LogReload writes a config reload audit entry.
func (a *AuditLogger) LogReload(entry ReloadAuditEntry) {
	if !a.enabled {
		return
	}
	line := formatReloadAuditLine(entry)
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

func formatQueryAuditLine(e QueryAuditEntry) string {
	cacheHit := "miss"
	if e.CacheHit {
		cacheHit = "hit"
	}
	upstream := "-"
	if e.Upstream != "" {
		upstream = e.Upstream
	}
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s query=%s type=%s rcode=%s latency=%s cache=%s upstream=%s",
		e.Timestamp,
		reqID,
		sanitizeLogField(e.ClientIP),
		sanitizeLogField(e.QueryName),
		sanitizeLogField(e.QueryType),
		e.Rcode,
		e.Latency.Round(time.Microsecond),
		cacheHit,
		upstream,
	)
}

func formatAXFRAuditLine(e AXFRAuditEntry) string {
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s zone=%s action=%s records=%d latency=%s",
		e.Timestamp,
		reqID,
		e.ClientIP,
		sanitizeLogField(e.Zone),
		e.Action,
		e.RecordCount,
		e.Latency.Round(time.Millisecond),
	)
}

func formatIXFRAuditLine(e IXFRAuditEntry) string {
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s zone=%s action=%s records=%d latency=%s",
		e.Timestamp,
		reqID,
		sanitizeLogField(e.ClientIP),
		sanitizeLogField(e.Zone),
		e.Action,
		e.RecordCount,
		e.Latency.Round(time.Millisecond),
	)
}

func formatNOTIFYAuditLine(e NOTIFYAuditEntry) string {
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s zone=%s action=%s",
		e.Timestamp,
		reqID,
		sanitizeLogField(e.ClientIP),
		sanitizeLogField(e.Zone),
		e.Action,
	)
}

func formatUpdateAuditLine(e UpdateAuditEntry) string {
	reqID := "-"
	if e.RequestID != "" {
		reqID = e.RequestID
	}
	return fmt.Sprintf("%s req=%s client=%s zone=%s action=%s rcode=%s added=%d deleted=%d",
		e.Timestamp,
		reqID,
		sanitizeLogField(e.ClientIP),
		sanitizeLogField(e.Zone),
		e.Action,
		e.Rcode,
		e.Added,
		e.Deleted,
	)
}

func formatReloadAuditLine(e ReloadAuditEntry) string {
	errStr := ""
	if e.Error != "" {
		errStr = " error=" + e.Error
	}
	return fmt.Sprintf("%s action=reload.%s zones=%d%s",
		e.Timestamp,
		e.Action,
		e.Zones,
		errStr,
	)
}
